package device

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"wg-go/wg-simple/crypto"
	"wg-go/wg-simple/tun"
)

const (
	MTU        = 1400
	PacketData = 1 // Packet type for data transfer
)

type Config struct {
	LocalAddr     string // Local UDP address
	RemoteAddr    string // Remote peer UDP address
	TunName       string // TUN interface name
	TunIP         string // IP address for TUN interface
	TunMask       string // Subnet mask (e.g., "24" for /24)
	EnableNAT     bool   // Enable NAT/masquerading
	NATIface      string // Interface for NAT (e.g., eth0)
	AddRoute      string // Add route via VPN (e.g., "default" or "8.8.8.8/32")
	EncryptionKey string // Hex-encoded 32-byte encryption key
}

type RouteBackup struct {
	defaultGateway  string
	defaultIface    string
	hadDefaultRoute bool
}

// Peer represents the other end of the VPN tunnel
type Peer struct {
	addr *net.UDPAddr
	conn *net.UDPConn
}

// Device represents our VPN device
type Device struct {
	tun           tun.Device
	peer          *Peer
	config        *Config
	routeBackup   *RouteBackup
	encryptionKey []byte         // 32-byte encryption key
	crypto        *crypto.Engine // Encryption/decryption engine
}

// Packet header: [Type:1 byte][Length:2 bytes][Data]
type PacketHeader struct {
	Type   byte
	Length uint16
}

func NewDevice(config *Config) (*Device, error) {
	// Parse and validate encryption key if provided
	var encryptionKey []byte
	var cryptoEngine *crypto.Engine

	if config.EncryptionKey != "" {
		key, err := crypto.ParseKey(config.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption key: %w", err)
		}
		encryptionKey = key

		// Initialize crypto engine
		cryptoEngine, err = crypto.NewEngine(encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize crypto: %w", err)
		}

		log.Printf("✓ Encryption enabled with ChaCha20-Poly1305 (%d bytes key)", len(encryptionKey))
	} else {
		log.Printf("⚠ Warning: No encryption key provided - traffic will be sent in PLAINTEXT!")
		log.Printf("   Generate a key with: go run simple-vpn.go -generate-key")
	}

	// Create TUN device
	tund, err := tun.NewDevice(tun.Config{
		Name: config.TunName,
		MTU:  MTU,
	})

	if err != nil {
		return nil, fmt.Errorf("create TUN: %w", err)
	}

	// Setup UDP connection
	localAddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		tund.Close()
		return nil, fmt.Errorf("resolve local addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		tund.Close()
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", config.RemoteAddr)
	if err != nil {
		conn.Close()
		tund.Close()
		return nil, fmt.Errorf("resolve remote addr: %w", err)
	}

	peer := &Peer{
		addr: remoteAddr,
		conn: conn,
	}

	log.Printf("✓ TUN device created: %s (MTU: %d)", tund.Name(), tund.MTU())
	log.Printf("✓ UDP socket listening on: %s", localAddr.String())

	return &Device{
		tun:           tund,
		peer:          peer,
		config:        config,
		routeBackup:   &RouteBackup{},
		encryptionKey: encryptionKey,
		crypto:        cryptoEngine,
	}, nil
}

// Cleanup removes routes and iptables rules
func (d *Device) Cleanup() {
	log.Println("Cleaning up...")

	// Remove routes
	if d.config.AddRoute != "" {
		if d.config.AddRoute == "default" {
			// Remove VPN default route
			runCommand("ip", "route", "del", "default", "dev", d.tun.Name())

			// Remove server-specific route
			serverIP := extractIPFromAddr(d.config.RemoteAddr)
			if serverIP != "" && serverIP != "127.0.0.1" {
				runCommand("ip", "route", "del", serverIP)
			}

			// Restore original default route
			d.restoreDefaultRoute()
		} else {
			runCommand("ip", "route", "del", d.config.AddRoute, "dev", d.tun.Name())
		}
	}

	// Remove NAT rules if they were added
	if d.config.EnableNAT {
		subnet := calculateSubnet(d.config.TunIP, d.config.TunMask)
		runCommand("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-s", subnet, "-o", d.config.NATIface, "-j", "MASQUERADE")
		runCommand("iptables", "-D", "FORWARD",
			"-i", d.tun.Name(), "-o", d.config.NATIface, "-j", "ACCEPT")
		runCommand("iptables", "-D", "FORWARD",
			"-i", d.config.NATIface, "-o", d.tun.Name(),
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		runCommand("iptables", "-t", "mangle", "-D", "FORWARD",
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu")
	}

	log.Println("✓ Cleanup complete")
}

func (d *Device) Start() {
	// Goroutine 1: TUN -> UDP (Outbound)
	go d.routineTUNRead()

	// Goroutine 2: UDP -> TUN (Inbound)
	go d.routineUDPRead()

	log.Println("✓ Packet processing started")
}

// routineTUNRead reads packets from TUN and sends to UDP
func (d *Device) routineTUNRead() {
	buffer := make([]byte, MTU+20) // Extra space for header

	for {
		// Read from TUN interface
		n, err := d.tun.Read(buffer[3:]) // Leave 3 bytes for header
		if err != nil {
			log.Printf("TUN read error: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		// Build packet header
		buffer[0] = PacketData
		binary.BigEndian.PutUint16(buffer[1:3], uint16(n))

		// Send to peer via UDP
		totalLen := 3 + n
		_, err = d.peer.conn.WriteToUDP(buffer[:totalLen], d.peer.addr)
		if err != nil {
			log.Printf("UDP write error: %v", err)
			continue
		}

		log.Printf("→ OUT: %d bytes", n)
	}
}

// routineUDPRead reads packets from UDP and writes to TUN
func (d *Device) routineUDPRead() {
	buffer := make([]byte, MTU+20)

	for {
		// Read from UDP
		n, addr, err := d.peer.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		if n < 3 {
			log.Printf("Packet too short: %d bytes", n)
			continue
		}

		// Parse header
		packetType := buffer[0]
		dataLen := binary.BigEndian.Uint16(buffer[1:3])

		if packetType != PacketData {
			log.Printf("Unknown packet type: %d", packetType)
			continue
		}

		if int(dataLen) != n-3 {
			log.Printf("Length mismatch: header=%d, actual=%d", dataLen, n-3)
			continue
		}

		// Write to TUN interface
		_, err = d.tun.Write(buffer[3:n])
		if err != nil {
			log.Printf("TUN write error: %v", err)
			continue
		}

		log.Printf("← IN: %d bytes from %s", dataLen, addr.String())
	}
}

func (d *Device) Close() {
	if d.peer != nil && d.peer.conn != nil {
		d.peer.conn.Close()
	}
	if d.tun != nil {
		d.tun.Close()
	}
}
