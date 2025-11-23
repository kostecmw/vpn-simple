package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// Simplified VPN - Educational purposes only
// No encryption, no security, fixed 2 peers

const (
	MTU        = 1420
	PacketData = 1 // Packet type for data transfer
)

type Config struct {
	Mode       string // "client" or "server"
	LocalAddr  string // Local UDP address
	RemoteAddr string // Remote peer UDP address
	TunName    string // TUN interface name
}

// Peer represents the other end of the VPN tunnel
type Peer struct {
	addr *net.UDPAddr
	conn *net.UDPConn
}

// Device represents our VPN device
type Device struct {
	tun    *TUNDevice
	peer   *Peer
	config *Config
}

// TUNDevice represents a virtual network interface
type TUNDevice struct {
	name string
	fd   int
	mtu  int
}

// Packet header: [Type:1 byte][Length:2 bytes][Data]
type PacketHeader struct {
	Type   byte
	Length uint16
}

func main() {
	config := parseFlags()

	log.Printf("Starting simplified VPN in %s mode", config.Mode)
	log.Printf("Local: %s, Remote: %s", config.LocalAddr, config.RemoteAddr)

	// Create device
	dev, err := NewDevice(config)
	if err != nil {
		log.Fatalf("Failed to create device: %v", err)
	}
	defer dev.Close()

	// Start packet processing
	dev.Start()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Mode, "mode", "client", "Mode: client or server")
	flag.StringVar(&config.LocalAddr, "local", ":51820", "Local UDP address")
	flag.StringVar(&config.RemoteAddr, "remote", "", "Remote peer UDP address")
	flag.StringVar(&config.TunName, "tun", "tun0", "TUN interface name")
	flag.Parse()

	if config.Mode != "client" && config.Mode != "server" {
		log.Fatal("Mode must be 'client' or 'server'")
	}

	if config.RemoteAddr == "" {
		log.Fatal("Remote address is required")
	}

	return config
}

func NewDevice(config *Config) (*Device, error) {
	// Create TUN device
	tun, err := CreateTUN(config.TunName, MTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w", err)
	}

	// Setup UDP connection
	localAddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("resolve local addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", config.RemoteAddr)
	if err != nil {
		conn.Close()
		tun.Close()
		return nil, fmt.Errorf("resolve remote addr: %w", err)
	}

	peer := &Peer{
		addr: remoteAddr,
		conn: conn,
	}

	log.Printf("TUN device created: %s (MTU: %d)", config.TunName, MTU)
	log.Printf("UDP socket listening on: %s", localAddr.String())

	return &Device{
		tun:    tun,
		peer:   peer,
		config: config,
	}, nil
}

func (d *Device) Start() {
	// Goroutine 1: TUN -> UDP (Outbound)
	go d.routineTUNRead()

	// Goroutine 2: UDP -> TUN (Inbound)
	go d.routineUDPRead()

	log.Println("Packet processing started")
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

		log.Printf("OUT: TUN -> UDP (%d bytes)", n)
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

		log.Printf("IN: UDP <- TUN (%d bytes from %s)", dataLen, addr.String())
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

// =============================================================================
// TUN Device Implementation (Linux-specific, simplified)
// =============================================================================

func CreateTUN(name string, mtu int) (*TUNDevice, error) {
	// Open TUN device
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	// Setup IFR request structure
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte // padding
	}

	copy(ifr.name[:], name)
	ifr.flags = 0x0001 // IFF_TUN

	// Create TUN interface
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}

	// Get actual interface name
	actualName := string(ifr.name[:])
	for i, c := range actualName {
		if c == 0 {
			actualName = actualName[:i]
			break
		}
	}

	tun := &TUNDevice{
		name: actualName,
		fd:   fd,
		mtu:  mtu,
	}

	// Bring interface up (requires ip command or manual configuration)
	log.Printf("TUN interface created: %s", actualName)
	log.Printf("Configure it with: sudo ip addr add 10.0.0.X/24 dev %s", actualName)
	log.Printf("                   sudo ip link set %s up", actualName)

	return tun, nil
}

func (t *TUNDevice) Read(buf []byte) (int, error) {
	n, err := syscall.Read(t.fd, buf)
	return n, err
}

func (t *TUNDevice) Write(buf []byte) (int, error) {
	n, err := syscall.Write(t.fd, buf)
	return n, err
}

func (t *TUNDevice) Close() error {
	return syscall.Close(t.fd)
}

// =============================================================================
// Usage Examples
// =============================================================================

/*
SETUP (run in separate terminals):

Terminal 1 (Server):
$ sudo go run simple-vpn.go -mode server -local :51820 -remote 127.0.0.1:51821 -tun tun0
$ sudo ip addr add 10.0.0.1/24 dev tun0
$ sudo ip link set tun0 up

Terminal 2 (Client):
$ sudo go run simple-vpn.go -mode client -local :51821 -remote 127.0.0.1:51820 -tun tun1
$ sudo ip addr add 10.0.0.2/24 dev tun1
$ sudo ip link set tun1 up

TEST:
Terminal 1: $ ping 10.0.0.2
Terminal 2: $ ping 10.0.0.1

CLEANUP:
$ sudo ip link delete tun0
$ sudo ip link delete tun1
*/
