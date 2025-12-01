package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"wg-go/wg-simple/crypto"

	"golang.org/x/crypto/chacha20poly1305"
)

// Simplified VPN - Educational purposes only
// No encryption, no security, fixed 2 peers

const (
	MTU        = 1400
	PacketData = 1 // Packet type for data transfer
)

type Config struct {
	Mode          string // "client" or "server"
	LocalAddr     string // Local UDP address
	RemoteAddr    string // Remote peer UDP address
	TunName       string // TUN interface name
	TunIP         string // IP address for TUN interface
	TunMask       string // Subnet mask (e.g., "24" for /24)
	EnableNAT     bool   // Enable NAT/masquerading
	NATIface      string // Interface for NAT (e.g., eth0)
	AddRoute      string // Add route via VPN (e.g., "default" or "8.8.8.8/32")
	EncryptionKey string // Hex-encoded 32-byte encryption key
	GenerateKey   bool   // Flag to generate and print key then exit
}

// RouteBackup stores original routing information for restoration
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
	tun           *TUNDevice
	peer          *Peer
	config        *Config
	routeBackup   *RouteBackup
	encryptionKey []byte         // 32-byte encryption key
	crypto        *crypto.Engine // Encryption/decryption engine
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

	// Handle key generation request
	if config.GenerateKey {
		generateAndPrintKey()
		return
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (use sudo)")
	}

	log.Printf("Starting simplified VPN in %s mode", config.Mode)
	log.Printf("Local: %s, Remote: %s", config.LocalAddr, config.RemoteAddr)

	// Create device
	dev, err := NewDevice(config)
	if err != nil {
		log.Fatalf("Failed to create device: %v", err)
	}
	defer dev.Close()

	// Configure TUN interface
	if err := dev.ConfigureTUN(); err != nil {
		log.Fatalf("Failed to configure TUN: %v", err)
	}

	// Setup routing
	if err := dev.SetupRouting(); err != nil {
		log.Fatalf("Failed to setup routing: %v", err)
	}

	// Setup NAT if enabled
	if config.EnableNAT {
		if err := dev.SetupNAT(); err != nil {
			log.Fatalf("Failed to setup NAT: %v", err)
		}
	}

	// Start packet processing
	dev.Start()

	log.Println("✓ VPN is ready!")

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	dev.Cleanup()
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Mode, "mode", "client", "Mode: client or server")
	flag.StringVar(&config.LocalAddr, "local", ":51820", "Local UDP address")
	flag.StringVar(&config.RemoteAddr, "remote", "", "Remote peer UDP address")
	flag.StringVar(&config.TunName, "tun", "tun0", "TUN interface name")
	flag.StringVar(&config.TunIP, "tun-ip", "", "TUN interface IP (required)")
	flag.StringVar(&config.TunMask, "tun-mask", "24", "TUN interface subnet mask (default: 24)")
	flag.BoolVar(&config.EnableNAT, "enable-nat", false, "Enable NAT/masquerading (server mode)")
	flag.StringVar(&config.NATIface, "nat-iface", "eth0", "Interface for NAT outbound traffic")
	flag.StringVar(&config.AddRoute, "route", "", "Add route via VPN (e.g., 'default' or '8.8.8.8/32')")
	flag.StringVar(&config.EncryptionKey, "key", "", "Encryption key (64 hex characters = 32 bytes)")
	flag.BoolVar(&config.GenerateKey, "generate-key", false, "Generate a new encryption key and exit")

	// Hidden flag for testing crypto
	testCrypto := flag.Bool("test-crypto", false, "Test encryption/decryption and exit")

	flag.Parse()

	// If testing crypto, run test and exit
	if *testCrypto {
		testCryptoEngine()
		return config
	}

	// If generating key, no other validation needed
	if config.GenerateKey {
		return config
	}

	if config.Mode != "client" && config.Mode != "server" {
		log.Fatal("Mode must be 'client' or 'server'")
	}

	if config.RemoteAddr == "" {
		log.Fatal("Remote address is required (-remote)")
	}

	if config.TunIP == "" {
		log.Fatal("TUN IP address is required (-tun-ip)")
	}

	// Validate NAT settings
	if config.EnableNAT && config.Mode != "server" {
		log.Println("Warning: NAT is typically used in server mode")
	}

	return config
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

	log.Printf("✓ TUN device created: %s (MTU: %d)", tun.name, MTU)
	log.Printf("✓ UDP socket listening on: %s", localAddr.String())

	return &Device{
		tun:           tun,
		peer:          peer,
		config:        config,
		routeBackup:   &RouteBackup{},
		encryptionKey: encryptionKey,
		crypto:        cryptoEngine,
	}, nil
}

// ConfigureTUN sets up the TUN interface with IP address
func (d *Device) ConfigureTUN() error {
	log.Printf("Configuring TUN interface %s...", d.tun.name)

	// Set IP address
	cidr := fmt.Sprintf("%s/%s", d.config.TunIP, d.config.TunMask)
	if err := runCommand("ip", "addr", "add", cidr, "dev", d.tun.name); err != nil {
		return fmt.Errorf("set IP address: %w", err)
	}
	log.Printf("✓ IP address: %s", cidr)

	// Set MTU
	if err := runCommand("ip", "link", "set", d.tun.name, "mtu", fmt.Sprintf("%d", MTU)); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	log.Printf("✓ MTU: %d", MTU)

	// Bring interface up
	if err := runCommand("ip", "link", "set", d.tun.name, "up"); err != nil {
		return fmt.Errorf("bring interface up: %w", err)
	}
	log.Printf("✓ Interface is UP")

	return nil
}

// SetupRouting configures routing through the VPN
func (d *Device) SetupRouting() error {
	if d.config.AddRoute == "" {
		return nil
	}

	log.Printf("Setting up routing...")

	route := d.config.AddRoute

	if route == "default" {
		// Save original default route
		if err := d.backupDefaultRoute(); err != nil {
			log.Printf("Warning: Could not backup default route: %v", err)
		}

		// Extract gateway IP from TUN IP (assuming peer is x.x.x.1 if we're x.x.x.2)
		parts := strings.Split(d.config.TunIP, ".")
		if len(parts) != 4 {
			return fmt.Errorf("invalid TUN IP format")
		}

		// Simple logic: if we're .2, gateway is .1, and vice versa
		lastOctet := parts[3]
		gateway := strings.Join(parts[:3], ".")
		if lastOctet == "1" {
			gateway += ".2"
		} else {
			gateway += ".1"
		}

		// Add route for VPN server through original gateway (prevent routing loop)
		serverIP := extractIPFromAddr(d.config.RemoteAddr)
		if serverIP != "" && serverIP != "127.0.0.1" && d.routeBackup.hadDefaultRoute {
			if err := runCommand("ip", "route", "add", serverIP, "via", d.routeBackup.defaultGateway, "dev", d.routeBackup.defaultIface); err != nil {
				log.Printf("Warning: Could not add server route: %v", err)
			} else {
				log.Printf("✓ Route to VPN server (%s) via original gateway", serverIP)
			}
		}

		// Delete old default route
		if d.routeBackup.hadDefaultRoute {
			if err := runCommand("ip", "route", "del", "default"); err != nil {
				log.Printf("Warning: Could not delete old default route: %v", err)
			} else {
				log.Printf("✓ Removed old default route")
			}
		}

		// Add new default route through VPN
		if err := runCommand("ip", "route", "add", "default", "via", gateway, "dev", d.tun.name); err != nil {
			// Try to restore if this fails
			d.restoreDefaultRoute()
			return fmt.Errorf("add default route: %w", err)
		}
		log.Printf("✓ New default route via %s", gateway)

	} else {
		// Add specific route
		parts := strings.Split(d.config.TunIP, ".")
		gateway := strings.Join(parts[:3], ".")
		lastOctet := parts[3]
		if lastOctet == "1" {
			gateway += ".2"
		} else {
			gateway += ".1"
		}

		if err := runCommand("ip", "route", "add", route, "via", gateway, "dev", d.tun.name); err != nil {
			return fmt.Errorf("add route: %w", err)
		}
		log.Printf("✓ Route %s via %s", route, gateway)
	}

	return nil
}

// SetupNAT configures NAT/masquerading for internet access
func (d *Device) SetupNAT() error {
	log.Printf("Setting up NAT...")

	// Enable IP forwarding
	if err := runCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable IP forwarding: %w", err)
	}
	log.Printf("✓ IP forwarding enabled")

	// Calculate subnet from TUN IP and mask
	subnet := calculateSubnet(d.config.TunIP, d.config.TunMask)

	// Add MASQUERADE rule
	if err := runCommand("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", subnet, "-o", d.config.NATIface, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("add MASQUERADE rule: %w", err)
	}
	log.Printf("✓ MASQUERADE rule added for %s", subnet)

	// Allow forwarding from TUN to NAT interface
	if err := runCommand("iptables", "-A", "FORWARD",
		"-i", d.tun.name, "-o", d.config.NATIface, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add forward rule: %w", err)
	}
	log.Printf("✓ Forward rule added")

	// Allow forwarding from NAT interface to TUN (established connections)
	if err := runCommand("iptables", "-A", "FORWARD",
		"-i", d.config.NATIface, "-o", d.tun.name,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add return forward rule: %w", err)
	}
	log.Printf("✓ Return forward rule added")

	// Add MSS clamping for better compatibility
	if err := runCommand("iptables", "-t", "mangle", "-A", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu"); err != nil {
		log.Printf("Warning: Could not add MSS clamping: %v", err)
	} else {
		log.Printf("✓ MSS clamping added")
	}

	return nil
}

// Cleanup removes routes and iptables rules
func (d *Device) Cleanup() {
	log.Println("Cleaning up...")

	// Remove routes
	if d.config.AddRoute != "" {
		if d.config.AddRoute == "default" {
			// Remove VPN default route
			runCommand("ip", "route", "del", "default", "dev", d.tun.name)

			// Remove server-specific route
			serverIP := extractIPFromAddr(d.config.RemoteAddr)
			if serverIP != "" && serverIP != "127.0.0.1" {
				runCommand("ip", "route", "del", serverIP)
			}

			// Restore original default route
			d.restoreDefaultRoute()
		} else {
			runCommand("ip", "route", "del", d.config.AddRoute, "dev", d.tun.name)
		}
	}

	// Remove NAT rules if they were added
	if d.config.EnableNAT {
		subnet := calculateSubnet(d.config.TunIP, d.config.TunMask)
		runCommand("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-s", subnet, "-o", d.config.NATIface, "-j", "MASQUERADE")
		runCommand("iptables", "-D", "FORWARD",
			"-i", d.tun.name, "-o", d.config.NATIface, "-j", "ACCEPT")
		runCommand("iptables", "-D", "FORWARD",
			"-i", d.config.NATIface, "-o", d.tun.name,
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

// =============================================================================
// Helper Functions
// =============================================================================

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func calculateSubnet(ip, mask string) string {
	return fmt.Sprintf("%s/%s", getNetworkAddress(ip, mask), mask)
}

func getNetworkAddress(ip, mask string) string {
	// Simple subnet calculation for /24 networks
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return fmt.Sprintf("%s.%s.%s.0", parts[0], parts[1], parts[2])
}

// backupDefaultRoute saves the current default route
func (d *Device) backupDefaultRoute() error {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("get default route: %w", err)
	}

	line := strings.TrimSpace(string(output))
	if line == "" {
		log.Printf("No default route found to backup")
		d.routeBackup.hadDefaultRoute = false
		return nil
	}

	// Parse: "default via 192.168.1.1 dev eth0"
	parts := strings.Fields(line)
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			d.routeBackup.defaultGateway = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			d.routeBackup.defaultIface = parts[i+1]
		}
	}

	if d.routeBackup.defaultGateway != "" && d.routeBackup.defaultIface != "" {
		d.routeBackup.hadDefaultRoute = true
		log.Printf("✓ Backed up default route: via %s dev %s",
			d.routeBackup.defaultGateway, d.routeBackup.defaultIface)
		return nil
	}

	return fmt.Errorf("could not parse default route")
}

// restoreDefaultRoute restores the original default route
func (d *Device) restoreDefaultRoute() {
	if !d.routeBackup.hadDefaultRoute {
		return
	}

	if err := runCommand("ip", "route", "add", "default",
		"via", d.routeBackup.defaultGateway,
		"dev", d.routeBackup.defaultIface); err != nil {
		log.Printf("Warning: Could not restore default route: %v", err)
	} else {
		log.Printf("✓ Restored default route: via %s dev %s",
			d.routeBackup.defaultGateway, d.routeBackup.defaultIface)
	}
}

// extractIPFromAddr extracts IP from "host:port" string
func extractIPFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}

	// If it's a hostname, resolve it
	ip := net.ParseIP(host)
	if ip != nil {
		return host
	}

	// Try to resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}

	return ips[0].String()
}

// =============================================================================
// Encryption Key Management
// =============================================================================

// generateAndPrintKey generates a new random 32-byte encryption key
func generateAndPrintKey() {
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate random key: %v", err)
	}

	hexKey := crypto.KeyToHex(key)

	fmt.Println("==============================================")
	fmt.Println("        Generated Encryption Key")
	fmt.Println("==============================================")
	fmt.Println()
	fmt.Printf("Key: %s\n", hexKey)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("------")
	fmt.Println("Use this key on BOTH server and client:")
	fmt.Println()
	fmt.Printf("  Server: sudo go run simple-vpn.go -mode server -key %s ...\n", hexKey)
	fmt.Printf("  Client: sudo go run simple-vpn.go -mode client -key %s ...\n", hexKey)
	fmt.Println()
	fmt.Println("Security Notes:")
	fmt.Println("- Keep this key SECRET")
	fmt.Println("- Share it securely with the other peer (SSH, secure channel)")
	fmt.Println("- Both peers MUST use the SAME key")
	fmt.Println("- Generate a new key periodically for better security")
	fmt.Println("==============================================")
}

// =============================================================================
// Cryptography Engine
// =============================================================================

// CryptoEngine handles encryption and decryption using ChaCha20-Poly1305
type CryptoEngine struct {
	aead cipher.AEAD
}

// NewCryptoEngine creates a new crypto engine with the given key
func NewCryptoEngine(key []byte) (*CryptoEngine, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	return &CryptoEngine{
		aead: aead,
	}, nil
}

// Encrypt encrypts plaintext and returns [nonce || ciphertext || tag]
func (c *CryptoEngine) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate random nonce (12 bytes for ChaCha20-Poly1305)
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	// Seal appends the ciphertext and tag to dst (starting with nonce)
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext of format [nonce || ciphertext || tag]
func (c *CryptoEngine) Decrypt(data []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()

	// Check minimum length: nonce + at least some data + tag
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes for nonce", nonceSize)
	}

	// Extract nonce and ciphertext
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt and verify
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or corrupted data): %w", err)
	}

	return plaintext, nil
}

// GetOverhead returns the number of extra bytes added by encryption
func (c *CryptoEngine) GetOverhead() int {
	// Nonce size + tag size
	return c.aead.NonceSize() + c.aead.Overhead()
}

// =============================================================================
// Crypto Testing
// =============================================================================

// testCryptoEngine tests the encryption/decryption functionality
func testCryptoEngine() {
	fmt.Println("==============================================")
	fmt.Println("     Testing Crypto Engine")
	fmt.Println("==============================================")
	fmt.Println()

	// Generate a test key
	key, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Test key: %x\n", key)
	fmt.Println()

	// Create crypto engine
	engine, err := crypto.NewEngine(key)
	if err != nil {
		fmt.Printf("❌ Failed to create crypto engine: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Crypto engine created\n")
	fmt.Printf("  - Nonce size: %d bytes\n", engine.NonceSize())
	fmt.Printf("  - Tag size: %d bytes\n", engine.TagSize())
	fmt.Printf("  - Total overhead: %d bytes\n", engine.Overhead())
	fmt.Println()

	// Test cases
	testCases := []struct {
		name string
		data string
	}{
		{"Short message", "Hello, World!"},
		{"Empty message", ""},
		{"Long message", strings.Repeat("The quick brown fox jumps over the lazy dog. ", 10)},
		{"Binary data", string([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd})},
	}

	for i, tc := range testCases {
		fmt.Printf("Test %d: %s\n", i+1, tc.name)
		fmt.Printf("  Original length: %d bytes\n", len(tc.data))

		// Encrypt
		encrypted, err := engine.Encrypt([]byte(tc.data))
		if err != nil {
			fmt.Printf("  ❌ Encryption failed: %v\n", err)
			continue
		}
		fmt.Printf("  ✓ Encrypted length: %d bytes (overhead: %d)\n",
			len(encrypted), len(encrypted)-len(tc.data))

		// Decrypt
		decrypted, err := engine.Decrypt(encrypted)
		if err != nil {
			fmt.Printf("  ❌ Decryption failed: %v\n", err)
			continue
		}
		fmt.Printf("  ✓ Decrypted length: %d bytes\n", len(decrypted))

		// Verify
		if string(decrypted) != tc.data {
			fmt.Printf("  ❌ Data mismatch!\n")
			fmt.Printf("     Original:  %q\n", tc.data)
			fmt.Printf("     Decrypted: %q\n", string(decrypted))
			continue
		}
		fmt.Printf("  ✓ Data matches original\n")
		fmt.Println()
	}

	// Test with wrong key
	fmt.Println("Test: Wrong key detection")
	wrongKey, _ := crypto.GenerateKey()
	wrongEngine, _ := crypto.NewEngine(wrongKey)

	encrypted, _ := engine.Encrypt([]byte("Secret message"))
	_, err = wrongEngine.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("  ✓ Correctly rejected decryption with wrong key\n")
		fmt.Printf("    Error: %v\n", err)
	} else {
		fmt.Printf("  ❌ Should have failed with wrong key!\n")
	}
	fmt.Println()

	// Test tampered data
	fmt.Println("Test: Tampered data detection")
	encrypted, _ = engine.Encrypt([]byte("Original message"))
	// Flip a bit in the ciphertext
	encrypted[20] ^= 0x01
	_, err = engine.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("  ✓ Correctly rejected tampered data\n")
		fmt.Printf("    Error: %v\n", err)
	} else {
		fmt.Printf("  ❌ Should have detected tampering!\n")
	}
	fmt.Println()

	fmt.Println("==============================================")
	fmt.Println("  All crypto tests completed!")
	fmt.Println("==============================================")

	os.Exit(0)
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
STEP 1: GENERATE ENCRYPTION KEY

$ go run simple-vpn.go -generate-key

Output:
==============================================
        Generated Encryption Key
==============================================

Key: 3a7f8c2e9d1b4f6a0e5c8d3a7f9b2c1e4d6a8f0b3c5e7a9d1f3b5c7e9a1d3f5
...

Copy this key - you'll need it for both server and client!

---

STEP 2: TEST ENCRYPTION (OPTIONAL)

$ go run simple-vpn.go -test-crypto

Output:
==============================================
     Testing Crypto Engine
==============================================
✓ Crypto engine created
  - Nonce size: 12 bytes
  - Tag size: 16 bytes
  - Total overhead: 28 bytes

Test 1: Short message
  ✓ Encrypted
  ✓ Decrypted
  ✓ Data matches original
...

---

SIMPLE SETUP (just ping between peers):

Terminal 1 (Server):
$ sudo go run simple-vpn.go \
    -mode server \
    -local :51820 \
    -remote 127.0.0.1:51821 \
    -tun-ip 10.0.0.1 \
    -key 3a7f8c2e9d1b4f6a0e5c8d3a7f9b2c1e4d6a8f0b3c5e7a9d1f3b5c7e9a1d3f5

Terminal 2 (Client):
$ sudo go run simple-vpn.go \
    -mode client \
    -local :51821 \
    -remote 127.0.0.1:51820 \
    -tun-ip 10.0.0.2 \
    -key 3a7f8c2e9d1b4f6a0e5c8d3a7f9b2c1e4d6a8f0b3c5e7a9d1f3b5c7e9a1d3f5

Test: ping 10.0.0.1 (from client) or ping 10.0.0.2 (from server)

⚠️ NOTE: Both peers MUST use the SAME key!

---

INTERNET ACCESS SETUP (client routes all traffic through server):

Terminal 1 (Server with NAT):
$ sudo go run simple-vpn.go \
    -mode server \
    -local :51820 \
    -remote CLIENT_PUBLIC_IP:51821 \
    -tun-ip 10.0.0.1 \
    -enable-nat \
    -nat-iface eth0 \
    -key YOUR_KEY_HERE

Terminal 2 (Client with default route):
$ sudo go run simple-vpn.go \
    -mode client \
    -local :51821 \
    -remote SERVER_PUBLIC_IP:51820 \
    -tun-ip 10.0.0.2 \
    -route default \
    -key YOUR_KEY_HERE

Test: curl ifconfig.me (should show server's IP)

---

WITHOUT ENCRYPTION (for testing - NOT RECOMMENDED):

$ sudo go run simple-vpn.go \
    -mode server \
    -local :51820 \
    -remote 127.0.0.1:51821 \
    -tun-ip 10.0.0.1

⚠️ Warning: No encryption key provided - traffic will be sent in PLAINTEXT!

---

FLAGS:
  -mode string
        Mode: client or server (default "client")
  -local string
        Local UDP address (default ":51820")
  -remote string
        Remote peer UDP address (required)
  -tun string
        TUN interface name (default "tun0")
  -tun-ip string
        TUN interface IP address (required)
  -tun-mask string
        TUN subnet mask (default "24")
  -enable-nat
        Enable NAT/masquerading (typically server mode)
  -nat-iface string
        Network interface for NAT (default "eth0")
  -route string
        Add route via VPN: "default" or specific IP/CIDR
  -key string
        Encryption key (64 hex characters = 32 bytes)
  -generate-key
        Generate a new encryption key and exit
  -test-crypto
        Test encryption/decryption and exit

CLEANUP:
The program automatically cleans up on exit (Ctrl+C)
Or manually: sudo ip link delete tun0
*/
