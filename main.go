package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"wg-go/wg-simple/crypto"
	"wg-go/wg-simple/device"
)

// Simplified VPN - Educational purposes only
// No encryption, no security, fixed 2 peers

type Config struct {
	Mode        string // "client" or "server"
	GenerateKey bool   // Flag to generate and print key then exit
	Device      device.Config
}

// RouteBackup stores original routing information for restoration

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
	log.Printf("Local: %s, Remote: %s", config.Device.LocalAddr, config.Device.RemoteAddr)

	// Create device
	dev, err := device.NewDevice(&config.Device)
	if err != nil {
		log.Fatalf("Failed to create device: %v", err)
	}
	defer dev.Close()

	// Setup Device: configure TUN, routing, NAT
	err = dev.Setup()
	if err != nil {
		log.Fatalf("Failed to setup device: %v", err)
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

	// Main Config
	flag.StringVar(&config.Mode, "mode", "client", "Mode: client or server")
	flag.BoolVar(&config.GenerateKey, "generate-key", false, "Generate a new encryption key and exit")

	// Device Config
	flag.StringVar(&config.Device.LocalAddr, "local", ":51820", "Local UDP address")
	flag.StringVar(&config.Device.RemoteAddr, "remote", "", "Remote peer UDP address")
	flag.StringVar(&config.Device.TunName, "tun", "tun0", "TUN interface name")
	flag.StringVar(&config.Device.TunIP, "tun-ip", "", "TUN interface IP (required)")
	flag.StringVar(&config.Device.TunMask, "tun-mask", "24", "TUN interface subnet mask (default: 24)")
	flag.BoolVar(&config.Device.EnableNAT, "enable-nat", false, "Enable NAT/masquerading (server mode)")
	flag.StringVar(&config.Device.NATIface, "nat-iface", "eth0", "Interface for NAT outbound traffic")
	flag.StringVar(&config.Device.AddRoute, "route", "", "Add route via VPN (e.g., 'default' or '8.8.8.8/32')")
	flag.StringVar(&config.Device.EncryptionKey, "key", "", "Encryption key (64 hex characters = 32 bytes)")

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

	if config.Device.RemoteAddr == "" {
		log.Fatal("Remote address is required (-remote)")
	}

	if config.Device.TunIP == "" {
		log.Fatal("TUN IP address is required (-tun-ip)")
	}

	// Validate NAT settings
	if config.Device.EnableNAT && config.Mode != "server" {
		log.Println("Warning: NAT is typically used in server mode")
	}

	return config
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
