package tun

import "io"

// Device represents a TUN virtual network interface
// This interface allows for platform-specific implementations and testing with mocks
type Device interface {
	// Read reads a packet from the TUN device
	// Returns the number of bytes read
	Read(buf []byte) (int, error)

	// Write writes a packet to the TUN device
	// Returns the number of bytes written
	Write(buf []byte) (int, error)

	// Name returns the name of the TUN interface (e.g., "tun0")
	Name() string

	// MTU returns the Maximum Transmission Unit of the interface
	MTU() int

	// Close closes the TUN device
	Close() error
}

// Config holds configuration for creating a TUN device
type Config struct {
	Name string // Desired interface name (e.g., "tun0")
	MTU  int    // Maximum Transmission Unit
}

// Ensure Device implements io.ReadWriteCloser
var _ io.ReadWriteCloser = (Device)(nil)
