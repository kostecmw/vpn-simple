//go:build linux

package tun

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// Linux TUN/TAP device constants
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
	TUNSETIFF = 0x400454ca
)

// LinuxDevice implements the Device interface for Linux TUN devices
type LinuxDevice struct {
	name string
	fd   int
	mtu  int
}

// NewDevice creates a new TUN device on Linux
func NewDevice(config Config) (Device, error) {
	// Open /dev/net/tun
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	// Setup interface request structure
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte // padding to match kernel struct size
	}

	// Copy desired name
	copy(ifr.name[:], config.Name)

	// Set flags: TUN device without packet info header
	ifr.flags = IFF_TUN | IFF_NO_PI

	// Create TUN interface via ioctl
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	// Extract actual interface name (kernel may have assigned different name)
	actualName := string(ifr.name[:])
	for i, c := range actualName {
		if c == 0 {
			actualName = actualName[:i]
			break
		}
	}

	return &LinuxDevice{
		name: actualName,
		fd:   fd,
		mtu:  config.MTU,
	}, nil
}

// Read reads a packet from the TUN device
func (d *LinuxDevice) Read(buf []byte) (int, error) {
	n, err := syscall.Read(d.fd, buf)
	if err != nil {
		return 0, fmt.Errorf("tun read error: %w", err)
	}
	return n, nil
}

// Write writes a packet to the TUN device
func (d *LinuxDevice) Write(buf []byte) (int, error) {
	n, err := syscall.Write(d.fd, buf)
	if err != nil {
		return 0, fmt.Errorf("tun write error: %w", err)
	}
	return n, nil
}

// Name returns the name of the TUN interface
func (d *LinuxDevice) Name() string {
	return d.name
}

// MTU returns the Maximum Transmission Unit
func (d *LinuxDevice) MTU() int {
	return d.mtu
}

// Close closes the TUN device
func (d *LinuxDevice) Close() error {
	if d.fd >= 0 {
		err := syscall.Close(d.fd)
		d.fd = -1
		return err
	}
	return nil
}
