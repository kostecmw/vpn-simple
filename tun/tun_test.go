//go:build integration && linux
// +build integration,linux

package tun

import (
	"bytes"
	"testing"
)

// MockDevice is a mock TUN device for testing
type MockDevice struct {
	name      string
	mtu       int
	readData  []byte
	writeData []byte
	closed    bool
}

// NewMockDevice creates a new mock TUN device for testing
func NewMockDevice(name string, mtu int) *MockDevice {
	return &MockDevice{
		name: name,
		mtu:  mtu,
	}
}

func (m *MockDevice) Read(buf []byte) (int, error) {
	if m.closed {
		return 0, ErrDeviceClosed
	}
	n := copy(buf, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *MockDevice) Write(buf []byte) (int, error) {
	if m.closed {
		return 0, ErrDeviceClosed
	}
	m.writeData = append(m.writeData, buf...)
	return len(buf), nil
}

func (m *MockDevice) Name() string {
	return m.name
}

func (m *MockDevice) MTU() int {
	return m.mtu
}

func (m *MockDevice) Close() error {
	m.closed = true
	return nil
}

// SetReadData sets data to be returned by Read()
func (m *MockDevice) SetReadData(data []byte) {
	m.readData = data
}

// GetWrittenData returns all data written via Write()
func (m *MockDevice) GetWrittenData() []byte {
	return m.writeData
}

// Ensure MockDevice implements Device interface
var _ Device = (*MockDevice)(nil)

// Common error for testing
var ErrDeviceClosed = &DeviceError{"device is closed"}

type DeviceError struct {
	msg string
}

func (e *DeviceError) Error() string {
	return e.msg
}

// Tests

func TestMockDevice(t *testing.T) {
	dev := NewMockDevice("tun0", 1420)

	if dev.Name() != "tun0" {
		t.Errorf("Name() = %s, want tun0", dev.Name())
	}

	if dev.MTU() != 1420 {
		t.Errorf("MTU() = %d, want 1420", dev.MTU())
	}
}

func TestMockDeviceReadWrite(t *testing.T) {
	dev := NewMockDevice("tun0", 1420)

	// Test Write
	testData := []byte("Hello, TUN!")
	n, err := dev.Write(testData)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write() n = %d, want %d", n, len(testData))
	}

	written := dev.GetWrittenData()
	if !bytes.Equal(written, testData) {
		t.Errorf("Written data = %v, want %v", written, testData)
	}

	// Test Read
	dev.SetReadData([]byte("Response data"))
	buf := make([]byte, 100)
	n, err = dev.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 13 {
		t.Errorf("Read() n = %d, want 13", n)
	}
	if string(buf[:n]) != "Response data" {
		t.Errorf("Read() data = %s, want 'Response data'", string(buf[:n]))
	}
}

func TestMockDeviceClose(t *testing.T) {
	dev := NewMockDevice("tun0", 1420)

	err := dev.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Operations after close should fail
	_, err = dev.Write([]byte("test"))
	if err != ErrDeviceClosed {
		t.Errorf("Write() after close should return ErrDeviceClosed, got %v", err)
	}

	_, err = dev.Read(make([]byte, 10))
	if err != ErrDeviceClosed {
		t.Errorf("Read() after close should return ErrDeviceClosed, got %v", err)
	}
}

func TestConfig(t *testing.T) {
	config := Config{
		Name: "test0",
		MTU:  1500,
	}

	if config.Name != "test0" {
		t.Errorf("Config.Name = %s, want test0", config.Name)
	}
	if config.MTU != 1500 {
		t.Errorf("Config.MTU = %d, want 1500", config.MTU)
	}
}

// Integration test - only runs on Linux with privileges
// Run with: sudo go test -v -tags integration

func TestLinuxDeviceCreation(t *testing.T) {
	config := Config{
		Name: "tuntest",
		MTU:  1420,
	}

	dev, err := NewDevice(config)
	if err != nil {
		t.Skipf("Skipping integration test (requires root): %v", err)
		return
	}
	defer dev.Close()

	if dev.Name() == "" {
		t.Error("Device name should not be empty")
	}

	if dev.MTU() != 1420 {
		t.Errorf("MTU = %d, want 1420", dev.MTU())
	}

	t.Logf("Created TUN device: %s", dev.Name())
}
