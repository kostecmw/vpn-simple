package network

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Common errors
var (
	ErrCommandFailed    = errors.New("command execution failed")
	ErrInvalidIP        = errors.New("invalid IP address")
	ErrNoDefaultRoute   = errors.New("no default route found")
	ErrRouteNotFound    = errors.New("route not found")
	ErrIPTablesNotFound = errors.New("iptables not found")
)

// RouteBackup stores original routing information for restoration
type RouteBackup struct {
	DefaultGateway  string
	DefaultIface    string
	HadDefaultRoute bool
}

// NATConfig holds configuration for NAT setup
type NATConfig struct {
	TunInterface string // TUN interface name (e.g., "tun0")
	SourceSubnet string // Source subnet for NAT (e.g., "10.0.0.0/24")
	OutInterface string // Outbound interface (e.g., "eth0")
}

// RouteConfig holds configuration for route management
type RouteConfig struct {
	TunInterface   string // TUN interface name
	Gateway        string // Gateway IP address
	Destination    string // Destination (e.g., "default", "8.8.8.8/32")
	ServerIP       string // VPN server IP (to prevent routing loop)
	OriginalBackup *RouteBackup
}

// RunCommand executes a system command and returns an error if it fails
func RunCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s failed: %v\nOutput: %s",
			ErrCommandFailed, name, err, string(output))
	}
	return nil
}

// RunCommandOutput executes a command and returns its output
func RunCommandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s failed: %v", ErrCommandFailed, name, err)
	}
	return string(output), nil
}

// CalculateSubnet calculates the subnet from IP and mask
func CalculateSubnet(ip, mask string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip + "/" + mask
	}
	// Simple implementation for /24 networks
	return fmt.Sprintf("%s.%s.%s.0/%s", parts[0], parts[1], parts[2], mask)
}

// GetNetworkAddress extracts the network address from an IP
func GetNetworkAddress(ip, mask string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	// Simple implementation for /24 networks
	return fmt.Sprintf("%s.%s.%s.0", parts[0], parts[1], parts[2])
}

// ExtractIPFromAddr extracts IP from "host:port" string
func ExtractIPFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}

	// If it's already an IP, return it
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

// ValidateIP checks if a string is a valid IP address
func ValidateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: %s", ErrInvalidIP, ip)
	}
	return nil
}

// IsCommandAvailable checks if a command is available in PATH
func IsCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
