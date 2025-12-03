package device

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

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
