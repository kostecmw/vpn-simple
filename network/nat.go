//go:build linux

package network

import (
	"fmt"
	"log"
)

// EnableIPForwarding enables IP forwarding in the kernel
func EnableIPForwarding() error {
	err := RunCommand("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}
	log.Println("✓ IP forwarding enabled")
	return nil
}

// SetupNAT configures NAT/masquerading for internet access through VPN
func SetupNAT(config NATConfig) error {
	// Check if iptables is available
	if !IsCommandAvailable("iptables") {
		return ErrIPTablesNotFound
	}

	// Enable IP forwarding
	if err := EnableIPForwarding(); err != nil {
		return err
	}

	// Add MASQUERADE rule
	err := RunCommand("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", config.SourceSubnet,
		"-o", config.OutInterface,
		"-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
	}
	log.Printf("✓ MASQUERADE rule added for %s", config.SourceSubnet)

	// Allow forwarding from TUN to out interface
	err = RunCommand("iptables", "-A", "FORWARD",
		"-i", config.TunInterface,
		"-o", config.OutInterface,
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to add forward rule: %w", err)
	}
	log.Println("✓ Forward rule added")

	// Allow forwarding from out interface to TUN (established connections)
	err = RunCommand("iptables", "-A", "FORWARD",
		"-i", config.OutInterface,
		"-o", config.TunInterface,
		"-m", "state", "--state", "RELATED,ESTABLISHED",
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to add return forward rule: %w", err)
	}
	log.Println("✓ Return forward rule added")

	// Add MSS clamping for better compatibility
	err = RunCommand("iptables", "-t", "mangle", "-A", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu")
	if err != nil {
		log.Printf("Warning: Could not add MSS clamping: %v", err)
	} else {
		log.Println("✓ MSS clamping added")
	}

	return nil
}

// CleanupNAT removes NAT/masquerading rules
func CleanupNAT(config NATConfig) {
	// Remove in reverse order of addition

	// Remove MSS clamping
	RunCommand("iptables", "-t", "mangle", "-D", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu")

	// Remove return forward rule
	RunCommand("iptables", "-D", "FORWARD",
		"-i", config.OutInterface,
		"-o", config.TunInterface,
		"-m", "state", "--state", "RELATED,ESTABLISHED",
		"-j", "ACCEPT")

	// Remove forward rule
	RunCommand("iptables", "-D", "FORWARD",
		"-i", config.TunInterface,
		"-o", config.OutInterface,
		"-j", "ACCEPT")

	// Remove MASQUERADE rule
	RunCommand("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", config.SourceSubnet,
		"-o", config.OutInterface,
		"-j", "MASQUERADE")

	log.Println("✓ NAT rules cleaned up")
}

// AddMSSClamping adds TCP MSS clamping for better compatibility
func AddMSSClamping(mss int) error {
	if mss <= 0 {
		// Use automatic MSS clamping
		return RunCommand("iptables", "-t", "mangle", "-A", "FORWARD",
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu")
	}

	// Set specific MSS value
	return RunCommand("iptables", "-t", "mangle", "-A", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss))
}

// FlushIPTables flushes all iptables rules (use with caution!)
func FlushIPTables() error {
	log.Println("⚠ Flushing all iptables rules...")

	if err := RunCommand("iptables", "-F"); err != nil {
		return err
	}
	if err := RunCommand("iptables", "-t", "nat", "-F"); err != nil {
		return err
	}
	if err := RunCommand("iptables", "-t", "mangle", "-F"); err != nil {
		return err
	}

	log.Println("✓ IPTables flushed")
	return nil
}
