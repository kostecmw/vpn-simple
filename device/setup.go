package device

import (
	"fmt"
	"log"
	"strings"
)

// ConfigureTUN sets up the TUN interface with IP address
func (d *Device) Setup() error {
	// Configure TUN interface
	if err := d.ConfigureTUN(); err != nil {
		return fmt.Errorf("failed to configure TUN: %w", err)
		//log.Fatalf("Failed to configure TUN: %v", err)
	}

	// Setup routing
	if err := d.SetupRouting(); err != nil {
		return fmt.Errorf("failed to setup routing: %w", err)
	}

	// Setup NAT if enabled
	if d.config.EnableNAT {
		if err := d.SetupNAT(); err != nil {
			return fmt.Errorf("failed to setup NAT: %w", err)
		}
	}

	return nil
}

// ConfigureTUN sets up the TUN interface with IP address
func (d *Device) ConfigureTUN() error {
	log.Printf("Configuring TUN interface %s...", d.tun.Name())

	// Set IP address
	cidr := fmt.Sprintf("%s/%s", d.config.TunIP, d.config.TunMask)
	if err := runCommand("ip", "addr", "add", cidr, "dev", d.tun.Name()); err != nil {
		return fmt.Errorf("set IP address: %w", err)
	}
	log.Printf("✓ IP address: %s", cidr)

	// Set MTU
	if err := runCommand("ip", "link", "set", d.tun.Name(), "mtu", fmt.Sprintf("%d", d.tun.MTU())); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	log.Printf("✓ MTU: %d", d.tun.MTU())

	// Bring interface up
	if err := runCommand("ip", "link", "set", d.tun.Name(), "up"); err != nil {
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
		if err := runCommand("ip", "route", "add", "default", "via", gateway, "dev", d.tun.Name()); err != nil {
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

		if err := runCommand("ip", "route", "add", route, "via", gateway, "dev", d.tun.Name()); err != nil {
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
		"-i", d.tun.Name(), "-o", d.config.NATIface, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add forward rule: %w", err)
	}
	log.Printf("✓ Forward rule added")

	// Allow forwarding from NAT interface to TUN (established connections)
	if err := runCommand("iptables", "-A", "FORWARD",
		"-i", d.config.NATIface, "-o", d.tun.Name(),
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
