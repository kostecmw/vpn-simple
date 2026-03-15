package network

import (
	"fmt"
	"log"
	"strings"
)

// BackupDefaultRoute saves the current default route
func BackupDefaultRoute() (*RouteBackup, error) {
	output, err := RunCommandOutput("ip", "route", "show", "default")
	if err != nil {
		return nil, fmt.Errorf("failed to get default route: %w", err)
	}

	line := strings.TrimSpace(output)
	if line == "" {
		log.Println("No default route found to backup")
		return &RouteBackup{HadDefaultRoute: false}, nil
	}

	backup := &RouteBackup{HadDefaultRoute: true}

	// Parse: "default via 192.168.1.1 dev eth0"
	parts := strings.Fields(line)
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			backup.DefaultGateway = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			backup.DefaultIface = parts[i+1]
		}
	}

	if backup.DefaultGateway != "" && backup.DefaultIface != "" {
		log.Printf("✓ Backed up default route: via %s dev %s",
			backup.DefaultGateway, backup.DefaultIface)
		return backup, nil
	}

	return nil, fmt.Errorf("could not parse default route: %s", line)
}

// RestoreDefaultRoute restores a previously backed up default route
func RestoreDefaultRoute(backup *RouteBackup) error {
	if backup == nil || !backup.HadDefaultRoute {
		return nil
	}

	if backup.DefaultGateway == "" || backup.DefaultIface == "" {
		return fmt.Errorf("invalid backup data")
	}

	err := RunCommand("ip", "route", "add", "default",
		"via", backup.DefaultGateway,
		"dev", backup.DefaultIface)
	if err != nil {
		return fmt.Errorf("failed to restore default route: %w", err)
	}

	log.Printf("✓ Restored default route: via %s dev %s",
		backup.DefaultGateway, backup.DefaultIface)
	return nil
}

// DeleteDefaultRoute removes the current default route
func DeleteDefaultRoute() error {
	err := RunCommand("ip", "route", "del", "default")
	if err != nil {
		return fmt.Errorf("failed to delete default route: %w", err)
	}
	log.Println("✓ Removed old default route")
	return nil
}

// AddDefaultRoute adds a default route through the VPN
func AddDefaultRoute(config RouteConfig) error {
	err := RunCommand("ip", "route", "add", "default",
		"via", config.Gateway,
		"dev", config.TunInterface)
	if err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}
	log.Printf("✓ New default route via %s", config.Gateway)
	return nil
}

// AddRoute adds a specific route
func AddRoute(destination, gateway, iface string) error {
	err := RunCommand("ip", "route", "add", destination,
		"via", gateway,
		"dev", iface)
	if err != nil {
		return fmt.Errorf("failed to add route %s: %w", destination, err)
	}
	log.Printf("✓ Route %s via %s", destination, gateway)
	return nil
}

// DeleteRoute removes a route
func DeleteRoute(destination string) error {
	err := RunCommand("ip", "route", "del", destination)
	if err != nil {
		// Don't treat as fatal error
		log.Printf("Warning: Could not delete route %s: %v", destination, err)
		return nil
	}
	return nil
}

// AddServerRoute adds a direct route to the VPN server (prevents routing loop)
func AddServerRoute(serverIP string, backup *RouteBackup) error {
	if serverIP == "" || serverIP == "127.0.0.1" {
		return nil // Localhost, no route needed
	}

	if backup == nil || !backup.HadDefaultRoute {
		log.Println("No default route backup, skipping server route")
		return nil
	}

	err := RunCommand("ip", "route", "add", serverIP,
		"via", backup.DefaultGateway,
		"dev", backup.DefaultIface)
	if err != nil {
		return fmt.Errorf("failed to add server route: %w", err)
	}

	log.Printf("✓ Route to VPN server (%s) via original gateway", serverIP)
	return nil
}

// SetupDefaultRouting sets up default route through VPN (full tunnel)
func SetupDefaultRouting(config RouteConfig) error {
	// 1. Backup current default route
	if config.OriginalBackup == nil {
		return fmt.Errorf("route backup is required")
	}

	// 2. Add direct route to VPN server
	if config.ServerIP != "" {
		if err := AddServerRoute(config.ServerIP, config.OriginalBackup); err != nil {
			log.Printf("Warning: Could not add server route: %v", err)
		}
	}

	// 3. Delete old default route
	if config.OriginalBackup.HadDefaultRoute {
		if err := DeleteDefaultRoute(); err != nil {
			log.Printf("Warning: Could not delete old default route: %v", err)
		}
	}

	// 4. Add new default route via VPN
	if err := AddDefaultRoute(config); err != nil {
		// Try to restore on failure
		RestoreDefaultRoute(config.OriginalBackup)
		return err
	}

	return nil
}

// SetupSpecificRouting sets up routing for specific destinations
func SetupSpecificRouting(config RouteConfig) error {
	return AddRoute(config.Destination, config.Gateway, config.TunInterface)
}

// CleanupDefaultRouting removes VPN routing and restores original
func CleanupDefaultRouting(config RouteConfig) {
	// Remove VPN default route
	DeleteRoute("default")

	// Remove server-specific route
	if config.ServerIP != "" && config.ServerIP != "127.0.0.1" {
		DeleteRoute(config.ServerIP)
	}

	// Restore original default route
	if config.OriginalBackup != nil {
		RestoreDefaultRoute(config.OriginalBackup)
	}
}

// CleanupSpecificRouting removes specific route
func CleanupSpecificRouting(destination string) {
	DeleteRoute(destination)
}
