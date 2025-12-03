package device

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

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
