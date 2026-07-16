// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tap manages tap interfaces for VM-based workloads (Kata, Firecracker,
// QEMU). Unlike veth, tap interfaces are L2 file descriptors opened by userspace
// VMMs; the CNI plugin only configures the host side.
package tap

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// errIptablesMissing is returned when the iptables binary is not available.
// Callers can use errors.Is to check for this and skip iptables rules.
var errIptablesMissing = errors.New("iptables binary not available")

func updateForwardRule(interfaceName string, action string) error {
	protocols := []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6}
	for _, proto := range protocols {
		ipt, err := iptables.NewWithProtocol(proto)
		if err != nil {
			// iptables binary not available (e.g., distroless images).
			// Return a sentinel error so callers can decide whether to fail.
			return errIptablesMissing
		}

		rules := [][]string{
			{"-o", interfaceName, "-j", "ACCEPT"}, // egress
			{"-i", interfaceName, "-j", "ACCEPT"}, // ingress
		}

		for _, ruleSpec := range rules {
			switch action {
			case "add":
				if err := ipt.Insert("filter", "FORWARD", 1, ruleSpec...); err != nil {
					return err
				}
			case "delete":
				if err := ipt.Delete("filter", "FORWARD", ruleSpec...); err != nil {
					return err
				}
			default:
				return fmt.Errorf("invalid action: '%s' (must be 'add' or 'delete')", action)
			}
		}
	}

	return nil
}

// Add creates a tap interface with the given MTU, enslaves it to the VRF,
// applies sysctls and iptables FORWARD rules. Idempotent — repairs state
// if the tap already exists (crash-recovery).
func Add(vpc, vpcAttachment string, mtu int) error {
	vrfName := intf.GenerateInterfaceNameVRF(vpc, vpcAttachment)
	tapName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)

	vrfLink, err := netlink.LinkByName(vrfName)
	if err != nil {
		return fmt.Errorf("find VRF %q: %w", vrfName, err)
	}

	// Check if tap already exists (crash-recovery or prior partial failure).
	existingTap, err := netlink.LinkByName(tapName)
	if err == nil {
		slog.Warn("tap: found existing tap from a previous ADD attempt, repairing state", "tap", tapName)
		return repairTap(existingTap, vrfLink, tapName)
	}

	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: tapName,
			MTU:  mtu,
		},
		Mode: netlink.TUNTAP_MODE_TAP,
	}

	if err := netlink.LinkAdd(tap); err != nil {
		return fmt.Errorf("create tap %q: %w", tapName, err)
	}
	slog.Debug("tap: created", "tap", tapName, "mtu", mtu)

	tapLink, err := netlink.LinkByName(tapName)
	if err != nil {
		return err
	}

	// Enslave to VRF, add iptables rules, bring up, then apply sysctls.
	// Sysctl files (rp_filter, forwarding) are only populated by the kernel
	// after the interface is brought UP.
	if err := netlink.LinkSetMaster(tapLink, vrfLink); err != nil {
		return fmt.Errorf("enslave tap to VRF: %w", err)
	}

	// Allow forwarded traffic through the tap (bidirectional).
	if err := updateForwardRule(tapName, "add"); err != nil {
		if !errors.Is(err, errIptablesMissing) {
			return err
		}
		slog.Warn("tap: iptables binary not available, skipping FORWARD rules", "tap", tapName)
	}

	// Bring the interface up so the kernel populates sysctl entries.
	if err := netlink.LinkSetUp(tapLink); err != nil {
		return fmt.Errorf("bring up tap %q: %w", tapName, err)
	}

	// Apply tap-specific sysctls (rp_filter + forwarding, no proxy_arp/ndp).
	if err := sysctl.ConfigureTapSysctls(tapName); err != nil {
		return err
	}

	slog.Debug("tap: enslaved to VRF and up", "tap", tapName, "vrf", vrfName)
	return nil
}

// Delete removes the tap interface and cleans up iptables rules.
// Idempotent — silently skips if the interface does not exist.
func Delete(vpc, vpcAttachment string) error {
	tapName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)

	// Skip iptables cleanup if binary is unavailable (distroless images).
	if err := updateForwardRule(tapName, "delete"); err != nil && !errors.Is(err, errIptablesMissing) {
		return err
	}

	tapLink, err := netlink.LinkByName(tapName)
	if err != nil {
		slog.Debug("tap: already gone, nothing to delete", "tap", tapName)
		return nil // interface already gone — idempotent
	}

	if err := netlink.LinkDel(tapLink); err != nil {
		return err
	}
	slog.Debug("tap: deleted", "tap", tapName)
	return nil
}

// repairTap verifies and repairs a pre-existing tap interface's state.
func repairTap(tapLink netlink.Link, vrfLink netlink.Link, tapName string) error {
	// Verify VRF enslavement.
	if tapLink.Attrs().MasterIndex != vrfLink.Attrs().Index {
		slog.Warn("tap: re-enslaving tap to VRF during repair", "tap", tapName)
		if err := netlink.LinkSetMaster(tapLink, vrfLink); err != nil {
			return fmt.Errorf("re-enslave tap to VRF: %w", err)
		}
	}

	// Ensure iptables rules exist.
	if err := updateForwardRule(tapName, "add"); err != nil {
		return err
	}

	// Bring up if down (ensures sysctl entries are populated).
	if tapLink.Attrs().Flags&net.FlagUp == 0 {
		slog.Warn("tap: bringing tap back up during repair", "tap", tapName)
		if err := netlink.LinkSetUp(tapLink); err != nil {
			return fmt.Errorf("bring up tap %q: %w", tapName, err)
		}
	}

	// Apply sysctls (idempotent — sets the same values).
	return sysctl.ConfigureTapSysctls(tapName)
}

// isLinkNotFoundError reports whether err indicates that a network link
// does not exist. This covers both ENOENT and ENODEV errors from netlink.
func isLinkNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such device") || strings.Contains(msg, "not found")
}
