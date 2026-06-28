// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package veth

import (
	"errors"
	"fmt"
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

// isLinkNotFoundError reports whether err indicates that a network link
// does not exist. This covers both ENOENT and ENODEV errors from netlink.
func isLinkNotFoundError(err error) bool {
	if os.IsNotExist(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such device") || strings.Contains(msg, "not found")
}

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

func Add(vpc, vpcAttachment string, mtu int) error {
	vrfName := intf.GenerateInterfaceNameVRF(vpc, vpcAttachment)
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	guestName := intf.GenerateInterfaceNameGuest(vpc, vpcAttachment)

	// If the host veth already exists (e.g. left behind by a failed cmdAdd
	// with no corresponding cmdDel), clean up the stale guest end and recreate
	// the pair so the guest side is in a known-good state.
	if existing, err := netlink.LinkByName(hostName); err == nil {
		// Remove any stale guest endpoint that may linger from a prior run.
		if guest, guestErr := netlink.LinkByName(guestName); guestErr == nil {
			netlink.LinkDel(guest) //nolint:errcheck // best-effort cleanup
		}
		if err := netlink.LinkDel(existing); err != nil && !isLinkNotFoundError(err) {
			return fmt.Errorf("remove stale veth %q: %w", hostName, err)
		}
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostName,
			MTU:  mtu,
		},
		PeerName: guestName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}

	// iptables is not available in distroless images; skip forwarding rules
	// gracefully so the CNI plugin can still produce a result in test environments.
	if err := updateForwardRule(hostName, "add"); err != nil && !errors.Is(err, errIptablesMissing) {
		return err
	}

	if err := sysctl.ConfigureInterfaceSysctls(hostName); err != nil {
		return err
	}

	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return err
	}
	guestLink, err := netlink.LinkByName(guestName)
	if err != nil {
		return err
	}
	vrfLink, err := netlink.LinkByName(vrfName)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetUp(hostLink); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(guestLink); err != nil {
		return err
	}

	return netlink.LinkSetMaster(hostLink, vrfLink)
}

func Delete(vpc, vpcAttachment string) error {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)

	// Skip iptables cleanup if binary is unavailable (distroless images).
	if err := updateForwardRule(hostName, "delete"); err != nil && !errors.Is(err, errIptablesMissing) {
		return err
	}

	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return err
	}

	return netlink.LinkDel(hostLink)
}
