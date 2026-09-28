// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tap manages tap interfaces for VM-based workloads. Unlike a veth, a
// tap is an L2 file descriptor opened by a userspace VMM; the CNI plugin only
// configures the host side.
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
				// A rule already gone is the desired end state, and treating it
				// as a failure would make a repeated or partial DEL impossible
				// to complete.
				if err := ipt.DeleteIfExists("filter", "FORWARD", ruleSpec...); err != nil {
					return err
				}
			default:
				return fmt.Errorf("invalid action: '%s' (must be 'add' or 'delete')", action)
			}
		}
	}

	return nil
}

// AddResult reports whether Add created this attachment's tap or adopted one
// that already existed, and, in the adopted case, who owned it before. cmdAdd
// uses it the same way the veth plugin's own result is used: a tap this call
// created is ours to remove on a failed ADD's rollback; one it adopted from a
// still-terminating predecessor must be handed back to that owner instead.
type AddResult struct {
	// Adopted is true when Add found an existing host tap under this
	// attachment's name and took it over rather than creating a fresh one.
	Adopted bool

	// PriorOwner is the alias (CNI container ID) stamped on the host tap Add
	// took over, or "" if the link carried none. Meaningful only when Adopted.
	PriorOwner string
}

// Add creates a tap interface with the given MTU, enslaves it to the VRF, and
// applies the sysctls and firewall rules it needs. Idempotent, repairing state
// when the tap already exists, and stamping ownerID -- the CNI container ID
// this ADD is running for -- on the tap either way.
//
// Unlike the veth plugin, a tap found already present is never deleted and
// recreated: a Kata VMM may still hold its file descriptor open across a
// container replacement, and tearing the device down from under a live guest
// would break it outright. It is adopted in place instead, and res.Adopted /
// res.PriorOwner record whether this call is the one that created it, the
// same distinction the veth plugin's rollback needs (see its own Add doc).
//
// The ownership stamp this leaves is also what lets a later Delete tell this
// container's tap from one belonging to a container that has since taken the
// attachment over: both a fresh and an adopted tap share the same name, keyed
// by (vpc, vpcAttachment) alone, with nothing else to distinguish them.
func Add(vpc, vpcAttachment, ownerID string, mtu int) (res AddResult, _ error) {
	vrfName := intf.GenerateInterfaceNameVRF(vpc)
	tapName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)

	vrfLink, err := netlink.LinkByName(vrfName)
	if err != nil {
		return res, fmt.Errorf("find VRF %q: %w", vrfName, err)
	}

	// Check if tap already exists (crash-recovery, prior partial failure, or a
	// predecessor container this attachment is being taken over from).
	if existingTap, err := netlink.LinkByName(tapName); err == nil {
		res.Adopted = true
		res.PriorOwner = existingTap.Attrs().Alias
		slog.Warn("tap: found existing tap from a previous ADD attempt, repairing state",
			"tap", tapName, "priorOwner", res.PriorOwner, "owner", ownerID)
		if err := repairTap(existingTap, vrfLink, tapName, mtu); err != nil {
			return res, err
		}
		// Claim the tap for ownerID now that its state is known good, so a
		// dead predecessor's delayed DEL sees the current owner rather than
		// its own stale alias and leaves this device alone.
		if err := netlink.LinkSetAlias(existingTap, ownerID); err != nil {
			return res, fmt.Errorf("record owner %q on tap %q: %w", ownerID, tapName, err)
		}
		return res, nil
	}

	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: tapName},
		Mode:      netlink.TUNTAP_MODE_TAP,
	}

	if err := netlink.LinkAdd(tap); err != nil {
		return res, fmt.Errorf("create tap %q: %w", tapName, err)
	}
	slog.Debug("tap: created", "tap", tapName, "mtu", mtu)

	tapLink, err := netlink.LinkByName(tapName)
	if err != nil {
		return res, err
	}

	if err := ensureMTU(tapLink, tapName, mtu); err != nil {
		return res, err
	}

	// Claim the tap for ownerID before anything else can observe it, same as
	// the veth plugin: the only reader is a later CNI DEL, its own short-lived
	// process with no shared state to consult instead.
	if err := netlink.LinkSetAlias(tapLink, ownerID); err != nil {
		return res, fmt.Errorf("record owner %q on tap %q: %w", ownerID, tapName, err)
	}

	// Enslave to the VRF, add the rules, bring the link up, then apply sysctls:
	// the kernel only populates the sysctl files once the interface is up.
	if err := netlink.LinkSetMaster(tapLink, vrfLink); err != nil {
		return res, fmt.Errorf("enslave tap to VRF: %w", err)
	}

	// Allow forwarded traffic through the tap (bidirectional).
	if err := updateForwardRule(tapName, "add"); err != nil {
		if !errors.Is(err, errIptablesMissing) {
			return res, err
		}
		slog.Warn("tap: iptables binary not available, skipping FORWARD rules", "tap", tapName)
	}

	// Bring the interface up so the kernel populates sysctl entries.
	if err := netlink.LinkSetUp(tapLink); err != nil {
		return res, fmt.Errorf("bring up tap %q: %w", tapName, err)
	}

	// Apply tap-specific sysctls (rp_filter + forwarding, no proxy_arp/ndp).
	if err := sysctl.ConfigureTapSysctls(tapName); err != nil {
		return res, err
	}

	slog.Debug("tap: enslaved to VRF and up", "tap", tapName, "vrf", vrfName)
	return res, nil
}

// RestoreOwner sets the alias on this attachment's host tap back to ownerID --
// the CNI container ID of the container that previously held it. A failed ADD
// whose tap step adopted an existing device calls this instead of Delete, so
// the tap is handed back to its prior owner, whose own DEL (arriving once
// that container finishes terminating) reclaims it, rather than being torn
// down out from under a still-live predecessor.
//
// It is a no-op when the host tap is already gone, which is not an error:
// with nothing to restore, there is nothing the prior owner's DEL still
// depends on.
func RestoreOwner(vpc, vpcAttachment, ownerID string) error {
	tapName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	tapLink, err := netlink.LinkByName(tapName)
	if err != nil {
		if isLinkNotFoundError(err) {
			return nil
		}
		return err
	}
	if err := netlink.LinkSetAlias(tapLink, ownerID); err != nil {
		return fmt.Errorf("restore owner %q on tap %q: %w", ownerID, tapName, err)
	}
	slog.Debug("tap: restored prior owner", "tap", tapName, "owner", ownerID)
	return nil
}

// OwnedBy reports whether link, a host tap, still belongs to ownerID.
//
// A link carrying no owner at all is treated as owned by whoever asks. It
// predates this stamp -- created by an earlier build, or by an ADD that
// failed before it got that far -- and refusing to clean those up would leak
// an interface per attachment with nothing left to reclaim it.
func OwnedBy(link netlink.Link, ownerID string) bool {
	alias := link.Attrs().Alias
	return alias == "" || alias == ownerID
}

// Delete removes the tap interface and cleans up iptables rules, but only
// while it still belongs to ownerID, the CNI container ID whose ADD created
// or adopted it. Idempotent — silently skips if the interface does not exist.
//
// The ownership check exists for the same reason the veth plugin's does: the
// host name is keyed by (vpc, vpcAttachment) alone, so a container replacing
// another on the same attachment can already have taken this device over by
// the time a predecessor's DEL, delayed behind its own termination, arrives.
// Going by name alone would tear down a live successor's tap.
func Delete(vpc, vpcAttachment, ownerID string) error {
	tapName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)

	tapLink, err := netlink.LinkByName(tapName)
	if err != nil {
		if !isLinkNotFoundError(err) {
			return err
		}
		tapLink = nil
	}

	if tapLink != nil && !OwnedBy(tapLink, ownerID) {
		slog.Info("tap: leaving host tap alone, another container has taken this attachment over",
			"tap", tapName, "owner", tapLink.Attrs().Alias, "requestedBy", ownerID)
		return nil
	}

	// Skip iptables cleanup if binary is unavailable (distroless images).
	if err := updateForwardRule(tapName, "delete"); err != nil && !errors.Is(err, errIptablesMissing) {
		return err
	}

	if tapLink == nil {
		slog.Debug("tap: already gone, nothing to delete", "tap", tapName)
		return nil // interface already gone — idempotent
	}

	if err := netlink.LinkDel(tapLink); err != nil {
		return err
	}
	slog.Debug("tap: deleted", "tap", tapName, "owner", ownerID)
	return nil
}

// ensureMTU sets the tap's MTU to mtu, leaving the kernel default in place
// when none is configured.
//
// Creating a tap never applies an MTU: the tap is made by an ioctl that has no
// MTU field, and the netlink library silently drops the one it is given. An
// unset MTU leaves the tap at 1500, too large for a VPC network whose packets
// gain an SRv6 header on the wire, and the guest adopts whatever the tap
// carries.
func ensureMTU(tapLink netlink.Link, tapName string, mtu int) error {
	if mtu <= 0 || tapLink.Attrs().MTU == mtu {
		return nil
	}
	if err := netlink.LinkSetMTU(tapLink, mtu); err != nil {
		return fmt.Errorf("set MTU %d on tap %q: %w", mtu, tapName, err)
	}
	return nil
}

// repairTap verifies and repairs a pre-existing tap interface's state.
func repairTap(tapLink netlink.Link, vrfLink netlink.Link, tapName string, mtu int) error {
	// A tap left behind by an earlier ADD keeps whatever MTU it had, and the
	// caller reports this tap's MTU to the guest, so a wrong value would
	// otherwise persist for the life of the instance.
	if err := ensureMTU(tapLink, tapName, mtu); err != nil {
		return err
	}

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
