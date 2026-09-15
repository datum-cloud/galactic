// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package veth

import (
	"errors"
	"fmt"
	"log/slog"
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
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such device") || strings.Contains(msg, "not found")
}

// isIptablesRuleNotFoundError reports whether err means the rule does not
// exist. The library returns a generic error whose message names that
// condition.
func isIptablesRuleNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "rule not found")
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

// Add creates this attachment's veth pair, enslaves the host end to the VPC's
// VRF, and records ownerID -- the CNI container ID of the container this pair
// was created for -- on the host end.
//
// The ownership stamp is what lets Delete tell this container's interface from
// one belonging to a container that has since taken the attachment over. Both
// ends are named from (vpc, vpcAttachment) alone, so a replacement container on
// the same attachment produces the very same names, and nothing in the name
// distinguishes the two.
func Add(vpc, vpcAttachment, ownerID string, mtu int) error {
	vrfName := intf.GenerateInterfaceNameVRF(vpc)
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	guestName := intf.GenerateInterfaceNameGuest(vpc, vpcAttachment)

	// A host veth left behind by a failed ADD with no matching DEL: clean up
	// the stale guest end and recreate the pair, so the guest side is in a
	// known-good state.
	if existing, err := netlink.LinkByName(hostName); err == nil {
		slog.Warn("veth: removing stale host veth left behind by a previous ADD attempt",
			"host", hostName, "guest", guestName, "previousOwner", existing.Attrs().Alias, "owner", ownerID)
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
		return fmt.Errorf("create veth pair %s/%s: %w", hostName, guestName, err)
	}
	slog.Debug("veth: pair created", "host", hostName, "guest", guestName, "mtu", mtu)

	// Claim the pair for ownerID before anything else can observe it. Stamped
	// on the link itself rather than tracked out of band because the only
	// process that needs to read it is a later CNI DEL, which runs as its own
	// short-lived process with no shared state and deliberately no Kubernetes
	// client.
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("look up newly created veth %q: %w", hostName, err)
	}
	if err := netlink.LinkSetAlias(hostLink, ownerID); err != nil {
		return fmt.Errorf("record owner %q on veth %q: %w", ownerID, hostName, err)
	}

	// iptables is not available in distroless images; skip forwarding rules
	// gracefully so the CNI plugin can still produce a result in test environments.
	if err := updateForwardRule(hostName, "add"); err != nil {
		if !errors.Is(err, errIptablesMissing) {
			return err
		}
		slog.Warn("veth: iptables binary not available, skipping FORWARD rules", "host", hostName)
	}

	if err := sysctl.ConfigureInterfaceSysctls(hostName); err != nil {
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

	if err := netlink.LinkSetMaster(hostLink, vrfLink); err != nil {
		return err
	}
	slog.Debug("veth: enslaved to VRF and up", "host", hostName, "vrf", vrfName)
	return nil
}

// OwnedBy reports whether link, a host veth, still belongs to ownerID.
//
// A link carrying no owner at all is treated as owned by whoever asks. It
// predates this stamp -- created by an earlier build, or by an ADD that failed
// before it got that far -- and refusing to clean those up would leak an
// interface per attachment with nothing left to reclaim it.
func OwnedBy(link netlink.Link, ownerID string) bool {
	alias := link.Attrs().Alias
	return alias == "" || alias == ownerID
}

// Delete removes this attachment's veth pair, but only while it still belongs
// to ownerID, the CNI container ID whose ADD created it.
//
// The ownership check is the whole point. Both ends are named from (vpc,
// vpcAttachment) alone, so a container replacing another on the same attachment
// -- a rolling restart, where the replacement's ADD runs while its predecessor
// is still terminating -- recreates the pair under the same names. The
// predecessor's DEL then arrives up to a termination grace period later and,
// going by name, would tear down the interface the live container is using. The
// pod stays Running with an address and no interface, and nothing retries,
// because from CNI's point of view both operations succeeded.
//
// This is the same race ops_del.go already defers the VRF and the BGP CRDs to
// GC for. The veth was left out of that reasoning as "private to this
// attachment", which is exactly the key that turns out not to be unique per
// container. Ownership is checked rather than deferring to GC because an
// interface, unlike a CRD, must be reclaimed promptly for the attachment to be
// reusable.
func Delete(vpc, vpcAttachment, ownerID string) error {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)

	// Resolved first so ownership can be judged before anything is removed. A
	// nil link with no error means it is already gone, which is not a failure:
	// the rules below are still worth withdrawing in that case, since an
	// interface that disappeared by some other route leaves them behind.
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		if !isLinkNotFoundError(err) {
			return err
		}
		hostLink = nil
	}

	// Checked before the iptables rules come out, not only before the link
	// does: those rules belong to whoever owns the interface now, and
	// withdrawing them would have the live container's traffic dropped by the
	// FORWARD policy with its interface still in place.
	if hostLink != nil && !OwnedBy(hostLink, ownerID) {
		slog.Info("veth: leaving host veth alone, another container has taken this attachment over",
			"host", hostName, "owner", hostLink.Attrs().Alias, "requestedBy", ownerID)
		return nil
	}

	// Skip iptables cleanup if binary is unavailable or the rule is already
	// gone (distroless images, or Delete already ran).
	if err := updateForwardRule(hostName, "delete"); err != nil {
		if errors.Is(err, errIptablesMissing) || isIptablesRuleNotFoundError(err) {
			// iptables not available or rule already absent — nothing to clean up.
		} else {
			return err
		}
	}

	if hostLink == nil {
		slog.Debug("veth: host veth already gone, nothing to delete", "host", hostName)
		return nil // interface already gone — idempotent
	}

	if err := netlink.LinkDel(hostLink); err != nil {
		return err
	}
	slog.Debug("veth: deleted", "host", hostName, "owner", ownerID)
	return nil
}
