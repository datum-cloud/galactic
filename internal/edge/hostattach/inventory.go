// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/nldump"
)

const aliasPrefix = "galactic-edge:hostattach:"
const vethType = "veth"

func ownerAlias(id string) string { return aliasPrefix + id }

// LinkID is the ID galactic-edge stamps on an attachment's links: the VPC
// identifier and the EdgeAttachment's UID. The UID makes a recreated
// attachment a different owner; the VPC names the ownership scope a link
// belongs to, and tells maintenance which VPC a link with no attachment left
// still uses.
func LinkID(vpc, uid string) string { return vpc + "." + uid }

// ParseLinkID splits an ID LinkID made. ok is false for any other ID.
func ParseLinkID(id string) (vpc, uid string, ok bool) {
	vpc, uid, ok = strings.Cut(id, ".")
	return vpc, uid, ok && vpc != "" && uid != ""
}

// ObservedAttachment identifies an owned host link, including partial attempts.
// It is observed kernel state, not a substitute for authorized durable intent.
type ObservedAttachment struct {
	ID          string
	HostLink    string
	HostIndex   int
	MasterIndex int
}

// List lists stamped host veths for restart reconciliation, including links
// created before any VRF or route was configured. Callers match IDs to their
// durable inventory before resuming or releasing resources.
func List(host *Namespace) ([]ObservedAttachment, error) {
	if err := host.Verify(); err != nil {
		return nil, err
	}
	h, err := host.netlink()
	if err != nil {
		return nil, err
	}
	defer func() { _ = h.Close() }()
	return listOwned(h)
}

// ListHost is List over the caller's own network namespace. Its netlink
// socket is opened in place rather than by entering a namespace, so it needs
// no CAP_SYS_ADMIN: a process that holds only CAP_NET_ADMIN, such as
// galactic-router, can call it from the host's namespace.
func ListHost() ([]ObservedAttachment, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("hostattach: netlink handle in the current network namespace: %w", err)
	}
	defer func() { _ = h.Close() }()
	return listOwned(h)
}

func listOwned(h *netlink.Handle) ([]ObservedAttachment, error) {
	links, err := nldump.On(h).LinkList()
	if err != nil {
		return nil, fmt.Errorf("hostattach: list owned links: %w", err)
	}
	var result []ObservedAttachment
	for _, l := range links {
		id, owned := strings.CutPrefix(l.Attrs().Alias, aliasPrefix)
		if l.Type() != vethType || !owned || id == "" {
			continue
		}
		result = append(result, ObservedAttachment{ID: id, HostLink: l.Attrs().Name,
			HostIndex: l.Attrs().Index, MasterIndex: l.Attrs().MasterIndex})
	}
	return result, nil
}

func hostPrefixes(a Attachment) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(a.Prefixes)+1)
	prefixes = append(prefixes, netip.PrefixFrom(a.Address, 128))
	return append(prefixes, a.Prefixes...)
}

// extraRoutes lists static unicast destinations on a dedicated owned link that
// no longer appear in desired state. Kernel-derived local/link-local routes
// and routes using other links are never candidates for deletion.
func extraRoutes(h *netlink.Handle, index int, table uint32, want []netip.Prefix) ([]netlink.Route, error) {
	routes, err := nldump.On(h).RouteListFiltered(unix.AF_INET6, &netlink.Route{Table: int(table), LinkIndex: index},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, fmt.Errorf("hostattach: list attachment routes: %w", err)
	}
	var extras []netlink.Route
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST || r.Protocol == unix.RTPROT_KERNEL {
			continue
		}
		found := false
		for _, p := range want {
			if sameDst(r.Dst, p) {
				found = true
				break
			}
		}
		if !found {
			extras = append(extras, r)
		}
	}
	return extras, nil
}

func pruneRoutes(h *netlink.Handle, index int, table uint32, want []netip.Prefix) error {
	extras, err := extraRoutes(h, index, table, want)
	if err != nil {
		return err
	}
	for _, r := range extras {
		if err := h.RouteDel(&r); err != nil {
			return fmt.Errorf("hostattach: remove stale route %s: %w", r.Dst, err)
		}
	}
	return nil
}
