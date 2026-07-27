// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// addRedirect wires bidirectional tc-mirred redirects between fromLink and
// toLink: every packet ingressing on fromLink is stolen and re-injected as
// an egress packet on toLink. Calling it twice, once with (eth0, tap0) and
// once with (tap0, eth0), gives the full bidirectional pattern described in
// .local/kraftlet-cilium-tap-plan.md section 3 — same mechanism
// awslabs/tc-redirect-tap uses for Firecracker.
//
// Callers must already be running inside the target network namespace.
// priority must not collide with Cilium's own clsact hooks on fromLink —
// see the tc/bpf hook ordering caveat in docs/vmtap-cni/configuration.md;
// this is unvalidated against any specific Cilium version/datapath mode.
func addRedirect(fromLink, toLink netlink.Link, priority uint16) error {
	if err := ensureIngressQdisc(fromLink); err != nil {
		return fmt.Errorf("ensure ingress qdisc on %q: %w", fromLink.Attrs().Name, err)
	}

	if err := removeRedirectFilter(fromLink, priority); err != nil {
		return fmt.Errorf("clear stale redirect filter on %q: %w", fromLink.Attrs().Name, err)
	}

	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: fromLink.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{
			&netlink.MirredAction{
				ActionAttrs:  netlink.ActionAttrs{Action: netlink.TC_ACT_STOLEN},
				MirredAction: netlink.TCA_EGRESS_REDIR,
				Ifindex:      toLink.Attrs().Index,
			},
		},
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("add redirect filter %s->%s: %w", fromLink.Attrs().Name, toLink.Attrs().Name, err)
	}
	slog.Debug("vmtap: redirect filter installed",
		"from", fromLink.Attrs().Name, "to", toLink.Attrs().Name, "priority", priority)
	return nil
}

// ensureIngressQdisc adds an ingress qdisc to link if one is not already
// present. Idempotent, and tolerant of Cilium (or anything else) having
// already attached its own qdisc — an ingress qdisc is shared per-link, so
// finding one already there (of any recognized type) is not an error; only
// a failed add when none exists is.
func ensureIngressQdisc(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs: %w", err)
	}
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_INGRESS {
			return nil
		}
	}

	qdisc := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_INGRESS,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("add ingress qdisc: %w", err)
	}
	return nil
}

// hasRedirectFilter reports whether a filter at the given priority exists on
// link's ingress qdisc — used by cmdCheck to verify ADD's filters are still
// in place.
func hasRedirectFilter(link netlink.Link, priority uint16) (bool, error) {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, fmt.Errorf("list filters: %w", err)
	}
	for _, f := range filters {
		if f.Attrs().Priority == priority {
			return true, nil
		}
	}
	return false, nil
}

// removeRedirectFilter deletes the redirect filter this plugin owns at the
// given priority on link's ingress qdisc, if present. Idempotent — a
// missing filter is not an error.
func removeRedirectFilter(link netlink.Link, priority uint16) error {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("list filters: %w", err)
	}
	for _, f := range filters {
		if f.Attrs().Priority == priority {
			if err := netlink.FilterDel(f); err != nil {
				return fmt.Errorf("delete filter at priority %d: %w", priority, err)
			}
		}
	}
	return nil
}

// deleteRedirect removes the redirect filter this plugin installed on link.
// It intentionally leaves the ingress qdisc itself in place — on eth0 that
// qdisc may be shared with Cilium's own hooks, and deleting it out from
// under a still-running pod interface would be far riskier than leaving an
// unused qdisc behind. Idempotent.
func deleteRedirect(link netlink.Link, priority uint16) error {
	if err := removeRedirectFilter(link, priority); err != nil {
		return fmt.Errorf("remove redirect filter on %q: %w", link.Attrs().Name, err)
	}
	return nil
}
