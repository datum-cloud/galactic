// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// linkByNameFn and linkDelFn are the kernel lookups the host-link reclaim
// makes under the VRF lock; variables so unprivileged tests can substitute
// fabricated links.
var (
	linkByNameFn = netlink.LinkByName
	linkDelFn    = netlink.LinkDel
)

// reclaimHostLinksFn is reclaimHostLinks, indirected so tests can observe or
// fail the reclaim RemoveOrphanedCRDs runs before deleting an advertisement.
var reclaimHostLinksFn = reclaimHostLinks

// containerKey returns the form a container ID takes in a BGPAdvertisement's
// netns annotation key, the key collectNetNSPaths reads back.
func containerKey(containerID string) string {
	return strings.TrimPrefix(crdnames.NetNSKey(containerID), annotationNetNS+".")
}

// hostLinkBelongsTo reports whether link is a host link of the attachment
// whose orphaned BGPAdvertisement o describes, owned by one of the containers
// o recorded, every one of which GC has found gone.
//
// A link the master plugin stamped belongs to o when it is on o's VPC and its
// owner, read through any host-only ports its alias also records
// (ifindexvrfmap.AliasOwner), is among o's dead containers. A container ID names one sandbox, whose
// netns every one of its attachments shares, so an owner o recorded as dead is
// dead on every attachment. A link carrying no owner, which builds before the
// stamp left, belongs to o only when its name maps to o's name exactly. A link
// owned by any other container is never o's to reclaim: it may be a live pod
// that has since taken the attachment over.
func hostLinkBelongsTo(link netlink.Link, o OrphanedCRD) bool {
	vpc, attachment, ok := intf.ParseInterfaceNameHost(link.Attrs().Name)
	if !ok {
		return false
	}
	if !vpcInSet(map[string]struct{}{vpcFromName(o.Name): {}}, vpc) {
		return false
	}
	owner := ifindexvrfmap.AliasOwner(link.Attrs().Alias)
	if owner == "" {
		return o.Node != "" && crdnames.BGPAdvertisementName(vpc, attachment, o.Node) == o.Name
	}
	_, dead := o.DeadContainers[containerKey(owner)]
	return dead
}

// reclaimHostLinks removes every host link belonging to the attachment whose
// orphaned BGPAdvertisement o describes (see hostLinkBelongsTo), returning how
// many it removed.
//
// The advertisement is the last record of who owned the attachment. GC deletes
// it once every container it recorded is gone, but a host-namespace link --
// a tap whose sandbox's DEL never ran or never removed it -- outlives its
// netns. Left behind, it stays enslaved to the VPC's VRF and keeps its
// pod-subnet route, and the next attachment the control plane gives that
// address is refused its own route on every retry. So the link goes first, and
// the kernel removes its routes with it. Once the advertisement is deleted,
// nothing on the node can prove the link dead any more.
//
// Each removal is decided again under the VRF lock, which every master plugin
// holds while it creates, adopts and stamps a host link, so a link a new
// container took over since it was listed is kept.
func reclaimHostLinks(o OrphanedCRD) (int, error) {
	links, err := listAllLinksFn()
	if err != nil {
		return 0, fmt.Errorf("list links: %w", err)
	}
	removed := 0
	var errs []error
	for _, l := range links {
		if !hostLinkBelongsTo(l, o) {
			continue
		}
		name, index := l.Attrs().Name, l.Attrs().Index
		var gone bool
		err := vrfLockedFn(func() error {
			cur, err := linkByNameFn(name)
			if err != nil {
				var notFound netlink.LinkNotFoundError
				if errors.As(err, &notFound) {
					return nil
				}
				return fmt.Errorf("find host link %q: %w", name, err)
			}
			if cur.Attrs().Index != index || !hostLinkBelongsTo(cur, o) {
				slog.Info("GC: kept host link another container took over since it was listed",
					"name", name, "owner", cur.Attrs().Alias, "resource_name", o.Name)
				return nil
			}
			if err := linkDelFn(cur); err != nil {
				return fmt.Errorf("delete host link %q: %w", name, err)
			}
			gone = true
			return nil
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if gone {
			slog.Info("GC: removed host link of a dead attachment",
				"name", name, "owner", l.Attrs().Alias, "resource_name", o.Name)
			removed++
		}
	}
	return removed, errors.Join(errs...)
}
