// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostscope is Worker's view of one VPC's canonical host state on
// the node: the host VRF and its table, the SID Argument and BGPVRFInstance,
// and the VPC's vrf_table row. CNI attachments and service claims of the VPC
// share that state. Worker owns the VPC's write fence (internal/ownership)
// and writes the state only inside its commits. CNI writes the same state
// with Exclusive whether or not Worker runs.
//
// The links enslaved to the VRF are the attachments CNI created. Worker
// observes them, reading each one's current ifindex and neighbors when asked,
// and never creates or deletes them.
package hostscope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/nodevpc"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/nldump"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Plan is what Worker read of a VPC's host state before a commit, without
// writing.
type Plan struct {
	// Present is true when the VPC's host VRF exists.
	Present bool
	// Links are the names of the links enslaved to the VRF.
	Links []string
	// EdgeUsed is true when a Galactic Edge attachment uses the VPC.
	EdgeUsed bool
	// Ensure is true when the VPC has claims and some of its canonical state
	// is missing or wrong.
	Ensure bool
}

// Referenced reports whether anything on the node other than Worker's own
// claims uses the VPC's host state.
func (p Plan) Referenced() bool { return len(p.Links) > 0 || p.EdgeUsed }

// Neighbor is one neighbor entry on an attachment's link.
type Neighbor struct {
	Addr  netip.Addr
	MAC   net.HardwareAddr
	State int
}

// Attachment is one link enslaved to a VPC's host VRF, as read from the
// kernel at the time of the call.
type Attachment struct {
	Name string
	// Index is the link's current ifindex, which changes when CNI replaces
	// the attachment.
	Index int
	// Kind is the link type, such as "tuntap" or "veth".
	Kind      string
	Up        bool
	Neighbors []Neighbor
}

// Host reads and writes VPCs' canonical host state.
type Host interface {
	// Discover returns every VPC with a host VRF on the node.
	Discover(ctx context.Context) ([]string, error)
	// Plan reads vpc's host state. claimed tells it whether Worker holds
	// claims in vpc, which need the canonical state ensured.
	Plan(ctx context.Context, vpc string, claimed bool) (Plan, error)
	// Ensure creates whatever is missing of vpc's canonical state and
	// changes nothing already in place. Worker calls it inside its commit.
	Ensure(ctx context.Context, vpc string) error
	// Reclaim removes vpc's VRF and BGPVRFInstance when nothing on the node
	// uses them, judged again under the commit, and reports whether the VRF
	// is gone. Worker calls it inside its commit, only for a VPC it holds no
	// claims in.
	Reclaim(ctx context.Context, vpc string) (bool, error)
	// Attachments returns the links enslaved to vpc's VRF, read now.
	Attachments(ctx context.Context, vpc string) ([]Attachment, error)
}

// Kernel is the Host of the calling process's network namespace, which must
// be the host's.
type Kernel struct {
	// K8s reads and writes BGPRouters and BGPVRFInstances. It should read
	// the API server rather than a cache, so an Argument claim sees every
	// instance.
	K8s client.Client
	// Namespace holds the node's BGPRouter and BGPVRFInstances.
	Namespace string
	// Node is this node.
	Node string
	// PinDir is the bpffs directory of the pinned uSID maps.
	PinDir string
	// Edge reports the VPCs Galactic Edge attachments use.
	Edge gc.EdgeUsers
}

var _ Host = (*Kernel)(nil)

func (k *Kernel) cfg() nodevpc.Config {
	return nodevpc.Config{K8s: k.K8s, Namespace: k.Namespace, Node: k.Node, PinDir: k.PinDir}
}

// Discover returns the VPC of every Galactic host VRF.
func (k *Kernel) Discover(context.Context) ([]string, error) {
	links, err := vrf.ListVRFLinks()
	if err != nil {
		return nil, fmt.Errorf("list VRF links: %w", err)
	}
	var vpcs []string
	for _, l := range links {
		if vpc, ok := gc.VPCFromVRFName(l.Name); ok {
			vpcs = append(vpcs, vpc)
		}
	}
	sort.Strings(vpcs)
	return vpcs, nil
}

// Plan reads vpc's VRF, its enslaved links and edge use, and, when claimed,
// whether its canonical state is in place.
func (k *Kernel) Plan(ctx context.Context, vpc string, claimed bool) (Plan, error) {
	var p Plan
	links, err := Enslaved(vpc)
	switch {
	case errors.Is(err, vrf.ErrNotFound):
	case err != nil:
		return p, err
	default:
		p.Present = true
		for _, l := range links {
			p.Links = append(p.Links, l.Attrs().Name)
		}
	}
	if k.Edge != nil {
		vpcs, err := k.Edge.VPCs(ctx)
		if err != nil {
			return p, fmt.Errorf("find VPCs edge attachments use: %w", err)
		}
		_, p.EdgeUsed = vpcs[vpc]
	}
	if claimed {
		ok, err := nodevpc.InPlace(ctx, k.cfg(), vpc)
		if err != nil {
			return p, err
		}
		p.Ensure = !ok
	}
	return p, nil
}

// Ensure runs nodevpc.Ensure for vpc.
func (k *Kernel) Ensure(ctx context.Context, vpc string) error {
	_, err := nodevpc.Ensure(ctx, k.cfg(), vpc)
	return err
}

// Reclaim runs gc.ReclaimVPC for vpc and reports whether its VRF is gone.
func (k *Kernel) Reclaim(ctx context.Context, vpc string) (bool, error) {
	if _, err := gc.ReclaimVPC(ctx, k.K8s, k.Namespace, k.Node, vpc, k.Edge); err != nil {
		return false, err
	}
	_, err := vrf.TableID(vpc)
	switch {
	case errors.Is(err, vrf.ErrNotFound):
		return true, nil
	case err != nil:
		return false, err
	}
	return false, nil
}

// Attachments returns AttachmentsOf(vpc).
func (k *Kernel) Attachments(_ context.Context, vpc string) ([]Attachment, error) {
	return AttachmentsOf(vpc)
}

// Enslaved returns the links whose master is vpc's host VRF, in the calling
// process's network namespace. The error wraps vrf.ErrNotFound when the VRF
// does not exist.
func Enslaved(vpc string) ([]netlink.Link, error) {
	name := intf.GenerateInterfaceNameVRF(vpc)
	master, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil, fmt.Errorf("VRF %s: %w", name, vrf.ErrNotFound)
		}
		return nil, fmt.Errorf("look up VRF %s: %w", name, err)
	}
	links, err := nldump.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	var out []netlink.Link
	for _, l := range links {
		if l.Attrs().MasterIndex == master.Attrs().Index {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Attrs().Name < out[j].Attrs().Name })
	return out, nil
}

// AttachmentsOf returns the links enslaved to vpc's host VRF with their
// current ifindex and neighbors, in the calling process's network namespace,
// or none when the VRF does not exist.
func AttachmentsOf(vpc string) ([]Attachment, error) {
	links, err := Enslaved(vpc)
	if errors.Is(err, vrf.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]Attachment, 0, len(links))
	for _, l := range links {
		a := l.Attrs()
		att := Attachment{Name: a.Name, Index: a.Index, Kind: l.Type(), Up: a.Flags&net.FlagUp != 0}
		neighs, err := netlink.NeighList(a.Index, unix.AF_UNSPEC)
		if err != nil {
			return nil, fmt.Errorf("list neighbors of %s: %w", a.Name, err)
		}
		for _, n := range neighs {
			addr, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			att.Neighbors = append(att.Neighbors, Neighbor{Addr: addr.Unmap(), MAC: n.HardwareAddr, State: n.State})
		}
		out = append(out, att)
	}
	return out, nil
}
