// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vrf manages the Linux VRF interfaces that isolate Galactic VPC
// networks. Each VPC gets one VRF with its own routing table ID per node,
// shared by every attachment landing on that VPC on that node rather than one
// per attachment. Requires CAP_NET_ADMIN.
package vrf

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// SidecarTableIDBase splits the routing table ID space between the two
// writers of the shared pinned eBPF maps. The host's VRFs take IDs below it,
// and the ingress sidecar's take IDs above it.
//
// Each network namespace allocates table IDs on its own, but
// egress_route_table is keyed by table ID alone and is shared between the
// host and every sidecar pod on the node. Without disjoint ranges, a sidecar
// VRF and a host tenant VRF both start at table 1 and overwrite each other's
// routes.
const SidecarTableIDBase = uint32(0x10000)

// HostTableIDMin and HostTableIDMax bound the routing table IDs Add allocates.
// HostTableIDMax stops short of SidecarTableIDBase: the host's installer keeps
// its sidecar return-path tables in the host namespace in the IDs between the
// two (internal/installer/sidecarreturn.go).
const (
	HostTableIDMin = uint32(1)
	HostTableIDMax = uint32(0xEFFF)
)

// UnreachableDefaultMetric is the metric of the unreachable default route Add
// installs in every VRF table, for each family. It is the value the kernel's
// own VRF documentation (Documentation/networking/vrf.rst) recommends: high
// enough that any real default route installed in the table, such as the
// ingress sidecar's, always wins over it.
const UnreachableDefaultMetric = 4278198272

// ErrNotFound is wrapped by TableID when no VRF interface for that VPC exists
// in this process's own network namespace.
//
// Callers need that distinguishable from a genuine netlink failure, because
// absent is an ordinary condition for some of them: a process in the host's
// root namespace legitimately cannot see a VRF the ingress sidecar created
// inside a pod's namespace, while a failed link listing is a real problem
// either way.
var ErrNotFound = errors.New("vrf: no VRF interface for this VPC in this network namespace")

// ErrTableOutOfRange is wrapped by AddInRange when this VPC's VRF already exists
// with a table ID outside the caller's range, for instance one created by an
// ingress sidecar version that allocated from the host's range.
var ErrTableOutOfRange = errors.New("vrf: existing VRF's table is outside the caller's range")

// vrfMu serializes VRF creation and deletion within one process. It does not by
// itself protect two separate CNI invocations racing on the same node, each
// being its own process, so Add and Delete also take a cross-process lock.
var vrfMu sync.Mutex

// Add creates the Linux VRF interface for a base62-encoded VPC, allocating the
// next available routing table ID in [HostTableIDMin, HostTableIDMax] and
// applying the required sysctls.
//
// The VRF is shared by every attachment on this VPC on this node, so concurrent
// calls, from goroutines here or from separate plugin processes attaching
// different pods, are serialized. It is idempotent by name: a VRF that already
// exists, whether created by a sibling attachment or left behind by a failed
// ADD, returns nil.
//
// Every call, including one that finds the VRF already present, ensures the
// table's unreachable defaults (see ensureUnreachableDefaults). A VRF created
// before those existed therefore gains them on its next attachment's ADD,
// with no migration step.
func Add(vpc string) error {
	return AddInRange(vpc, HostTableIDMin, HostTableIDMax)
}

// AddInRange is Add with the routing table ID allocated from [minID, maxID].
// A VRF that already exists under this VPC's name with a table ID outside that
// range is an error: its table may collide with the other writer's, and
// recreating it would strand whatever is already routed through it.
func AddInRange(vpc string, minID, maxID uint32) error {
	vrfMu.Lock()
	defer vrfMu.Unlock()

	lock, err := acquireLock()
	if err != nil {
		return err
	}
	defer func() { _ = lock.close() }()

	name := intf.GenerateInterfaceNameVRF(vpc)

	if link, err := netlink.LinkByName(name); err == nil {
		existing, ok := link.(*netlink.Vrf)
		if !ok {
			return fmt.Errorf("interface %q exists but is a %s, not a VRF", name, link.Type())
		}
		if existing.Table < minID || existing.Table > maxID {
			return fmt.Errorf("VRF %q has table %d, not in [%d,%d]: %w",
				name, existing.Table, minID, maxID, ErrTableOutOfRange)
		}
		return ensureUnreachableDefaults(existing.Table)
	}

	vrfID, err := findNextAvailableVRFID(minID, maxID)
	if err != nil {
		return err
	}

	if err := FlushTable(vrfID); err != nil {
		return err
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: vrfID,
	}

	if err := netlink.LinkAdd(vrf); err != nil {
		return err
	}

	if err := sysctl.ConfigureInterfaceSysctls(name); err != nil {
		return err
	}

	// Installed before the VRF comes up, so no packet is ever routed in it
	// without the catch-all in place.
	if err := ensureUnreachableDefaults(vrfID); err != nil {
		return err
	}

	return netlink.LinkSetUp(vrf)
}

// ensureUnreachableDefaults installs an unreachable default route for IPv4
// and IPv6 in VRF table tableID, at UnreachableDefaultMetric.
//
// Without it, a lookup that misses in the VRF's table does not stop there.
// The l3mdev rule only selects the table, and a miss falls through to the
// rules after it, ending in the main table. A tenant packet the eBPF datapath
// does not claim would then be routed by the host's own routes, out the
// node's default interface with the tenant's source address. The kernel's
// VRF documentation calls for exactly this route to prevent that. A packet
// with no route in its VRF now fails there, and the sender gets an ICMP
// unreachable.
//
// Idempotent: the route is replaced rather than added.
func ensureUnreachableDefaults(tableID uint32) error {
	defaults := []*net.IPNet{
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
	for _, dst := range defaults {
		route := &netlink.Route{
			Dst:      dst,
			Table:    int(tableID),
			Type:     unix.RTN_UNREACHABLE,
			Priority: UnreachableDefaultMetric,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("install unreachable default %s in VRF table %d: %w", dst, tableID, err)
		}
	}
	return nil
}

// Delete flushes every route from the VRF's routing table and removes the
// interface for a base62-encoded VPC. Idempotent: an absent interface returns
// nil.
//
// Callers must only invoke it once no attachment on this VPC on this node
// remains live, since deleting out from under a sibling breaks it. The CNI
// teardown path never calls it for that reason; only garbage collection does,
// after confirming through every advertisement for this VPC and node that none
// is still in use.
func Delete(vpc string) error {
	vrfMu.Lock()
	defer vrfMu.Unlock()

	lock, err := acquireLock()
	if err != nil {
		return err
	}
	defer func() { _ = lock.close() }()

	name := intf.GenerateInterfaceNameVRF(vpc)

	vrfID, err := getVRFIDForInterface(name)
	if err != nil {
		return nil // VRF already gone — idempotent
	}

	if err := FlushTable(vrfID); err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // interface already gone — idempotent
	}

	return netlink.LinkDel(link)
}

// TableID returns the Linux routing table ID for a base62-encoded VPC's VRF.
// The error wraps ErrNotFound when no such interface exists in this process's
// own network namespace, which some callers treat as ordinary rather than a
// failure.
func TableID(vpc string) (uint32, error) {
	return getVRFIDForInterface(intf.GenerateInterfaceNameVRF(vpc))
}

// Exists reports whether a VRF interface for the given VPC exists in the
// kernel.
func Exists(vpc string) error {
	name := intf.GenerateInterfaceNameVRF(vpc)
	if _, err := netlink.LinkByName(name); err != nil {
		return fmt.Errorf("VRF interface %q not found", name)
	}
	return nil
}

// FlushTable removes every IPv4 and IPv6 route from the given routing table.
// Add calls it before creating a VRF on a reused table ID, which happens when a
// previous VRF was removed without going through Delete, and Delete calls it
// before removing the interface, so a stale table is always cleared rather than
// inherited.
//
// Exported so garbage collection's fallback path, which removes a legacy-named
// interface directly rather than through Delete, can flush the table itself and
// get the same guarantee.
func FlushTable(vrfID uint32) error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: int(vrfID)},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if err := netlink.RouteDel(&route); err != nil {
				return err
			}
		}
	}
	return nil
}

// linkDumpAttempts and linkDumpBackoff bound how long ListVRFLinks keeps
// retrying a dump that other processes keep interrupting. Each attempt is
// itself up to 10 tries inside netlink, so this only matters under sustained
// link churn; the pause lets a burst of changes finish before the next dump.
const (
	linkDumpAttempts = 5
	linkDumpBackoff  = 20 * time.Millisecond
)

// ListVRFLinks returns all VRF interfaces currently present on the host.
//
// The link dump retries when the kernel flags it interrupted, which happens
// whenever another process adds or removes a link while the dump is running.
// The package-level netlink.LinkList makes a single attempt and returns
// ErrDumpInterrupted, which failed a caller on a node with unrelated link
// churn. TableID, Add and the sidecar's startup inventory all list through
// here.
func ListVRFLinks() ([]*netlink.Vrf, error) {
	handle, err := netlink.NewHandleWithOptions(netlink.HandleOptions{RetryInterrupted: true})
	if err != nil {
		return nil, err
	}
	defer handle.Close() //nolint:errcheck // best-effort close of our own sockets

	var links []netlink.Link
	for attempt := 1; ; attempt++ {
		links, err = handle.LinkList()
		if err == nil {
			break
		}
		// An interrupted dump may be incomplete, so its partial result is
		// never used: a VRF missing from it would look absent.
		if !errors.Is(err, netlink.ErrDumpInterrupted) || attempt == linkDumpAttempts {
			return nil, err
		}
		time.Sleep(time.Duration(attempt) * linkDumpBackoff)
	}

	vrfLinks := make([]*netlink.Vrf, 0, len(links))
	for _, link := range links {
		if v, ok := link.(*netlink.Vrf); ok {
			vrfLinks = append(vrfLinks, v)
		}
	}
	return vrfLinks, nil
}

func listVRFLinks() ([]*netlink.Vrf, error) {
	return ListVRFLinks()
}

func findNextAvailableVRFID(minID, maxID uint32) (uint32, error) {
	vrfs, err := listVRFLinks()
	if err != nil {
		return 0, err
	}

	used := make(map[uint32]struct{}, len(vrfs))
	for _, vrf := range vrfs {
		used[vrf.Table] = struct{}{}
	}
	return nextFreeTableID(used, minID, maxID)
}

// nextFreeTableID returns the lowest table ID in [minID, maxID] that is
// neither in used nor one of the kernel's reserved tables (253 default, 254
// main, 255 local). A VRF bound to main would route its tenant through the
// host's own table.
func nextFreeTableID(used map[uint32]struct{}, minID, maxID uint32) (uint32, error) {
	for vrfID := uint64(minID); vrfID <= uint64(maxID); vrfID++ {
		id := uint32(vrfID)
		if id == unix.RT_TABLE_DEFAULT || id == unix.RT_TABLE_MAIN || id == unix.RT_TABLE_LOCAL {
			continue
		}
		if _, ok := used[id]; !ok {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no available VRF table id in [%d,%d]", minID, maxID)
}

func getVRFIDForInterface(name string) (uint32, error) {
	vrfs, err := listVRFLinks()
	if err != nil {
		return 0, err
	}

	vrfByName := make(map[string]*netlink.Vrf, len(vrfs))
	for _, vrf := range vrfs {
		vrfByName[vrf.Name] = vrf
	}

	if vrf, ok := vrfByName[name]; ok {
		return vrf.Table, nil
	}
	return 0, fmt.Errorf("could not find VRF ID for interface %s: %w", name, ErrNotFound)
}
