// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// linkListFn is an override point, matching linkByNameFn, so the bond sibling
// lookup can be faked in tests.
var linkListFn = netlink.LinkList

// attachFn is an override point so Set's tests can drive attachment without a
// real program or a real NIC.
var attachFn = attachOne

// attachedLink is one interface's XDP link, along with the ifindex it was
// attached to. The ifindex is what tells a member replaced under the same name
// apart from the one this link still points at.
type attachedLink struct {
	link  link.Link
	index int
}

// Set is the live set of interfaces one XDP program is attached to, kept
// current after startup by Reconcile.
//
// It only ever adds. An interface that drops out of the desired set while it
// still exists keeps its program: detaching makes the driver reallocate its
// rings exactly as attaching does, so a route flap that briefly took an uplink
// out of the desired set would otherwise bounce that link twice, and on a bond
// both bounces land on a member the aggregate is still using. A link is
// released only once its interface is gone, or has been replaced by a new one
// under the same name.
//
// A Set is safe for concurrent use.
type Set struct {
	program *ebpf.Program

	mu      sync.Mutex
	links   map[string]attachedLink
	missing []string
}

// NewSet returns a Set for program that already holds links, the result of an
// Attach of names at startup, in the same order.
func NewSet(program *ebpf.Program, names []string, links []link.Link) (*Set, error) {
	if program == nil {
		return nil, errors.New("xdpattach: program is nil")
	}
	if len(names) != len(links) {
		return nil, fmt.Errorf("xdpattach: %d interface names for %d links", len(names), len(links))
	}
	s := &Set{program: program, links: make(map[string]attachedLink, len(names))}
	for i, name := range names {
		// An index that cannot be read leaves 0, which no live interface
		// has, so the next Reconcile re-reads it and releases the link if
		// the interface really is gone.
		var index int
		if l, err := linkByNameFn(name); err == nil {
			index = l.Attrs().Index
		}
		s.links[name] = attachedLink{link: links[i], index: index}
	}
	return s, nil
}

// Reconcile attaches the program to every interface in desired that does not
// already hold it, and releases the link of every attached interface that no
// longer exists. It returns the desired interfaces still without the program,
// in desired's order, which Missing reports until the next call.
//
// New interfaces are attached one at a time through the same gate Attach
// uses: each is checked for native XDP support first, and a bond slave is
// waited back into its aggregate before the next is touched. A bond slave that
// is carrying traffic while none of its siblings is, is left for a later call
// rather than attached: attaching bounces it, and with no sibling carrying
// traffic the bounce takes the whole uplink down.
//
// Unlike Attach, one interface failing does not undo the others. It is
// reported missing and retried on the next call, and every link already held
// stays attached.
func (s *Set) Reconcile(desired []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.releaseGone()

	var missing []string
	blocked := false
	for _, name := range desired {
		if _, ok := s.links[name]; ok {
			continue
		}
		if blocked {
			missing = append(missing, name)
			continue
		}
		if err := s.attachNew(name); err != nil {
			slog.Warn("xdpattach: cannot attach XDP program to interface yet, will retry", "interface", name, "err", err)
			missing = append(missing, name)
			continue
		}
		if err := waitBondSlaveReady(name, BondReadyTimeout); err != nil {
			// The program is attached, so name is covered, but its bond has
			// not taken it back yet. Attaching the next member now could take
			// both down together, so the rest wait for the next call.
			slog.Warn("xdpattach: attached interface has not rejoined its bond; deferring the rest",
				"interface", name, "err", err)
			blocked = true
		}
	}

	s.missing = missing
	return slices.Clone(missing)
}

// Missing reports the interfaces the last Reconcile could not attach to. It is
// empty before the first call, the startup Attach having covered every name it
// was given.
func (s *Set) Missing() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.missing)
}

// Attached reports every interface currently holding the program, sorted.
func (s *Set) Attached() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.links))
	for name := range s.links {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// releaseGone closes the link of every interface that no longer exists, or
// exists under the same name with a different ifindex. Either way the link
// points at a device the program no longer runs on, and the name is free to be
// attached again. Any other lookup failure keeps the link: a transient netlink
// error is no reason to give up coverage.
func (s *Set) releaseGone() {
	for name, held := range s.links {
		l, err := linkByNameFn(name)
		var notFound netlink.LinkNotFoundError
		switch {
		case errors.As(err, &notFound):
			slog.Info("xdpattach: interface is gone, releasing its XDP link", "interface", name)
		case err != nil:
			continue
		case l.Attrs().Index == held.index:
			continue
		default:
			slog.Info("xdpattach: interface was replaced, releasing the old XDP link", "interface", name,
				"oldIndex", held.index, "newIndex", l.Attrs().Index)
		}
		_ = held.link.Close()
		delete(s.links, name)
	}
}

// attachNew attaches the program to one interface not yet in the set, after
// the checks that keep doing so from costing a bond its uplink.
func (s *Set) attachNew(name string) error {
	if err := checkNativeXDPSupport([]string{name}); err != nil {
		return err
	}
	isolates, err := bounceIsolatesBond(name)
	if err != nil {
		return err
	}
	if isolates {
		return fmt.Errorf("xdpattach: %q is the only member of its bond carrying traffic; "+
			"attaching now would take the bond down", name)
	}

	xdpLink, err := attachFn(s.program, name)
	if err != nil {
		return err
	}
	var index int
	if l, err := linkByNameFn(name); err == nil {
		index = l.Attrs().Index
	}
	s.links[name] = attachedLink{link: xdpLink, index: index}
	slog.Info("xdpattach: attached XDP program to interface found after startup", "interface", name)
	return nil
}

// bounceIsolatesBond reports whether attaching to ifaceName now would leave
// its bond with no member carrying traffic: ifaceName is a bond slave carrying
// traffic, it has siblings, and none of them is.
//
// A slave not carrying traffic yet, such as a member that has only just been
// enslaved, costs the bond nothing to bounce. A slave with no siblings at all
// is attached regardless, as at startup: there is no aggregate to protect, and
// waiting would only leave it uncovered for good.
func bounceIsolatesBond(ifaceName string) (bool, error) {
	slave, masterIndex, ok, err := bondSlaveOf(ifaceName)
	if err != nil || !ok {
		return false, err
	}
	lacp, err := bondUsesLACP(masterIndex)
	if err != nil {
		return false, err
	}
	if !bondSlaveCarryingTraffic(slave, lacp) {
		return false, nil
	}

	links, err := linkListFn()
	if err != nil {
		return false, fmt.Errorf("xdpattach: list links for the siblings of %q: %w", ifaceName, err)
	}
	siblings := 0
	for _, l := range links {
		attrs := l.Attrs()
		if attrs.MasterIndex != masterIndex || attrs.Name == ifaceName {
			continue
		}
		sib, ok := attrs.Slave.(*netlink.BondSlave)
		if !ok {
			continue
		}
		siblings++
		if bondSlaveCarryingTraffic(sib, lacp) {
			return false, nil
		}
	}
	return siblings > 0, nil
}
