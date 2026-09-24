// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/srcfiltermap"
)

// USIDTarget adapts the uSID datapath's source filter maps to Target.
type USIDTarget struct {
	Filter *srcfiltermap.Filter
}

var _ Target = USIDTarget{}

// ListAllow implements Target.
func (t USIDTarget) ListAllow() ([]Entry, error) {
	in, err := t.Filter.ListAllow()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(in))
	for _, e := range in {
		out = append(out, Entry{Prefix: e.Prefix, IfaceMask: e.IfaceMask, AnyIface: e.AnyIface})
	}
	return out, nil
}

// PutAllow implements Target.
func (t USIDTarget) PutAllow(e Entry) error {
	return t.Filter.PutAllow(srcfiltermap.Entry{Prefix: e.Prefix, IfaceMask: e.IfaceMask, AnyIface: e.AnyIface})
}

// DeleteAllow implements Target.
func (t USIDTarget) DeleteAllow(p netip.Prefix) error { return t.Filter.DeleteAllow(p) }

// UplinkSlots implements Target.
func (t USIDTarget) UplinkSlots() (map[uint32]uint8, error) { return t.Filter.UplinkSlots() }

// SyncUplinkSlots implements Target.
func (t USIDTarget) SyncUplinkSlots(slots map[uint32]uint8) error {
	return t.Filter.SyncUplinkSlots(slots)
}

// State implements Target.
func (t USIDTarget) State() (State, error) {
	c, err := t.Filter.Config()
	if err != nil {
		return State{}, err
	}
	m, err := fromMapMode(c.Mode)
	if err != nil {
		return State{}, err
	}
	return State{Mode: m, Populated: c.Populated, Generation: uint64(c.Generation)}, nil
}

// SetState implements Target. The map holds a 32-bit generation, so the
// counter wraps there.
func (t USIDTarget) SetState(s State) error {
	m, err := toMapMode(s.Mode)
	if err != nil {
		return err
	}
	return t.Filter.SetConfig(srcfiltermap.Config{
		Mode:       m,
		Populated:  s.Populated,
		Generation: uint32(s.Generation), //nolint:gosec // an opaque counter; wrapping is harmless
	})
}

func toMapMode(m Mode) (srcfiltermap.Mode, error) {
	switch m {
	case ModeOff:
		return srcfiltermap.ModeOff, nil
	case ModeAudit:
		return srcfiltermap.ModeAudit, nil
	case ModeEnforce:
		return srcfiltermap.ModeEnforce, nil
	default:
		return srcfiltermap.ModeOff, fmt.Errorf("srcfilter: invalid mode %s", m)
	}
}

func fromMapMode(m srcfiltermap.Mode) (Mode, error) {
	switch m {
	case srcfiltermap.ModeOff:
		return ModeOff, nil
	case srcfiltermap.ModeAudit:
		return ModeAudit, nil
	case srcfiltermap.ModeEnforce:
		return ModeEnforce, nil
	default:
		return ModeOff, fmt.Errorf("srcfilter: datapath holds unknown mode %s", m)
	}
}

// MainTableRoutes lists every IPv6 route in the host's main routing table.
func MainTableRoutes() ([]netlink.Route, error) {
	return netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
}
