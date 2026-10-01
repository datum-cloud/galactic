// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mssclamp computes and writes the TCP MSS limits the uSID datapath
// clamps SYNs to, into its mss_clamp_table map.
//
// The fabric carries a tenant packet inside a 40-byte outer IPv6 header with no
// SRH, so a tenant packet can be at most the uplink MTU minus 40, while a tenant
// interface at the uplink's own MTU sizes its TCP segments for the full MTU.
// Nothing on the path fragments an oversized packet or reports it, so every
// full-size segment of such a connection is dropped. Clamping the MSS each SYN
// advertises makes both ends size their segments to fit. See usid.c's struct
// mss_clamp_value for where the datapath applies it.
package mssclamp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

const (
	// OuterHeaderLen is the encapsulation overhead a tenant packet carries
	// across the fabric: one outer IPv6 header. A single uSID segment fits in
	// that header's destination address, so there is no SRH.
	OuterHeaderLen = 40

	ipv6HeaderLen = 40
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20

	// MinMTU is the smallest fabric MTU a clamp is computed for: the IPv6
	// minimum link MTU (RFC 8200). The fabric's underlay is IPv6, so a smaller
	// one could not carry it at all, and treating it as a misconfiguration is
	// safer than deriving a tiny MSS from it.
	MinMTU = 1280

	// MaxMTU is the largest value an MTU override may name, the largest a
	// 16-bit IPv6 payload length allows.
	MaxMTU = 65535
)

// Values is one mss_clamp_table entry: the MSS limit for each tenant address
// family. Zero turns clamping off for that family.
type Values struct {
	IPv4 uint16
	IPv6 uint16
}

// Off is the Values that turns clamping off for both families.
var Off = Values{}

// IsOff reports whether v clamps neither family.
func (v Values) IsOff() bool { return v == Off }

// FromMTU returns the limits for a fabric whose uplink MTU is mtu: the largest
// TCP payload whose packet still fits once encapsulated. At an MTU of 1500 that
// is 1420 for IPv4 tenants and 1400 for IPv6 ones.
//
// No third value is needed for NAT64. An IPv6 tenant's limit makes a
// 1440-byte IPv4 packet at a 1500 MTU, which grows by 20 bytes when the egress
// shard translates it back to IPv6 and by 40 when it is re-encapsulated: 1500
// again.
func FromMTU(mtu int) (Values, error) {
	if mtu < MinMTU || mtu > MaxMTU {
		return Off, fmt.Errorf("fabric MTU %d is outside [%d, %d]", mtu, MinMTU, MaxMTU)
	}
	return Values{
		IPv4: uint16(mtu - OuterHeaderLen - ipv4HeaderLen - tcpHeaderLen),
		IPv6: uint16(mtu - OuterHeaderLen - ipv6HeaderLen - tcpHeaderLen),
	}, nil
}

// Mode values the override setting takes, besides an MTU number.
const (
	ModeAuto = "auto"
	ModeOff  = "off"
)

// ErrNoUplinkMTU is returned by Resolve in auto mode when no uplink MTU is
// known yet.
var ErrNoUplinkMTU = errors.New("no fabric uplink MTU to size the MSS clamp from")

// Resolve returns the limits for override, the operator's setting, given the
// MTUs of the fabric uplinks the datapath is attached to.
//
// override is ModeAuto or empty (size the clamp from the smallest uplink MTU,
// since a packet may leave by any of them), ModeOff (no clamping), or a number,
// read as the fabric MTU to size against. The number is for a path whose real
// MTU is below what the interfaces report, such as a VLAN tag carried inside a
// 1500-byte link. An invalid override is an error rather than a silent fallback
// to auto, so a typo cannot quietly clamp to the wrong value.
func Resolve(override string, uplinkMTUs []int) (Values, error) {
	switch v := strings.ToLower(strings.TrimSpace(override)); v {
	case "", ModeAuto:
		if len(uplinkMTUs) == 0 {
			return Off, ErrNoUplinkMTU
		}
		lowest := uplinkMTUs[0]
		for _, mtu := range uplinkMTUs[1:] {
			lowest = min(lowest, mtu)
		}
		return FromMTU(lowest)
	case ModeOff:
		return Off, nil
	default:
		mtu, err := strconv.Atoi(v)
		if err != nil {
			return Off, fmt.Errorf("MSS clamp setting %q is not %q, %q, or a fabric MTU", override, ModeAuto, ModeOff)
		}
		return FromMTU(mtu)
	}
}

// Putter is the one operation Write needs from mss_clamp_table, so tests can
// substitute a fake. A loaded *ebpf.Map satisfies it.
type Putter interface {
	Put(key, value any) error
}

// Write stores v in table's single entry.
func Write(table Putter, v Values) error {
	if err := table.Put(uint32(0), prog.UsidMssClampValue{MssIpv4: v.IPv4, MssIpv6: v.IPv6}); err != nil {
		return fmt.Errorf("write mss_clamp_table: %w", err)
	}
	return nil
}

// LinkMTU returns the MTU of the named interface. A package-level override
// point so tests need no real interface.
var LinkMTU = func(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}
	return link.Attrs().MTU, nil
}

// UplinkMTUs returns the MTU of each named uplink. An uplink that cannot be
// read is an error rather than skipped: sizing the clamp from the others could
// leave it too high for the one that was missed.
func UplinkMTUs(names []string) ([]int, error) {
	mtus := make([]int, 0, len(names))
	for _, name := range names {
		mtu, err := LinkMTU(name)
		if err != nil {
			return nil, fmt.Errorf("read MTU of uplink %q: %w", name, err)
		}
		mtus = append(mtus, mtu)
	}
	return mtus, nil
}

// Reconciler keeps mss_clamp_table in step with the operator's setting and the
// uplinks' MTUs. It writes the map only when the values change, so it is cheap
// to call on every health tick.
type Reconciler struct {
	table    Putter
	override string
	uplinks  func() ([]string, error)

	written bool
	last    Values
}

// NewReconciler returns a Reconciler writing table, sized per override (see
// Resolve) from the MTUs of the interfaces uplinks returns.
func NewReconciler(table Putter, override string, uplinks func() ([]string, error)) *Reconciler {
	return &Reconciler{table: table, override: override, uplinks: uplinks}
}

// Reconcile computes the current values and writes them if they differ from
// the last write. It returns the values in effect and whether they changed.
//
// On any error the map is left as it was. A node that has never written it
// reads zero, which is clamping off: an unresolved MTU leaves the datapath
// exactly as it behaved before the clamp existed, rather than guessing.
func (r *Reconciler) Reconcile() (Values, bool, error) {
	v, err := r.resolve()
	if err != nil {
		return r.last, false, err
	}
	if r.written && v == r.last {
		return v, false, nil
	}
	if err := Write(r.table, v); err != nil {
		return r.last, false, err
	}
	r.written, r.last = true, v
	return v, true, nil
}

func (r *Reconciler) resolve() (Values, error) {
	mode := strings.ToLower(strings.TrimSpace(r.override))
	if mode != "" && mode != ModeAuto {
		return Resolve(r.override, nil)
	}
	names, err := r.uplinks()
	if err != nil {
		return Off, fmt.Errorf("resolve fabric uplinks: %w", err)
	}
	mtus, err := UplinkMTUs(names)
	if err != nil {
		return Off, err
	}
	return Resolve(r.override, mtus)
}
