// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgepreflight

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// The netdev generic netlink family reports, per interface, which XDP actions
// that interface's driver implements. It is the only way to learn whether a
// native XDP attach will be accepted without performing one: a driver with no
// ndo_bpf rejects the attach, but a driver that has one reallocates its rings
// to service it and drops carrier while it does. On a bond slave that carrier
// drop can cost the aggregate a member, so support has to be known before any
// link is touched.
//
// Constants are from include/uapi/linux/netdev.h.
const (
	netdevFamilyName = "netdev"

	netdevCmdDevGet = 1

	netdevAttrDevIfindex      = 1
	netdevAttrDevXDPFeatures  = 3
	netdevAttrDevXDPZCMaxSegs = 4

	// netdevXDPActBasic is the feature bit for the XDP actions every
	// XDP-capable driver implements: XDP_ABORTED, XDP_DROP, XDP_PASS and
	// XDP_TX. The edge datapath needs no more than these, so it is the
	// whole of what this checks.
	netdevXDPActBasic = 1
)

// ErrXDPFeaturesUnavailable reports that the running kernel does not serve the
// netdev generic netlink family, so per-interface XDP support cannot be read.
// The family landed in Linux 6.3; on anything older a caller has no choice but
// to discover support by attaching.
var ErrXDPFeaturesUnavailable = errors.New("edgepreflight: netdev generic netlink family unavailable")

// ifaceByNameFn is an override point so the ifindex lookup can be faked in
// tests alongside the family query.
var ifaceByNameFn = net.InterfaceByName

// InterfaceXDPFn is an override point, as elsewhere in this codebase, so tests
// can substitute a fake capability view without touching the host network
// stack.
var InterfaceXDPFn = InterfaceSupportsNativeXDP

// InterfaceSupportsNativeXDP reports whether ifaceName's driver implements the
// basic XDP actions, meaning a native-mode attach against it will be accepted.
//
// It returns [ErrXDPFeaturesUnavailable] when the kernel does not serve the
// netdev family at all, which a caller should treat as "cannot tell" rather
// than "unsupported".
func InterfaceSupportsNativeXDP(ifaceName string) (bool, error) {
	ifi, err := ifaceByNameFn(ifaceName)
	if err != nil {
		return false, fmt.Errorf("edgepreflight: find interface %q: %w", ifaceName, err)
	}

	conn, err := genetlink.Dial(nil)
	if err != nil {
		return false, fmt.Errorf("edgepreflight: dial generic netlink: %w", err)
	}
	defer conn.Close() //nolint:errcheck // read-only socket, nothing to flush

	family, err := conn.GetFamily(netdevFamilyName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, ErrXDPFeaturesUnavailable
		}
		return false, fmt.Errorf("edgepreflight: resolve the %q generic netlink family: %w", netdevFamilyName, err)
	}

	enc := netlink.NewAttributeEncoder()
	enc.Uint32(netdevAttrDevIfindex, uint32(ifi.Index)) //nolint:gosec // an ifindex is never negative
	data, err := enc.Encode()
	if err != nil {
		return false, fmt.Errorf("edgepreflight: encode netdev request for %q: %w", ifaceName, err)
	}

	msgs, err := conn.Execute(
		genetlink.Message{
			Header: genetlink.Header{Command: netdevCmdDevGet, Version: family.Version},
			Data:   data,
		},
		family.ID,
		netlink.Request,
	)
	if err != nil {
		return false, fmt.Errorf("edgepreflight: query XDP features of %q: %w", ifaceName, err)
	}

	for _, msg := range msgs {
		features, ok, err := xdpFeaturesFrom(msg.Data)
		if err != nil {
			return false, fmt.Errorf("edgepreflight: decode XDP features of %q: %w", ifaceName, err)
		}
		if ok {
			return features&netdevXDPActBasic != 0, nil
		}
	}
	// The interface exists and the family answered, but reported no feature
	// attribute. Treat that as "cannot tell" rather than claiming the driver
	// is unsupported on the strength of a missing field.
	return false, ErrXDPFeaturesUnavailable
}

// xdpFeaturesFrom pulls the XDP feature bitmask out of one netdev reply,
// reporting whether the attribute was present at all.
func xdpFeaturesFrom(data []byte) (uint64, bool, error) {
	dec, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return 0, false, err
	}
	var (
		features uint64
		found    bool
	)
	for dec.Next() {
		if dec.Type() == netdevAttrDevXDPFeatures {
			features = dec.Uint64()
			found = true
		}
	}
	if err := dec.Err(); err != nil {
		return 0, false, err
	}
	return features, found, nil
}
