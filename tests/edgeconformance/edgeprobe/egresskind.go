// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// egressKind prints how the uSID datapath delivers to a host link: the row
// of ifindex_egress_kind_table for the link's ifindex, as
// {"t","ifindex","kind","present"}. kind 0 is a veth, delivered with
// bpf_redirect_peer into its peer's namespace, and 1 is a tap, delivered with
// bpf_redirect. present is false when the link has no row.
func egressKind(args []string) error {
	fs := flag.NewFlagSet("egresskind", flag.ExitOnError)
	iface := fs.String("iface", "", "host link")
	pinDir := fs.String("pin-dir", "/sys/fs/bpf/galactic", "the uSID datapath's pin directory")
	_ = fs.Parse(args)
	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(*pinDir, "ifindex_egress_kind_table"),
		&ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("open ifindex_egress_kind_table: %w", err)
	}
	defer func() { _ = m.Close() }()
	var kind uint32
	present := true
	if err := m.Lookup(uint32(ifi.Index), &kind); errors.Is(err, ebpf.ErrKeyNotExist) { //nolint:gosec // ifindex
		present = false
	} else if err != nil {
		return err
	}
	return out.Encode(map[string]any{"t": boottime(), "ifindex": ifi.Index, "kind": kind, "present": present})
}
