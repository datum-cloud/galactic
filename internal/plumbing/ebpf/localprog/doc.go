// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package localprog holds the tc programs of Worker's Local module (#1435)
// and their loader. local.c includes the uSID datapath source, so its policy
// decisions run the product's own tp_capture and tp_decide; Load replaces
// every uSID map those programs use with the map galactic-cni pinned, and
// fails rather than create one. The lt_* maps are Local's own and are pinned
// under the Local pin directory.
//
// local_meta.h is the metadata ABI a public receive program uses to hand a
// packet to local_rx.
package localprog

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -Wno-unused-function -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type lt_tap_value -type lt_link_value -type lt_guest_key -type lt_guest_value -type lt_pair_value -type lt_guard_value -type lt_flow_key -type lt_flow_value -type lt_rx_value Local local.c
