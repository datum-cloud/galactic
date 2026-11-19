// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package probe holds the prototype eBPF programs for the Local kernel
// handoffs (#1444) and the loader the lab's handoff-probe uses to place them
// on a scratch rig. It is test code and is never deployed.
//
// handoff.c includes the uSID datapath source, so its policy decisions run
// the product's own tp_capture and tp_decide. Load replaces every uSID map
// those programs use with the map galactic-cni pinned, and fails rather than
// create one.
package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -Wno-unused-function -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type hp_vip_value -type hp_shard_value -type hp_tap_value -type hp_snat_value -type hp_pair_rx_value -type hp_guard_value -type hp_cfg_value -type hp_in6 Handoff handoff.c
