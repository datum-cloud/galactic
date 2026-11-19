// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package localfixture holds test stand-ins for the XDP programs the gateway
// and the NAT shard run at Worker's Local handoffs, so the Local programs can
// be tested end to end on a real kernel. It is test code and is never
// deployed.
package localfixture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -Wno-unused-function -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type ltf_vip_value -type ltf_shard_value -type ltf_snat_value -type ltf_in6 Fixture fixture.c
