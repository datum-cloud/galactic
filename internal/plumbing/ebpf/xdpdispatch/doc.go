// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package xdpdispatch shares a node's XDP hook between the datapaths that
// need it: the edge gateway's load-balancing and return programs, and the
// egress shard's translation program.
//
// An interface takes one native XDP program. Before this package, the gateway
// attached its own programs and the shard ran as a tail call inside them, so
// the shard depended on the gateway: a gateway restart detached the hook and
// cut egress, and a shard configured to chain on a node with no gateway never
// became ready (issue #717).
//
// # How it works
//
// One small root program, xdp_dispatch, is attached to every interface either
// datapath needs. It owns no packet logic. It looks up the ingress interface's
// role bits and tail-calls, in slot order, every slot those roles permit whose
// lease is live and which holds a program. A datapath that does not claim a
// packet passes it on with dispatch_next (dispatch.h), so every later slot
// still sees it. The last slot, the egress shard, returns XDP_PASS itself.
//
// Each datapath fills only its own slot (Fill), sets the role bits for its own
// interfaces (SetRole), and renews its slot's lease while it runs (Lease).
//
// # Lifetime
//
// Everything is pinned under PinDir: the maps and root under a versioned
// directory, the links under links/. Pinning the links is what keeps the root
// attached when a datapath's process exits, so a restart of either datapath
// neither detaches the hook nor resets the NIC's rings. A restarted datapath
// replaces its program in its slot, which the kernel does atomically.
//
// A slot whose lease has passed is skipped, so a datapath that was removed, or
// that has been down for longer than LeaseTTL, stops claiming packets instead
// of acting on state nobody maintains. Its traffic passes to the later slots
// and the kernel, as it would with no program attached.
//
// The root stays attached after every datapath is gone. Release detaches it.
//
// # Upgrades
//
// The maps are ABI and are never recreated: unpinning a prog array empties
// every slot in it, including the other datapath's. A layout change that
// cannot be made by appending gets a new versioned directory. The root can
// change without a new layout: a process carrying a newer RootRevision swaps
// it on every link with a link update, which neither detaches the hook nor
// leaves the interface without a program.
//
// # Locking
//
// Two processes can attach to the same interfaces, so first attaches and the
// bond-member waits that follow them run under Lock, an flock on PinDir.
// Without it, the gateway and the shard could each bounce a different member
// of one bond at the same time and take the bond down.
//
// # Generated code
//
// dispatch.c and dispatch.h are the source of truth. `go generate` compiles
// them with clang and generates the Go bindings here. The generated files are
// gitignored and regenerated at every build site, as for the other datapath
// packages.
package xdpdispatch

// See the uSID program package's doc.go for why the include flags list both
// multiarch directories and why the compiler is not named explicitly.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb Dispatch dispatch.c
