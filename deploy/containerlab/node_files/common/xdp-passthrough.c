// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// xdp-passthrough.c is a trivial, always-XDP_PASS eBPF program that exists
// for exactly one reason: on a veth pair, the kernel's native XDP_TX fast
// path only promotes a redirected frame into the peer interface's normal
// receive stack if the peer *also* has an XDP program attached -- without
// one, the frame is queued through a raw fast path nothing but another XDP
// program on that peer can see, and in this lab's multi-hop topology it
// never actually arrives anywhere (confirmed live: with no XDP program on
// the peer, the receiving node's own eBPF datapath counters for the
// affected traffic stay at exactly zero; attaching this program is what
// makes them move).
//
// Both XDP datapaths on an edge node leave their packets from the driver:
// the egress shard (internal/plumbing/ebpf/natprog) and galactic-gateway's
// edge_lb/edge_return (internal/plumbing/ebpf/edgeprog/edgedsr.c), XDP_TX
// back out the interface a packet arrived on, XDP_REDIRECT out another. On a
// real edge node's uplinks, genuine physical NICs, that is the ordinary
// high-throughput XDP pattern. This program's only job is making this lab's
// veth-pair simulation of those uplinks behave the way a real NIC already
// does, on whichever node sits on the *other* end of a link facing an edge
// node: the transit ports facing each edge node's transit bond, where a
// translated packet leaves toward the off-fabric host and edge_return sends
// a backend's reply toward the client, and the compute-node ports facing
// each edge node's compute-facing bond, where a shard redirects an
// un-translated reply back toward the tenant's node and edge_lb redirects a
// client's packet toward its backend. See deploy:lab-xdp-passthrough and
// deploy:lab-xdp-passthrough-compute for the exact lists. Not applied
// anywhere else in this topology: usid_ingress/usid_egress (usid.c) are
// TC-BPF, not XDP, so ordinary tenant traffic never needed this.
//
// Built by deploy/containerlab/Taskfile.yaml's build:lab-xdp-passthrough
// task (clang -target bpf); not go:generate'd or wrapped in bpf2go
// bindings like every other program in this repo, since nothing ever
// needs to read a map from it or drive it from Go -- it is loaded purely
// via `ip link set ... xdp obj ... sec xdp`, the same as this Taskfile's
// own deploy:lab-xdp-passthrough task does. The compiled .o is gitignored,
// matching this repo's established convention of never committing eBPF
// build output (see internal/plumbing/ebpf/prog/doc.go).

#define SEC(name) __attribute__((section(name), used))

// A local, minimal stand-in for struct xdp_md (from linux/bpf.h) -- not
// actually read by this program, but required so the function signature
// matches what the "xdp" program type expects.
struct xdp_md {
	unsigned int data;
	unsigned int data_end;
	unsigned int data_meta;
	unsigned int ingress_ifindex;
	unsigned int rx_queue_index;
	unsigned int egress_ifindex;
};

SEC("xdp")
int xdp_passthrough(struct xdp_md *ctx)
{
	(void) ctx;
	return 2; // XDP_PASS
}

char _license[] SEC("license") = "GPL";
