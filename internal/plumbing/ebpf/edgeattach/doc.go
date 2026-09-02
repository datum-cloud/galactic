// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgeattach loads internal/plumbing/ebpf/edgeprog's compiled XDP
// program and attaches it to the gateway node's public/underlay-facing
// uplink. Load mirrors internal/plumbing/ebpf/attach.Load's mechanics
// (pinned maps, verifier-error unwrapping, incompatible-map recreation on a
// schema change) almost verbatim, since none of that is
// attach-mechanism-specific; Attach itself is genuinely new, not a port of
// internal/plumbing/ebpf/gwattach's TC-BPF clsact+filter mechanics (the
// earlier, rejected Geneve-based design) -- XDP attaches via a kernel
// bpf_link (github.com/cilium/ebpf/link.AttachXDP), a different
// netlink/bpf-link surface than TC's netlink.BpfFilter entirely.
//
// The configured uplink (config.GatewayConfig.PublicInterface) is usually a
// single physical interface, in which case ResolveTargets/Attach have
// exactly one attach target, attached once at process startup. If it names
// a Linux bonding master instead, ResolveTargets expands it to that bond's
// slave interfaces and Attach attaches to every one of them -- native-mode
// XDP against a bonding master is not reliable (see ResolveTargets' own
// doc comment for the confirmed failure and why it's not simply "bonding
// never implements ndo_bpf"), unlike internal/plumbing/ebpf/attach's
// TC-BPF path, which attaches to both the master and its slaves. Either
// way there is no
// Watch-style netlink-driven re-attachment here: the attach target set is
// resolved once at process startup and never revisited -- there is no
// external network event (a Geneve device appearing, a NIC renumbering, a
// bond's active slave changing) this package needs to notice on its own,
// unlike internal/plumbing/ebpf/attach's SRv6 underlay-facing interface
// set.
//
// Native XDP support is required, not merely preferred: Attach always
// requests link.XDPDriverMode and returns an error rather than silently
// retrying in link.XDPGenericMode (SKB mode) if the interface's driver
// doesn't support it. Generic mode has materially different performance
// characteristics -- accepting it silently would defeat the reason this
// design chose XDP over TC-BPF in the first place, and violates the same
// "no partial/unsafe fallback" invariant
// internal/plumbing/ebpf/preflight/edgepreflight already hold the rest of
// this datapath to.
//
// Unlike a TC-BPF filter (which persists in the kernel's qdisc structure
// independent of any process holding a reference), an unpinned bpf_link
// detaches automatically when the last file descriptor referencing it is
// closed. This package does not pin the returned links: the owning process
// (galactic-gateway) is expected to hold every one of them open for its own
// lifetime and Close each on shutdown, the same "keep the fd, don't pin"
// simplification gwattach's own AttachPublic used for its single fixed
// interface. A process restart therefore has a genuinely clean slate -- no
// existing attach to conflict with -- so there is no TC-FilterReplace-style
// "replace what's already there" case to handle.
package edgeattach
