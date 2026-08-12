// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgeattach loads internal/plumbing/ebpf/edgeprog's compiled XDP
// program and attaches it to one interface -- the gateway node's single
// public/underlay-facing uplink. Load mirrors
// internal/plumbing/ebpf/attach.Load's mechanics (pinned maps, verifier-
// error unwrapping, incompatible-map recreation on a schema change) almost
// verbatim, since none of that is attach-mechanism-specific; Attach itself
// is genuinely new, not a port of internal/plumbing/ebpf/gwattach's TC-BPF
// clsact+filter mechanics (the earlier, rejected Geneve-based design) --
// XDP attaches via a kernel bpf_link (github.com/cilium/ebpf/link.
// AttachXDP), a different netlink/bpf-link surface than TC's
// netlink.BpfFilter entirely.
//
// Like gwattach before it, there is no Watch-style netlink-driven
// re-attachment here: this program has exactly one attach target (a
// fixed, operator-configured interface name,
// config.GatewayConfig.PublicInterface), attached once at process startup
// -- there is no external network event (a Geneve device appearing, a NIC
// renumbering) this package would ever need to notice on its own, unlike
// internal/plumbing/ebpf/attach's SRv6 underlay-facing interface set.
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
// closed. This package does not pin the returned link: the owning process
// (galactic-gateway) is expected to hold it open for its own lifetime and
// Close it on shutdown, the same "keep the fd, don't pin" simplification
// gwattach's own AttachPublic used for its single fixed interface. A
// process restart therefore has a genuinely clean slate -- no existing
// attach to conflict with -- so there is no TC-FilterReplace-style
// "replace what's already there" case to handle.
package edgeattach
