// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgemap implements the read/write API that populates
// internal/plumbing/ebpf/edgeprog's control-plane maps -- rule_table and
// gw_config_table. conn_table is not wrapped here: it is written and read
// exclusively by the compiled program itself (edgenat.c's forward branch
// writes it, the return branch reads it); nothing in the Go control plane
// ever touches it directly, the same boundary the earlier, rejected
// gwprog/gwnatmap design drew for its own conn_table.
//
// This package does not itself decide *when* to register anything, load
// the program, or attach it to an interface -- that is
// internal/gateway.Engine's job (via its Datapath interface) and
// internal/plumbing/ebpf/edgeattach's, analogous to
// internal/plumbing/ebpf/attach but for this program.
//
// # Why RuleTable carries a Generation field
//
// internal/gateway.Engine is a single long-lived process, but it can still
// crash mid-reconcile and leave rule_table entries behind with no
// corresponding NetworkRule left to reconcile them against.
// RuleTable.Reconcile's cutoff/Generation mechanism guards exactly that
// crash-restart window -- the same register-after-snapshot-is-safe
// guarantee internal/plumbing/ebpf/usidmap.VRFTable's identical mechanism
// already documents.
//
// # Testability
//
// RuleTable is built against the Table interface (table.go), not directly
// against *ebpf.Map -- KernelTable adapts a real, loaded map (e.g.
// edgeprog.EdgenatObjects.RuleTable) for production use, while this
// package's own tests substitute an in-memory fake implementation to
// exercise register/unregister/reconcile logic without a kernel or root
// privileges. Table/Iterator/KernelTable are a deliberate duplicate of
// usidmap's identical types, not an import of them -- this package and
// usidmap serve two unrelated datapaths (edge ingress NAT/LB vs. SRv6 uSID
// decap) with no shared map/key layout, so importing usidmap would gain
// nothing but coupling.
package edgemap
