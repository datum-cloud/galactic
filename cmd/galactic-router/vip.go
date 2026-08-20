// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/plumbing/vip"
)

// newVIPCommand builds the "vip" subcommand group: a thin, manual/debug
// surface directly over internal/plumbing/vip's Bind/Unbind/Verify --
// the same veth-branch mechanism ServiceVIPBindingReconciler
// (internal/controller/servicevipbinding_controller.go) drives for every
// EgressKindVeth ServiceVIPBinding. This is the first subcommand group
// galactic-router's root command has ever had (see cmd/galactic-cni/main.go
// for the established pattern this mirrors); the root command's own RunE
// (root.go) still runs the router daemon itself when no subcommand is
// given, unaffected by this addition.
func newVIPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vip",
		Short: "Manually bind, unbind, or verify a service VIP on this node's galactic-vip0 interface",
		Long: `vip is a manual/debug surface directly over internal/plumbing/vip -- the
same mechanism ServiceVIPBindingReconciler drives automatically for every
EgressKindVeth ServiceVIPBinding. It does not touch Kubernetes at all: it
only manipulates this node's own galactic-vip0 dummy interface.`,
	}
	cmd.AddCommand(newVIPBindCommand(), newVIPUnbindCommand(), newVIPVerifyCommand())
	return cmd
}

// parseVIPAddr parses addr as an IP address, returning a clear,
// actionable error (rather than a nil net.IP silently propagating) if it
// isn't one.
func parseVIPAddr(addr string) (net.IP, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", addr)
	}
	return ip, nil
}

func newVIPBindCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "bind <addr>",
		Short: "Idempotently assign addr to galactic-vip0",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			addr, err := parseVIPAddr(args[0])
			if err != nil {
				return err
			}
			return vip.Bind(addr)
		},
	}
}

func newVIPUnbindCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "unbind <addr>",
		Short: "Idempotently remove addr from galactic-vip0",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			addr, err := parseVIPAddr(args[0])
			if err != nil {
				return err
			}
			return vip.Unbind(addr)
		},
	}
}

func newVIPVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <addr>",
		Short: "Confirm addr is live on galactic-vip0 (present and resolvable as a local route)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := parseVIPAddr(args[0])
			if err != nil {
				return err
			}
			if err := vip.Verify(addr); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s is live on %s\n", addr, vip.InterfaceName)
			return err
		},
	}
}
