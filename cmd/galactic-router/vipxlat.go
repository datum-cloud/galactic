// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
)

// vipXlatTable is the part of *vipxlatmap.VipXlatTable the xlat subcommands
// use, so tests can run them against a fake.
type vipXlatTable interface {
	List() ([]vipxlatmap.Entry, error)
	UnregisterBinding(proto uint8, vipAddr net.IP, vipPort uint16,
		backendAddr net.IP, backendPort uint16) ([]vipxlatmap.Entry, error)
}

// openVipXlatTable opens this node's pinned vip_xlat_table. Tests replace it.
var openVipXlatTable = func(pinDir string) (vipXlatTable, io.Closer, error) {
	return vipxlatmap.OpenPinnedVipXlatTable(pinDir)
}

// newVIPXlatCommand builds the "vip xlat" subcommand group: a manual surface
// over this node's vip_xlat_table, for finding and removing rows a
// ServiceVIPBinding left behind, such as after its finalizer was cleared by
// hand.
func newVIPXlatCommand() *cobra.Command {
	var pinDir string
	cmd := &cobra.Command{
		Use:   "xlat",
		Short: "List or remove this node's vip_xlat_table rows",
		Long: `xlat reads and edits the vip_xlat_table eBPF map pinned on this node, the
same map ServiceVIPBindingReconciler registers each binding's two rows in. It
does not touch Kubernetes. Run it in this node's galactic-router pod.`,
	}
	cmd.PersistentFlags().StringVar(&pinDir, "pin-dir", attach.PinDir,
		"bpffs directory the uSID datapath's maps are pinned under")
	cmd.AddCommand(newVIPXlatListCommand(&pinDir), newVIPXlatRemoveCommand(&pinDir))
	return cmd
}

func newVIPXlatListCommand(pinDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Print every vip_xlat_table row",
		Long: `list prints every vip_xlat_table row. An ingress row is keyed on the VIP
and its port and rewrites to the backend. An egress row is keyed on the backend
and its port and rewrites to the VIP.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			table, closer, err := openVipXlatTable(*pinDir)
			if err != nil {
				return err
			}
			defer closer.Close() //nolint:errcheck // read-only use of our own fd

			entries, err := table.List()
			if err != nil {
				return err
			}
			return writeVipXlatEntries(cmd.OutOrStdout(), entries)
		},
	}
}

func newVIPXlatRemoveCommand(pinDir *string) *cobra.Command {
	var (
		protocol    string
		vipAddr     string
		vipPort     uint16
		backendAddr string
		backendPort uint16
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the rows one ServiceVIPBinding wrote",
		Long: `remove deletes the two vip_xlat_table rows a ServiceVIPBinding with these
spec values wrote, under whatever VRF they were written, and prints them. A row
is removed only while it still rewrites to these values. One another binding
has since written its own values to is left alone.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			proto, err := parseXlatProtocol(protocol)
			if err != nil {
				return err
			}
			vip, err := parseVIPAddr(vipAddr)
			if err != nil {
				return fmt.Errorf("--vip: %w", err)
			}
			backend, err := parseVIPAddr(backendAddr)
			if err != nil {
				return fmt.Errorf("--backend: %w", err)
			}
			if vipPort == 0 || backendPort == 0 {
				return errors.New("--port and --backend-port must be 1-65535")
			}

			table, closer, err := openVipXlatTable(*pinDir)
			if err != nil {
				return err
			}
			defer closer.Close() //nolint:errcheck // our own fd; the pinned map outlives it

			removed, err := table.UnregisterBinding(proto, vip, vipPort, backend, backendPort)
			if len(removed) > 0 {
				if werr := writeVipXlatEntries(cmd.OutOrStdout(), removed); werr != nil {
					err = errors.Join(err, werr)
				}
			} else if err == nil {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no matching rows")
			}
			return err
		},
	}
	cmd.Flags().StringVar(&protocol, xlatFlagProtocol, "", "binding protocol, tcp or udp")
	cmd.Flags().StringVar(&vipAddr, xlatFlagVIP, "", "binding spec.vipAddress")
	cmd.Flags().Uint16Var(&vipPort, xlatFlagPort, 0, "binding spec.port")
	cmd.Flags().StringVar(&backendAddr, xlatFlagBackend, "", "binding spec.backendAddress")
	cmd.Flags().Uint16Var(&backendPort, xlatFlagBackendPort, 0, "binding spec.backendPort")
	for _, name := range []string{xlatFlagProtocol, xlatFlagVIP, xlatFlagPort, xlatFlagBackend, xlatFlagBackendPort} {
		_ = cmd.MarkFlagRequired(name) // only fails for an undefined flag name
	}
	return cmd
}

// The protocol names the xlat subcommands accept and print.
const (
	xlatProtocolTCP = "tcp"
	xlatProtocolUDP = "udp"
)

// The remove subcommand's flag names.
const (
	xlatFlagProtocol    = "protocol"
	xlatFlagVIP         = "vip"
	xlatFlagPort        = "port"
	xlatFlagBackend     = "backend"
	xlatFlagBackendPort = "backend-port"
)

// parseXlatProtocol maps a ServiceVIPBinding protocol name to the IANA number
// vip_xlat_table keys on.
func parseXlatProtocol(protocol string) (uint8, error) {
	switch strings.ToLower(protocol) {
	case xlatProtocolTCP:
		return vipxlatmap.ProtoTCP, nil
	case xlatProtocolUDP:
		return vipxlatmap.ProtoUDP, nil
	default:
		return 0, fmt.Errorf("--protocol %q: must be tcp or udp", protocol)
	}
}

// writeVipXlatEntries prints entries as an aligned table.
func writeVipXlatEntries(w io.Writer, entries []vipxlatmap.Entry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "DIRECTION\tBLOCK\tARGUMENT\tPROTO\tMATCH\tREWRITE"); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := fmt.Fprintf(tw, "%s\t%#x\t%d\t%s\t%s\t%s\n",
			e.Direction, e.Block, e.Argument, xlatProtocolName(e.Proto),
			netip.AddrPortFrom(e.Addr, e.Port),
			net.JoinHostPort(e.RewriteAddr.String(), strconv.Itoa(int(e.RewritePort)))); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// xlatProtocolName is parseXlatProtocol's inverse, falling back to the number.
func xlatProtocolName(proto uint8) string {
	switch proto {
	case vipxlatmap.ProtoTCP:
		return xlatProtocolTCP
	case vipxlatmap.ProtoUDP:
		return xlatProtocolUDP
	default:
		return strconv.Itoa(int(proto))
	}
}
