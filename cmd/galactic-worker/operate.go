// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/diag"
	"go.datum.net/galactic/internal/worker/handback"
	"go.datum.net/galactic/internal/worker/local"
	"go.datum.net/galactic/internal/worker/store"
)

// newInspectCommand prints the node's Worker status: capability readiness,
// each VPC scope's owner and generation, and each claim's destinations with
// their locality, readiness and reason. Run it in the Worker pod with
// kubectl exec; it reads files only and changes nothing.
func newInspectCommand() *cobra.Command {
	var statusFile, ownershipDir, output string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Print this node's Worker status: capabilities, VPC scopes, claims and destinations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := diag.Read(statusFile)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			var fence *ownership.Authority
			if f, err := ownership.Open(ownershipDir); err == nil {
				fence = f
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			s, err = diag.Join(s, fence)
			if err != nil {
				return err
			}
			switch output {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			case "text":
				return diag.Print(cmd.OutOrStdout(), s, time.Now())
			default:
				return fmt.Errorf("--output must be text or json, not %q", output)
			}
		},
	}
	f := cmd.Flags()
	f.StringVar(&statusFile, "status-file", diag.DefaultPath, "Worker's status snapshot")
	f.StringVar(&ownershipDir, "ownership-dir", ownership.DefaultDir, "Ownership fence directory")
	f.StringVarP(&output, "output", "o", "text", "text or json")
	return cmd
}

// newHandbackCommand returns the VPC scopes a stopped Worker owned on this
// node to the writers it took them from (docs/worker/operations.md).
func newHandbackCommand() *cobra.Command {
	var (
		nodeName, ownershipDir, socket, stateDir, statusFile string
		pinDir, localPinDir, dispatchDir, procRoot           string
	)
	cmd := &cobra.Command{
		Use:   "handback",
		Short: "Hand the VPC scopes a stopped Worker owned back to the node's other writers",
		Long: `Hand the VPC scopes a stopped Worker owned back to the node's other writers.

Run it on the node after the Worker pod is gone; it refuses while a Worker
answers on the socket. For each Worker-owned scope it leaves a handback
label as the owner, with a resync pending, and removes the handoff links,
filters and pass-through entries Worker's Local module wrote. It leaves the
tenant routes Worker's Fabric module wrote: restart galactic-router on the
node afterwards so it writes them again. Repeating it is safe.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if nodeName == "" {
				nodeName = os.Getenv(envNodeName)
			}
			fence, err := ownership.Open(ownershipDir)
			if errors.Is(err, os.ErrNotExist) {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No ownership fence on this node: nothing to hand back.")
				return nil
			}
			if err != nil {
				return err
			}
			cfg := handback.Config{Fence: fence, Socket: socket, ClaimsDir: stateDir, Remove: []string{statusFile},
				Log: slog.Default()}
			// Loading the Local programs pins their maps, so Local state is
			// removed only where Local ran and left its pins.
			if _, err := os.Stat(localPinDir); err == nil {
				if nodeName == "" {
					return fmt.Errorf("--node-name (or %s) is required to remove Local state", envNodeName)
				}
				pods := &local.ProcPods{ProcRoot: procRoot, Pods: auth.CgroupPodResolver{ProcRoot: procRoot}}
				k := &local.Kernel{PinDir: pinDir, LocalPinDir: localPinDir, DispatchDir: dispatchDir, Pods: pods}
				defer func() { _ = k.Close() }()
				m, err := local.New(local.Config{Kernel: k, Node: nodeName, Log: slog.Default()})
				if err != nil {
					return err
				}
				cfg.Local = m
				cfg.RemoveAll = []string{localPinDir}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			res, err := handback.Run(cmd.Context(), cfg)
			for _, s := range res.HandedBack {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "handed back %s as %s\n", s, res.Owner)
			}
			for _, s := range res.Released {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed Local state of %s\n", s)
			}
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Done: %d scopes handed back. Restart galactic-router on this node next.\n",
				len(res.HandedBack))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&nodeName, "node-name", "", "This node's name (env "+envNodeName+")")
	f.StringVar(&ownershipDir, "ownership-dir", ownership.DefaultDir, "Ownership fence directory")
	f.StringVar(&socket, "socket", workerv1alpha1.DefaultSocketPath, "Worker API socket")
	f.StringVar(&stateDir, "state-dir", store.DefaultDir, "Worker's durable desired state, emptied at the end")
	f.StringVar(&statusFile, "status-file", diag.DefaultPath, "Worker's status snapshot, removed at the end")
	f.StringVar(&pinDir, "pin-dir", attach.PinDir, "bpffs directory of the pinned uSID maps")
	f.StringVar(&localPinDir, "local-pin-dir", localprog.PinDir, "bpffs directory of the Local handoff maps")
	f.StringVar(&dispatchDir, "xdp-dispatch-dir", xdpdispatch.PinDir, "bpffs directory of the shared XDP dispatcher")
	f.StringVar(&procRoot, "proc-root", "/proc", "The host's /proc")
	return cmd
}
