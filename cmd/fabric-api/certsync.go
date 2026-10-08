// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"time"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/fabric/identity"
)

func newCertSyncCommand() *cobra.Command {
	s := &identity.Sync{}
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "certsync",
		Short: "Copy this node's fabric-api certificate from a csi-driver volume to the node for the fabric-router sidecar",
		Long: `Runs in the fabric-api-certs pod on each fabric node. It copies the
certificate, key and trust bundle csi-driver issues into --source to the
node-local directory --dest, which the fabric-api sidecar in the
fabric-router pod mounts. The certificate is issued here rather than in the
fabric-router pod because a csi-driver volume blocks its pod until the
certificate is issued, and that must never hold FRR from starting.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signalContext(cmd.Context())
			defer stop()
			s.Run(ctx, interval)
			return nil
		},
	}
	cmd.Flags().StringVar(&s.Source, "source", "/var/run/fabric-api/csi", "Directory csi-driver writes the certificate to")
	cmd.Flags().StringVar(&s.Dest, "dest", "/var/run/fabric-api/node", "Node-local directory the sidecar reads")
	cmd.Flags().DurationVar(&interval, "interval", 10*time.Second, "Time between syncs")
	return cmd
}
