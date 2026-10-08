// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
	"go.datum.net/galactic/internal/fabric/gateway"
)

func newJanitorCommand() *cobra.Command {
	var retention, grace, interval time.Duration
	cmd := &cobra.Command{
		Use:   "janitor",
		Short: "Delete expired FabricQuery copies the federation failed to delete",
		Long: `Deletes FabricQuery objects in every namespace whose expiration or
completion, whichever is later, is more than --retention plus --grace in the
past. With --interval 0 it sweeps once and exits (for a CronJob).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signalContext(cmd.Context())
			defer stop()
			scheme := runtime.NewScheme()
			utilruntime.Must(fabricapi.AddToScheme(scheme))
			c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
			if err != nil {
				return fmt.Errorf("create client: %w", err)
			}
			j := &gateway.Janitor{Client: c, Retention: retention, Grace: grace}
			if interval <= 0 {
				n, err := j.Sweep(ctx)
				slog.Info("fabric query sweep done", "deleted", n)
				return err
			}
			j.Run(ctx, interval)
			return nil
		},
	}
	cmd.Flags().DurationVar(&retention, "retention", gateway.DefaultRetention, "How long a finished query is kept")
	cmd.Flags().DurationVar(&grace, "grace", gateway.DefaultCleanupGrace,
		"How long past retention to wait for the federation to delete a query")
	cmd.Flags().DurationVar(&interval, "interval", 0, "Time between sweeps; 0 sweeps once")
	return cmd
}
