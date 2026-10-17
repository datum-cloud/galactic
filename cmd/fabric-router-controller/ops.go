// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/ops"
)

// opsClient connects to the cluster the current kubeconfig names.
func opsClient() (client.Client, error) {
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes client configuration: %w", err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{Scheme: scheme})
}

// newOpsCommands returns the operator workflows. Each writes only the API
// objects the rollout manager and node agents act on.
func newOpsCommands() []*cobra.Command {
	var namespace string
	withNamespace := func(cmd *cobra.Command) *cobra.Command {
		cmd.Flags().StringVarP(&namespace, "namespace", "n", "galactic-system", "Namespace of the fabric routers")
		return cmd
	}
	status := withNamespace(&cobra.Command{
		Use:   "status",
		Short: "Show every fabric router's source, active and applied revision, candidate and problems",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.FleetStatus(cmd.Context(), c, namespace, time.Now(), cmd.OutOrStdout())
		},
	})
	source := withNamespace(&cobra.Command{
		Use:   "source DEPLOYMENT ConfigMap|Shadow|CRD",
		Short: "Move a fabric router's configuration source",
		Long: `Moves a deployment to another configuration source. On Shadow the agent
validates and diffs the candidate revision; on CRD it activates releases.
Leaving CRD goes only to ConfigMap, and names the node's ConfigMap as it is
now, which the agent checks before handing the node back.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.SetSource(cmd.Context(), c, namespace, args[0], networkv1alpha1.FabricConfigSource(args[1]))
		},
	})
	suspend := withNamespace(&cobra.Command{
		Use:   "suspend DEPLOYMENT",
		Short: "Stop promoting revisions to a fabric router; it keeps running what it runs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.SetSuspended(cmd.Context(), c, namespace, args[0], true)
		},
	})
	resume := withNamespace(&cobra.Command{
		Use:   "resume DEPLOYMENT",
		Short: "Allow promoting revisions to a suspended fabric router again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.SetSuspended(cmd.Context(), c, namespace, args[0], false)
		},
	})
	var fromUID, by, method string
	rebind := withNamespace(&cobra.Command{
		Use:   "rebind DEPLOYMENT --from-uid UID --by WHO",
		Short: "Let a recreated or restored deployment take over its node's activation journal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.Rebind(cmd.Context(), c, namespace, args[0], fromUID, by, time.Now())
		},
	})
	rebind.Flags().StringVar(&fromUID, "from-uid", "",
		"Deployment UID the node's journal is bound to (its RecoveryConflict condition names it)")
	rebind.Flags().StringVar(&by, "by", "", "Who confirmed the old deployment is gone")
	move := withNamespace(&cobra.Command{
		Use:   "move DEPLOYMENT NODE --fenced-by WHO --method HOW",
		Short: "Retarget a fabric router to another node once the node it leaves is fenced",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.Move(cmd.Context(), c, namespace, args[0], args[1], method, by, time.Now())
		},
	})
	move.Flags().StringVar(&by, "fenced-by", "", "Who confirmed the old node is cut off from the fabric")
	move.Flags().StringVar(&method, "method", "", "How it was fenced, such as a switch port shutdown")
	return []*cobra.Command{status, newReleaseCommand(), source, suspend, resume, rebind, move}
}

func newReleaseCommand() *cobra.Command {
	var namespace string
	cmd := &cobra.Command{
		Use:   "release",
		Short: "Create and follow release authorizations",
	}
	cmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "galactic-system", "Namespace of the fabric routers")

	var spec ops.ReleaseSpec
	var dryRun bool
	create := &cobra.Command{
		Use:   "create NAME --domain DOMAIN --sequence N [DEPLOYMENT...]",
		Short: "Authorize promoting the named deployments, or every changed one, to their candidate revisions",
		Long: `Creates a FabricReleaseAuthorization naming each deployment, by name and
UID, and its current candidate revision and digest. Without deployment
names it takes every deployment on the CRD source, not suspended, whose
candidate differs from what it runs. --withdraw makes it an emergency
withdrawal of those prefixes, which may start while a release is
outstanding. --retire decommissions the routers with this promotion.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			spec.Namespace, spec.Name, spec.Deployments = namespace, args[0], args[1:]
			auth, err := ops.BuildRelease(cmd.Context(), c, spec, time.Now())
			if err != nil {
				return err
			}
			if dryRun {
				out, err := yaml.Marshal(auth)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(out)
				return err
			}
			if err := c.Create(cmd.Context(), auth); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "release %s created for %d routers\n", auth.Name,
				len(auth.Spec.Deployments))
			return err
		},
	}
	create.Flags().StringVar(&spec.RoutingDomain, "domain", "", "Routing domain the release belongs to (required)")
	create.Flags().Int64Var(&spec.FleetSequence, "sequence", 0,
		"Fleet sequence, higher than every earlier release in the domain (required)")
	create.Flags().StringVar(&spec.FleetReleaseID, "fleet-release", "",
		"Release ID shared across cells (default: NAME)")
	create.Flags().StringSliceVar(&spec.Withdraw, "withdraw", nil, "Make it an emergency withdrawal of these prefixes")
	create.Flags().BoolVar(&spec.Retire, "retire", false, "Decommission the routers with this promotion")
	create.Flags().DurationVar(&spec.StartWithin, "start-within", 0,
		"Cancel the release if it cannot start within this long")
	create.Flags().BoolVar(&dryRun, "dry-run", false, "Print the release instead of creating it")
	_ = create.MarkFlagRequired("domain")
	_ = create.MarkFlagRequired("sequence")

	show := &cobra.Command{
		Use:   "status NAME",
		Short: "Show a release's phase and where each router stands",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.ReleaseStatus(cmd.Context(), c, namespace, args[0], cmd.OutOrStdout())
		},
	}
	var by string
	confirm := &cobra.Command{
		Use:   "confirm-recovery NAME --by WHO",
		Short: "Release a failed release's routing domain once an operator confirmed its routers are safe",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opsClient()
			if err != nil {
				return err
			}
			return ops.ConfirmRecovery(cmd.Context(), c, namespace, args[0], by)
		},
	}
	confirm.Flags().StringVar(&by, "by", "", "Who confirmed the routers are safe (required)")
	_ = confirm.MarkFlagRequired("by")
	cmd.AddCommand(create, show, confirm)
	return cmd
}
