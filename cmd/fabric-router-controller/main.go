// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fabric-router-controller compiles fabric routers' typed BGP
// resources into FRR configuration. run is the in-cluster controller that
// turns every fabric-class router into immutable FabricRouterRevisions. The
// offline subcommands contact no cluster: import turns a rendered frr.conf
// into typed resources, preview compiles resources, or a stored revision,
// into the frr.conf a router would run, and diff compares that with a configuration FRR runs
// today.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	_ "golang.org/x/crypto/x509roots/fallback"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
	"go.datum.net/galactic/internal/fabric/routing/revision"
	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
)

const appName = "fabric-router-controller"

func main() {
	if err := newRootCommand().ExecuteContext(ctrl.SetupSignalHandler()); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var logOpts logging.Options
	cmd := &cobra.Command{
		Use:          appName,
		Short:        "Compile fabric routers' typed BGP resources into FRR configuration",
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return logOpts.Setup()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				return nil
			}
			return cmd.Help()
		},
	}
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	cmd.AddCommand(newImportCommand(), newPreviewCommand(), newDiffCommand(), newRunCommand())
	cmd.AddCommand(newOpsCommands()...)
	logOpts.BindFlags(cmd.PersistentFlags())
	return cmd
}

func newImportCommand() *cobra.Command {
	var opts frrimport.Options
	var className string
	cmd := &cobra.Command{
		Use:   "import FRR_CONF",
		Short: "Write the typed resources that compile back to a rendered frr.conf",
		Long: `Reads one router's rendered frr.conf and writes, as a YAML stream, the
BGPRouterClass, FRRRouterParameters, BGPRouter and every peer, profile,
policy, list, set, advertisement and static route that compiles back to it.
Any line outside the fabric conformance matrix is an error, never dropped.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			if opts.NodeName == "" {
				opts.NodeName = strings.TrimSuffix(filepath.Base(args[0]), filepath.Ext(args[0]))
			}
			opts.RouterClassName = className
			objs, err := frrimport.Import(f, opts)
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			return bundle.FromImport(objs, className).Write(cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.NodeName, "node", "",
		"Node the router runs on (default: the file name without its extension)")
	cmd.Flags().StringVar(&opts.Namespace, "namespace", "galactic-system", "Namespace of the namespaced resources")
	cmd.Flags().StringVar(&className, "class", "fabric-frr", "BGPRouterClass and FRRRouterParameters name")
	return cmd
}

func newPreviewCommand() *cobra.Command {
	var router, revisionFile string
	cmd := &cobra.Command{
		Use:   "preview RESOURCES_YAML --router ROUTER | preview --revision REVISION_YAML",
		Short: "Print the frr.conf a router's typed resources, or a stored revision, compile to",
		Long: `With --router, compiles the named router from RESOURCES_YAML. With
--revision, recompiles a FabricRouterRevision as kubectl get -o yaml writes
it, and prints its frr.conf only when that matches the digests the revision
records.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res compile.Result
			var err error
			switch {
			case revisionFile != "" && (router != "" || len(args) > 0):
				return errors.New("--revision takes no RESOURCES_YAML or --router")
			case revisionFile != "":
				res, err = compileRevisionFile(revisionFile)
			case router == "" || len(args) != 1:
				return errors.New("name RESOURCES_YAML and --router, or --revision")
			default:
				res, err = compileFile(args[0], router)
			}
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), res.Config)
			return err
		},
	}
	cmd.Flags().StringVar(&router, "router", "", "BGPRouter to compile from RESOURCES_YAML")
	cmd.Flags().StringVar(&revisionFile, "revision", "", "FabricRouterRevision manifest to recompile and verify")
	return cmd
}

// compileRevisionFile reads one FabricRouterRevision from path and
// recompiles it, failing unless the result matches its recorded digests.
func compileRevisionFile(path string) (compile.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return compile.Result{}, err
	}
	rev := &networkv1alpha1.FabricRouterRevision{}
	if err := yaml.Unmarshal(data, rev); err != nil {
		return compile.Result{}, fmt.Errorf("%s: %w", path, err)
	}
	if rev.Kind != "FabricRouterRevision" {
		return compile.Result{}, fmt.Errorf("%s: kind %q, not FabricRouterRevision", path, rev.Kind)
	}
	return revision.Verify(rev)
}

func newDiffCommand() *cobra.Command {
	var router string
	cmd := &cobra.Command{
		Use:   "diff RESOURCES_YAML FRR_CONF",
		Short: "Show what compiling a router's resources would change in a running frr.conf",
		Long: `Compiles the router and compares the result with FRR_CONF by context,
ignoring comments, order and prefix spelling, and applying the pinned
FRR's display rules. It approximates FRR's own reload comparison; the
frr-tagged parity test is the authoritative check. Lines prefixed - are in
FRR_CONF only, lines prefixed + in the compiled configuration only. Exits
non-zero when they differ.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := compileFile(args[0], router)
			if err != nil {
				return err
			}
			running, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			diff := frrtext.Diff(frrtext.Normalize(string(running)), frrtext.Normalize(res.Config))
			for _, line := range diff {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), line); err != nil {
					return err
				}
			}
			if len(diff) > 0 {
				return fmt.Errorf("%d lines differ", len(diff))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&router, "router", "", "BGPRouter to compile (required)")
	_ = cmd.MarkFlagRequired("router")
	return cmd
}

func compileFile(path, router string) (compile.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return compile.Result{}, err
	}
	defer func() { _ = f.Close() }()
	b, err := bundle.Read(f)
	if err != nil {
		return compile.Result{}, fmt.Errorf("%s: %w", path, err)
	}
	in, err := b.Input(router)
	if err != nil {
		return compile.Result{}, err
	}
	return compile.Compile(in)
}
