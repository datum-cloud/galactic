// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fabric-router-controller compiles fabric routers' typed BGP
// resources into FRR configuration. This build carries the offline
// subcommands: import turns a rendered frr.conf into typed resources,
// preview compiles resources into the frr.conf a router would run, and diff
// compares that with a configuration FRR runs today. None of them contact a
// cluster.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
	"go.datum.net/galactic/internal/metadata"
)

const appName = "fabric-router-controller"

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          appName,
		Short:        "Compile fabric routers' typed BGP resources into FRR configuration",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				return nil
			}
			return cmd.Help()
		},
	}
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	cmd.AddCommand(newImportCommand(), newPreviewCommand(), newDiffCommand())
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
	var router string
	cmd := &cobra.Command{
		Use:   "preview RESOURCES_YAML",
		Short: "Print the frr.conf a router's typed resources compile to",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := compileFile(args[0], router)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), res.Config)
			return err
		},
	}
	cmd.Flags().StringVar(&router, "router", "", "BGPRouter to compile (required)")
	_ = cmd.MarkFlagRequired("router")
	return cmd
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
