// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	appName = "galactic-usid"

	appDesc = `Galactic uSID Codec

 Converts Galactic VPC/VPCAttachment identifiers between the hex form used
 in BGP artifacts (BGPAdvertisement, EVPN paths) and the base62 form used
 in kernel interface names and SRv6 uSID addresses. Ships in the
 galactic-debug image for decoding identifiers by hand during an
 incident, rather than reimplementing internal/plumbing/intf's conversion
 in your head.

 Find more information at: https://www.datum.net/docs`
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		// --build-info/--version are handled in PersistentPreRunE, which
		// cobra only invokes on a command that actually runs; an empty
		// RunE is what makes that happen for the bare root command
		// (otherwise cobra shows help without ever calling it).
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.PersistentFlags().Bool("build-info", false, "Print build information and exit")
	cmd.PersistentFlags().BoolP("version", "V", false, "Print version and exit")
	cmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if ok, _ := cmd.Flags().GetBool("build-info"); ok {
			fmt.Println(metadata.BuildInfo(appName))
			os.Exit(0)
		}
		if ok, _ := cmd.Flags().GetBool("version"); ok {
			fmt.Printf("%s version %s\n", appName, metadata.Version)
			os.Exit(0)
		}
		return nil
	}

	cmd.AddCommand(newEncodeCommand(), newDecodeCommand())
	return cmd
}

func newEncodeCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "encode <hex>",
		Aliases: []string{"hex-to-base62"},
		Short:   "Convert a hex identifier to its base62 form",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			out, err := intf.HexToBase62(args[0])
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		},
	}
}

func newDecodeCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "decode <base62>",
		Aliases: []string{"base62-to-hex"},
		Short:   "Convert a base62 identifier to its hex form",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			out, err := intf.Base62ToHex(args[0])
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		},
	}
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
