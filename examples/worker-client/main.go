// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command worker-client is an independent Galactic Worker client. It is
// built from the published Worker API alone
// (go.datum.net/galactic/api/galactic/worker/v1alpha1 and
// go.datum.net/galactic/pkg/workerclient) and drives one claim through the
// documented interface.
//
// Subcommands:
//
//	capabilities   print GetCapabilities as JSON
//	lifecycle      request, observe, update, observe and release one claim,
//	               and check that a forbidden capability is refused
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/datum-cloud/galactic/examples/worker-client/internal/lifecycle"
	"google.golang.org/protobuf/encoding/protojson"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

const usage = `usage: worker-client <capabilities|lifecycle> [flags]

Every subcommand takes --socket and --token-file. Run
"worker-client <subcommand> -h" for its flags.`

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func handoff(name string) (workerv1alpha1.Handoff, error) {
	if name == "" {
		return workerv1alpha1.Handoff_HANDOFF_UNSPECIFIED, nil
	}
	v, ok := workerv1alpha1.Handoff_value["HANDOFF_"+strings.ToUpper(name)]
	if !ok {
		return 0, fmt.Errorf("unknown handoff %q (tap, veth_pair, routed_link, socket)", name)
	}
	return workerv1alpha1.Handoff(v), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "worker-client:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	socket := fs.String("socket", workerv1alpha1.DefaultSocketPath, "Worker socket")
	tokenFile := fs.String("token-file", workerclient.DefaultTokenFile, "projected ServiceAccount token")
	timeout := fs.Duration("timeout", time.Minute, "overall deadline")
	var p lifecycle.Plan
	var node, vpc, attachment, hName, forbidden string
	var dests, updates list
	if cmd == "lifecycle" {
		fs.StringVar(&node, "node", "", "claim node")
		fs.StringVar(&vpc, "vpc", "", "claim VPC identifier")
		fs.StringVar(&attachment, "attachment", "", "claim attachment UID")
		fs.StringVar(&hName, "handoff", "veth_pair", "claim handoff")
		fs.StringVar(&forbidden, "forbidden-handoff", "", "a handoff this caller must be refused")
		fs.Var(&dests, "destination", "destination attachment UID for the request (repeatable)")
		fs.Var(&updates, "update-destination", "destination attachment UID for the update (repeatable)")
	} else if cmd != "capabilities" {
		return fmt.Errorf("unknown subcommand %q\n%s", cmd, usage)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	c, err := workerclient.Dial(ctx, workerclient.Options{SocketPath: *socket, TokenFile: *tokenFile})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = c.Close() }()

	if cmd == "capabilities" {
		b, err := protojson.Marshal(c.Capabilities())
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if p.Handoff, err = handoff(hName); err != nil {
		return err
	}
	if p.Forbidden, err = handoff(forbidden); err != nil {
		return err
	}
	if len(updates) == 0 {
		updates = dests
	}
	p.Key = &workerv1alpha1.ClaimKey{Node: node, Vpc: vpc, AttachmentUid: attachment}
	p.Destinations, p.UpdateDestinations = dests, updates
	if err := lifecycle.Run(ctx, c, p, func(f string, a ...any) { fmt.Printf(f+"\n", a...) }); err != nil {
		return err
	}
	fmt.Println("lifecycle passed")
	return nil
}
