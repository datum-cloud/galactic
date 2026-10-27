// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command looking-glass-client is an independent Looking Glass service
// client. It is built from the published service API alone
// (go.datum.net/galactic/api/fabric/service/v1 and api/fabric/v1), calls a
// cell's fabric-api gateway as an authorized service, and checks every
// stream against the contract's grammar and coverage rules.
//
// Subcommands:
//
//	capabilities   print GetCapabilities as JSON
//	run            run one diagnostic; print its record as JSON
//	load           run a workload from a JSON spec; print one record per
//	               attempt as JSON lines, then one summary line per group
//	invoke         call any unary method with an empty request and print its
//	               status, to show a method is closed to the service
//
// Records hold statuses, coverage and timings, never diagnostic payloads;
// run --events prints the events themselves to stderr.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/conn"
	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/load"
	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/rpcerr"
	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/run"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
)

const usage = `usage: looking-glass-client <capabilities|run|load|invoke> [flags]

Every subcommand takes --addr, --cell, --cert, --key and --ca. Run
"looking-glass-client <subcommand> -h" for its flags.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "capabilities":
		err = capabilities(ctx, os.Args[2:])
	case "run":
		err = runOne(ctx, os.Args[2:])
	case "load":
		err = runLoad(ctx, os.Args[2:])
	case "invoke":
		err = invoke(ctx, os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "looking-glass-client:", err)
		os.Exit(1)
	}
}

func connFlags(fs *flag.FlagSet) *conn.Options {
	o := &conn.Options{}
	fs.StringVar(&o.Addr, "addr", "", "gateway address, host:port")
	fs.StringVar(&o.Cell, "cell", "", "the cell of the gateway and of the service identity")
	fs.StringVar(&o.CertFile, "cert", "tls.crt", "the service's certificate (PEM); empty presents none")
	fs.StringVar(&o.KeyFile, "key", "tls.key", "the service's private key (PEM)")
	fs.StringVar(&o.CAFile, "ca", "ca.crt", "the cell's trust bundle (PEM)")
	return o
}

func check(o *conn.Options) error {
	if o.Addr == "" || o.Cell == "" {
		return errors.New("--addr and --cell are required")
	}
	return nil
}

// result is what capabilities and invoke print.
type result struct {
	Method       string          `json:"method,omitempty"`
	Status       rpcerr.Error    `json:"status"`
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(v)
}

func capabilities(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("capabilities", flag.ExitOnError)
	co := connFlags(fs)
	major := fs.Uint("api-major", 1, "api_major to request")
	_ = fs.Parse(args)
	if err := check(co); err != nil {
		return err
	}
	cc, err := conn.Dial(*co)
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := servicev1.NewLookingGlassServiceClient(cc).GetCapabilities(ctx,
		&servicev1.GetCapabilitiesRequest{Cell: co.Cell, ApiMajor: uint32(*major)})
	if err != nil {
		// A refusal is a result, not a client failure.
		return printJSON(result{Status: rpcerr.Decode(err)})
	}
	b, err := protojson.Marshal(resp)
	if err != nil {
		return err
	}
	return printJSON(result{Status: rpcerr.Decode(nil), Capabilities: b})
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, strings.Split(v, ",")...)
	return nil
}

func runOne(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	co := connFlags(fs)
	var o run.Options
	var nodes, features, md listFlag
	var expires, deadline, readDelay, cancelAfter time.Duration
	var major uint
	fs.StringVar(&o.Project, "project", "", "project UID the request is attributed to")
	fs.StringVar(&o.RequestID, "request-id", "", "request UUID; random when empty")
	fs.StringVar(&o.Query.Type, "type", "BGPSummary", "RouteLookup, BGPSummary, Ping or Traceroute")
	fs.StringVar(&o.Query.Target, "target", "", "the query's target address or prefix")
	fs.StringVar(&o.Query.Family, "family", "", "IPv4, IPv6, or empty to infer it from the target")
	fs.Var(&nodes, "nodes", "routers to select, by node name (repeatable or comma-separated)")
	fs.Var(&features, "require", "features the request requires (repeatable or comma-separated)")
	fs.Var(&md, "metadata", "request metadata as key=value (repeatable or comma-separated)")
	fs.UintVar(&major, "api-major", 1, "api_major to send")
	reqCell := fs.String("request-cell", "", "cell to name in the request; defaults to --cell")
	fs.DurationVar(&expires, "expires-in", 30*time.Second, "expires_at, from now")
	fs.DurationVar(&deadline, "deadline", 0, "transport deadline; defaults to --expires-in")
	fs.DurationVar(&readDelay, "read-delay", 0, "delay before each read after the first, as a slow consumer")
	fs.IntVar(&o.StopReadingAfter, "stop-reading-after", 0, "stop reading after N events and hold the stream")
	fs.IntVar(&o.CancelAfterEvents, "cancel-after-events", 0, "cancel after N events")
	fs.DurationVar(&cancelAfter, "cancel-after", 0, "cancel this long after the call starts")
	events := fs.Bool("events", false, "print every event, payloads included, to stderr as JSON lines")
	_ = fs.Parse(args)
	if err := check(co); err != nil {
		return err
	}
	o.Cell, o.Nodes, o.RequiredFeatures, o.APIMajor = co.Cell, nodes, features, uint32(major)
	if *reqCell != "" {
		o.Cell = *reqCell
	}
	for _, kv := range md {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--metadata %q is not key=value", kv)
		}
		if o.Metadata == nil {
			o.Metadata = map[string]string{}
		}
		o.Metadata[k] = v
	}
	o.ExpiresIn, o.Deadline, o.ReadDelay, o.CancelAfter =
		run.Duration(expires), run.Duration(deadline), run.Duration(readDelay), run.Duration(cancelAfter)
	cc, err := conn.Dial(*co)
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	var onEvent func(*servicev1.DiagnosticEvent)
	if *events {
		onEvent = func(ev *servicev1.DiagnosticEvent) {
			if b, err := protojson.Marshal(ev); err == nil {
				fmt.Fprintln(os.Stderr, string(b))
			}
		}
	}
	rec, err := run.Do(ctx, cc, o, onEvent)
	if err != nil {
		return err
	}
	return printJSON(rec)
}

func runLoad(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	co := connFlags(fs)
	specFile := fs.String("spec", "", "workload spec (JSON); - reads stdin")
	_ = fs.Parse(args)
	if err := check(co); err != nil {
		return err
	}
	var raw []byte
	var err error
	if *specFile == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(*specFile)
	}
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}
	var spec load.Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}
	spec.Cell = co.Cell
	cc, err := conn.Dial(*co)
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	var lines []load.Line
	err = load.Run(ctx, cc, spec, func(l load.Line) {
		lines = append(lines, l)
		_ = printJSON(l)
	})
	for _, s := range load.Summarize(lines) {
		_ = printJSON(map[string]any{"summary": s})
	}
	// An interrupt ends the workload early; what finished is the result.
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func invoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("invoke", flag.ExitOnError)
	co := connFlags(fs)
	method := fs.String("method", "", "full method name, /package.Service/Method")
	_ = fs.Parse(args)
	if err := check(co); err != nil {
		return err
	}
	if *method == "" {
		return errors.New("--method is required")
	}
	cc, err := conn.Dial(*co)
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = cc.Invoke(ctx, *method, &emptypb.Empty{}, &emptypb.Empty{})
	return printJSON(result{Method: *method, Status: rpcerr.Decode(err)})
}
