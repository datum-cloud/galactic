// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"time"
)

const (
	commandQuery = "query"
	transportTCP = "tcp"
	transportUDP = "udp"
	modeRoot     = "root"
	modeProducer = "producer"
)

// Run executes a query or relay subcommand and returns its process exit status.
func Run(ctx context.Context, args []string, output io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("expected query or relay command")
	}
	if args[0] == "relay" {
		return runRelay(ctx, args[1:], output)
	}
	if args[0] != commandQuery {
		return 2, errors.New("expected query or relay command")
	}
	flags := flag.NewFlagSet(commandQuery, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cfg := QueryConfig{}
	flags.StringVar(&cfg.Transport, "transport", transportUDP, "udp or tcp")
	flags.StringVar(&cfg.Frontend, "frontend", "[fd70:ffff::10]:8443", "consumer frontend address")
	flags.StringVar(&cfg.Source, "source", "[fd00:c::2]:40530", "consumer source address")
	flags.StringVar(&cfg.Expected, "expected", "", "expected producer IP")
	flags.StringVar(&cfg.Payload, "payload", "", "request payload")
	flags.DurationVar(&cfg.Timeout, "timeout", 2*time.Second, "request timeout")
	if err := flags.Parse(args[1:]); err != nil {
		return 2, err
	}
	if flags.NArg() != 0 || !validTransport(cfg.Transport) || cfg.Expected == "" || cfg.Timeout <= 0 {
		return 2, errors.New("query requires udp or tcp, expected producer IP, and a positive timeout")
	}
	reply, peer, queryErr := Query(ctx, cfg)
	result := struct {
		Reply
		Transport string `json:"transport"`
		Peer      string `json:"peer"`
		Timeout   bool   `json:"timeout"`
		Error     string `json:"error,omitempty"`
	}{Reply: reply, Transport: cfg.Transport, Peer: peer}
	var networkErr net.Error
	if queryErr != nil {
		result.Error = queryErr.Error()
		result.Timeout = errors.As(queryErr, &networkErr)
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return 1, err
	}
	if result.Timeout {
		return 3, queryErr
	}
	if queryErr != nil {
		return 1, queryErr
	}
	return 0, nil
}

func runRelay(ctx context.Context, args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("relay", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cfg := RelayConfig{}
	flags.StringVar(&cfg.Mode, "mode", modeRoot, "root responder or producer relay")
	flags.StringVar(&cfg.Transport, "transport", transportUDP, "udp or tcp")
	flags.StringVar(&cfg.Listen, "listen", "", "listener address")
	flags.StringVar(&cfg.Target, "target", "", "producer identity or upstream address")
	flags.StringVar(&cfg.StateDir, "state-dir", "", "response delay state directory")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	if flags.NArg() != 0 || !validTransport(cfg.Transport) || (cfg.Mode != modeRoot && cfg.Mode != modeProducer) ||
		cfg.Listen == "" || cfg.Target == "" || (cfg.Mode == modeProducer && cfg.StateDir == "") {
		return 2, errors.New("relay requires a valid mode, transport, listen address, target, and producer state directory")
	}
	if err := Serve(ctx, cfg, output); err != nil {
		return 1, err
	}
	return 0, nil
}

func validTransport(transport string) bool {
	return transport == transportTCP || transport == transportUDP
}
