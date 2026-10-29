// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/netip"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// rib polls the EVPN RIB of a galactic-router through its read-only GoBGP
// API socket every -interval for -duration and counts the IP prefix routes
// (EVPN route type 5) for -prefix. It prints the count {"t","paths"} at the
// first poll and whenever it changes, then {"t","end"}. A poll that fails
// prints {"t","error"} and counts nothing.
func rib(args []string) error {
	fs := flag.NewFlagSet("rib", flag.ExitOnError)
	socket := fs.String("socket", "", "the router's GoBGP API unix socket")
	prefixFlag := fs.String("prefix", "", "the IP prefix to count routes for")
	interval := fs.Duration("interval", 200*time.Millisecond, "time between polls")
	duration := fs.Duration("duration", 30*time.Second, "how long to poll")
	_ = fs.Parse(args)
	prefix, err := netip.ParsePrefix(*prefixFlag)
	if err != nil {
		return err
	}
	if *socket == "" {
		return errors.New("-socket is required")
	}
	conn, err := grpc.NewClient("unix://"+*socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	c := api.NewGoBgpServiceClient(conn)
	last := -1
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	deadline := time.Now().Add(*duration)
	for time.Now().Before(deadline) {
		t := boottime()
		n, err := countPrefix(c, prefix, *interval)
		switch {
		case err != nil:
			_ = out.Encode(ribEvent{T: t, Error: err.Error()})
		case n != last:
			last = n
			_ = out.Encode(ribEvent{T: t, Paths: &n})
		}
		<-tick.C
	}
	return out.Encode(ribEvent{T: boottime(), End: true})
}

// ribEvent is one line rib prints.
type ribEvent struct {
	T     int64  `json:"t"`
	Paths *int   `json:"paths,omitempty"`
	Error string `json:"error,omitempty"`
	End   bool   `json:"end,omitempty"`
}

// countPrefix counts the global RIB's EVPN IP prefix paths for p.
func countPrefix(c api.GoBgpServiceClient, p netip.Prefix, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), max(timeout, time.Second))
	defer cancel()
	stream, err := c.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    &api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN},
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		rsp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return 0, err
		}
		for _, path := range rsp.GetDestination().GetPaths() {
			r := path.GetNlri().GetEvpnIpPrefix()
			if r == nil || path.GetIsWithdraw() {
				continue
			}
			addr, err := netip.ParseAddr(r.GetIpPrefix())
			if err == nil && netip.PrefixFrom(addr, int(r.GetIpPrefixLen())) == p {
				n++
			}
		}
	}
}
