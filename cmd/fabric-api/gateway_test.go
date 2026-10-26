// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"go.datum.net/galactic/internal/fabric/gateway/limit"
)

// budgets is the flag every valid limit needs; qualified is in the error of
// a limit raised above its ceiling.
const (
	budgets   = "--aggregate-budgets"
	qualified = "qualified"
)

// parseLimits parses args as the gateway's limit flags, with the cell slot,
// queue and budget flags they depend on.
func parseLimits(t *testing.T, args ...string) (limit.Limits, error) {
	t.Helper()
	o := &gatewayOptions{}
	f := pflag.NewFlagSet("gateway", pflag.ContinueOnError)
	f.IntVar(&o.slots, "cell-slots", 8, "")
	f.IntVar(&o.queue, "cell-queue", 256, "")
	f.BoolVar(&o.aggregateBudgets, "aggregate-budgets", false, "")
	registerLimitFlags(f, &o.limits)
	if err := f.Parse(args); err != nil {
		t.Fatal(err)
	}
	for _, name := range limitFlags {
		if f.Lookup(name) == nil {
			t.Fatalf("limit flag --%s is not registered", name)
		}
	}
	return gatewayLimits(f, o)
}

func TestGatewayLimits(t *testing.T) {
	l, err := parseLimits(t, budgets)
	if err != nil {
		t.Fatal(err)
	}
	if l != limit.Defaults() {
		t.Errorf("default limits = %+v, want the contract's", l)
	}

	l, err = parseLimits(t, budgets, "--packet-host-rate=10", "--packet-host-burst=320",
		"--principal-slots=1", "--project-streams=1", "--queue-wait=5s", "--request-cell-burst=4")
	if err != nil {
		t.Fatal(err)
	}
	if l.PacketHost != (limit.Rate{PerSecond: 10, Burst: 320}) || l.PrincipalSlots != 1 || l.ProjectStreams != 1 ||
		l.QueueWait != 5*time.Second || l.RequestCell.Burst != 4 {
		t.Errorf("lowered limits = %+v", l)
	}

	// A smaller cell lowers each principal's default share with it.
	l, err = parseLimits(t, budgets, "--cell-slots=1", "--cell-queue=8", "--service-streams=1")
	if err != nil {
		t.Fatal(err)
	}
	if l.Slots != 1 || l.PrincipalSlots != 1 || l.Queue != 8 || l.PrincipalQueue != 8 || l.ProjectStreams != 1 {
		t.Errorf("small cell limits = %+v", l)
	}
}

func TestGatewayLimitsRefused(t *testing.T) {
	cases := map[string]struct {
		args []string
		want string
	}{
		"limit without budgets":  {[]string{"--packet-cell-rate=50"}, "needs --aggregate-budgets"},
		"raised rate":            {[]string{budgets, "--packet-host-rate=21"}, qualified},
		"raised burst":           {[]string{budgets, "--request-project-burst=3"}, qualified},
		"raised principal slots": {[]string{budgets, "--principal-slots=3"}, qualified},
		"raised project streams": {[]string{budgets, "--project-streams=3"}, qualified},
		"principal above cell": {
			[]string{budgets, "--cell-slots=1", "--principal-slots=2"}, "principal slots",
		},
		"burst too long":    {[]string{budgets, "--packet-host-rate=1"}, "burst/rate"},
		"short burst":       {[]string{budgets, "--packet-prefix-burst=19"}, "cannot fund"},
		"zero rate":         {[]string{budgets, "--request-cell-rate=0"}, "positive"},
		"queue wait raised": {[]string{budgets, "--queue-wait=11s"}, "queue wait"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseLimits(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}
