// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

const (
	validPrefix = "fd00:ed9e:1:100::/64"
	notMasked   = "masked, non-default IPv6"
)

const valid = `
provider: example-echo
services:
  - namespace: tenant-a
    name: echo
    uid: 11111111-1111-1111-1111-111111111111
    vpcUID: 22222222-2222-2222-2222-222222222222
    capabilities: [SocketAccess, PacketAccess]
    prefixes: ["fd00:ed9e:1:100::/64"]
`

func TestParse(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 7777 || len(c.Services) != 1 || !c.Services[0].Has(PacketAccess) ||
		c.Services[0].Prefixes[0].String() != validPrefix {
		t.Fatalf("parsed %+v", c)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ from, to, want string }{
		"no provider":         {"provider: example-echo", "provider: \"\"", "provider is required"},
		"unknown field":       {"provider: example-echo", "provider: example-echo\nextra: 1", "unknown field"},
		"missing uid":         {"uid: 11111111-1111-1111-1111-111111111111", "uid: \"\"", "are required"},
		"unknown capability":  {"[SocketAccess, PacketAccess]", "[SocketAccess, Teleport]", "is not SocketAccess"},
		"prefix needs packet": {"[SocketAccess, PacketAccess]", "[SocketAccess]", "prefixes need PacketAccess"},
		"ipv4 prefix":         {validPrefix, "10.0.0.0/8", notMasked},
		"unmasked prefix":     {validPrefix, "fd00:ed9e:1:100::1/64", notMasked},
		"default prefix":      {validPrefix, "::/0", notMasked},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(valid, tc.from, tc.to, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
