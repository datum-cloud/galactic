// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package frrtext

import (
	"strings"
	"testing"
)

const config = `! comment
frr defaults traditional
router bgp 64500
 neighbor PG peer-group
 address-family ipv6 unicast
  network 2001:db8:010c::/48 route-map R
  neighbor PG activate
 exit-address-family
 bmp targets t
  bmp connect 127.0.0.1 port 1
 exit
route-map R permit 10
 set community 64500:1
exit
`

// TestNormalizeIgnoresWhatFRRIgnores: order, comments, blank lines and
// leading zeros in prefixes do not change a configuration.
func TestNormalizeIgnoresWhatFRRIgnores(t *testing.T) {
	reordered := `route-map R permit 10
 set community 64500:1
exit

router bgp 64500
 bmp targets t
  bmp connect 127.0.0.1 port 1
 exit
 address-family ipv6 unicast
  neighbor PG activate
  network 2001:db8:10c::/48 route-map R
 exit-address-family
 neighbor PG peer-group
frr defaults traditional
`
	if diff := Diff(Normalize(config), Normalize(reordered)); len(diff) > 0 {
		t.Errorf("equivalent configurations differ:\n%s", strings.Join(diff, "\n"))
	}
}

// TestNormalizeKeepsContexts: the same line in a different context, or a
// changed line, is a difference.
func TestNormalizeKeepsContexts(t *testing.T) {
	for name, changed := range map[string]string{
		"line moved to the other family": strings.Replace(config, "ipv6 unicast", "ipv4 unicast", 1),
		"set changed":                    strings.Replace(config, "64500:1", "64500:2", 1),
		"bmp line dropped":               strings.Replace(config, "  bmp connect 127.0.0.1 port 1\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if diff := Diff(Normalize(config), Normalize(changed)); len(diff) == 0 {
				t.Error("a changed configuration compares equal")
			}
		})
	}
}
