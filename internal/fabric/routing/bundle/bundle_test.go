// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bytes"
	"strings"
	"testing"

	"go.datum.net/galactic/internal/fabric/routing/frrimport"
)

const minimal = `frr defaults traditional
hostname node-a-fabric
router bgp 64500
 bgp router-id 192.0.2.1
 neighbor 2001:db8::1 remote-as 64496
 address-family ipv6 unicast
  neighbor 2001:db8::1 activate
  neighbor 2001:db8::1 route-map OUT out
 exit-address-family
route-map OUT permit 10
exit
`

func imported(t *testing.T) *Bundle {
	t.Helper()
	o, err := frrimport.Import(strings.NewReader(minimal), frrimport.Options{
		Namespace: "galactic-system", NodeName: "node-a", RouterClassName: "fabric-frr",
	})
	if err != nil {
		t.Fatal(err)
	}
	return FromImport(o, "fabric-frr")
}

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := imported(t).Write(&buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "status: {}") || strings.Contains(buf.String(), "creationTimestamp: null") {
		t.Errorf("written objects carry empty status or timestamps:\n%s", buf.String())
	}
	b, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	in, err := b.Input("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if in.Class == nil || in.Parameters == nil || len(in.Peers) != 1 || len(in.Policies) != 1 {
		t.Errorf("input = class %v, parameters %v, %d peers, %d policies",
			in.Class != nil, in.Parameters != nil, len(in.Peers), len(in.Policies))
	}
}

func TestReadRefuses(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown kind": "apiVersion: galactic.datumapis.com/v1alpha1\nkind: BGPSomething\nmetadata:\n  name: x\n",
		"other group":  "apiVersion: example.com/v1\nkind: BGPPeer\nmetadata:\n  name: x\n",
		"field with the wrong case": "apiVersion: galactic.datumapis.com/v1alpha1\nkind: BGPPeer\n" +
			"metadata:\n  name: x\nspec:\n  peerAsn: 64500\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(doc)); err == nil {
				t.Error("read without error")
			}
		})
	}
}

func TestInputRefusesAmbiguity(t *testing.T) {
	t.Run("duplicate name", func(t *testing.T) {
		b := imported(t)
		b.Policies = append(b.Policies, b.Policies[0].DeepCopy())
		if _, err := b.Input("node-a"); err == nil {
			t.Error("two policies with one name resolved")
		}
	})
	t.Run("other namespace", func(t *testing.T) {
		b := imported(t)
		b.Policies[0].Namespace = "elsewhere"
		if _, err := b.Input("node-a"); err == nil {
			t.Error("a policy from another namespace resolved")
		}
	})
	t.Run("missing router", func(t *testing.T) {
		if _, err := imported(t).Input("node-b"); err == nil {
			t.Error("a missing router resolved")
		}
	})
}
