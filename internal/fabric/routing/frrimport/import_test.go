// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package frrimport

import (
	"strings"
	"testing"
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

// hostnameLine is the line most insertions follow.
const hostnameLine = "hostname node-a-fabric\n"

func importText(text string) (*Objects, error) {
	return Import(strings.NewReader(text), Options{
		Namespace: "galactic-system", NodeName: "node-a", RouterClassName: "fabric-frr",
	})
}

func TestImportMinimal(t *testing.T) {
	o, err := importText(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if o.Router.Name != "node-a" || o.Parameters.HostnameSuffix != "-fabric" || !o.Parameters.IPv4UnicastDefault {
		t.Errorf("router %s, suffix %q, ipv4 default %v",
			o.Router.Name, o.Parameters.HostnameSuffix, o.Parameters.IPv4UnicastDefault)
	}
	if len(o.Peers) != 1 || o.Peers[0].Spec.PeerASN != 64496 || len(o.Peers[0].Spec.AddressFamilies) != 1 {
		t.Errorf("peers = %+v", o.Peers)
	}
	if got := o.Peers[0].Spec.FamilySettings[0].ExportPolicyRef.Name; got != "out" {
		t.Errorf("export policy ref = %q, want the object name out", got)
	}
}

// TestImportRefusesUnknownConstructs: the importer never drops a line it
// cannot represent; it names it.
func TestImportRefusesUnknownConstructs(t *testing.T) {
	for _, tc := range []struct{ name, insert, after string }{
		{"bfd", " neighbor 2001:db8::1 bfd\n", " neighbor 2001:db8::1 remote-as 64496\n"},
		{"vrf", "vrf blue\n", hostnameLine},
		{"expanded community list", "bgp community-list expanded X permit _64500_\n", hostnameLine},
		{"route-map call", " call OTHER\n", "route-map OUT permit 10\n"},
		{"prefix list without sequence", "ip prefix-list X permit 0.0.0.0/0\n", hostnameLine},
		{"network without route-map", "  network 2001:db8::/32\n", "  neighbor 2001:db8::1 activate\n"},
		{"static route with distance", "ipv6 route 2001:db8::/32 Null0 250\n", hostnameLine},
		{
			"repeated description",
			" neighbor 2001:db8::1 description first\n neighbor 2001:db8::1 description second\n",
			" neighbor 2001:db8::1 remote-as 64496\n",
		},
		{"repeated family setting", "  neighbor 2001:db8::1 route-map OUT out\n", "  neighbor 2001:db8::1 activate\n"},
		{"evpn family", " address-family l2vpn evpn\n exit-address-family\n", " bgp router-id 192.0.2.1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.Replace(minimal, tc.after, tc.after+tc.insert, 1)
			if text == minimal {
				t.Fatal("insertion point not found")
			}
			_, err := importText(text)
			if err == nil {
				t.Fatalf("imported %q without error", strings.TrimSpace(tc.insert))
			}
			if !strings.Contains(err.Error(), strings.Fields(tc.insert)[0]) {
				t.Errorf("error %v does not name the line", err)
			}
		})
	}
}

func TestImportRefusesHostnameForAnotherNode(t *testing.T) {
	if _, err := importText(strings.Replace(minimal, "node-a-fabric", "node-b-fabric", 1)); err == nil {
		t.Error("imported a configuration whose hostname names another node")
	}
}

func TestObjectName(t *testing.T) {
	for in, want := range map[string]string{
		"V6-UPSTREAM-AS64496-OUT": "v6-upstream-as64496-out",
		"SITE_LARGE__X":           "site-large-x",
	} {
		if got := objectName(in); got != want {
			t.Errorf("objectName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := objectName("node-a", "2001:db8::/32"); got != "node-a-2001-db8-32" {
		t.Errorf("objectName with a prefix = %q", got)
	}
}
