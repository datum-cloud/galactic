// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package frrimport

import (
	"strings"
	"testing"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
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

// activateLine is the line family insertions follow.
const activateLine = "  neighbor 2001:db8::1 activate\n"

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
		{"redistribution without route-map", "  redistribute connected\n", activateLine},
		{"source not an address", " set src lo\n", "route-map OUT permit 10\n"},
		{"next-hop-self with another option", "  neighbor 2001:db8::1 next-hop-self all\n", activateLine},
		{"static route with distance", "ipv6 route 2001:db8::/32 Null0 250\n", hostnameLine},
		{
			"repeated description",
			" neighbor 2001:db8::1 description first\n neighbor 2001:db8::1 description second\n",
			" neighbor 2001:db8::1 remote-as 64496\n",
		},
		{"repeated family setting", "  neighbor 2001:db8::1 route-map OUT out\n", activateLine},
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

// lab holds every optional construct the lab uses, with hash comments in
// each context and a route-map entry closed by an unindented line.
const lab = `# top-level comment
frr defaults traditional
hostname node-a-fabric
log syslog informational
ip forwarding
route-map SRC permit 10
 # indented route-map comment
 set src 2001:db8::1
!
router bgp 64500
 bgp router-id 192.0.2.1
 no bgp ebgp-requires-policy
 # indented router comment
 neighbor 2001:db8::1 remote-as 64496
 address-family ipv6 unicast
  # indented family comment
  neighbor 2001:db8::1 activate
  neighbor 2001:db8::1 next-hop-self force
  neighbor 2001:db8::1 route-map SRC in
  network 2001:db8:1::/48
  aggregate-address 2001:db8::/32 summary-only
 exit-address-family
 bmp targets collector
  # indented bmp comment
  bmp connect 2001:db8::8 port 5000 min-retry 1000 max-retry 30000 source-interface lo
  bmp monitor ipv6 unicast loc-rib
  bmp stats interval 60000
 exit
#
ipv6 forwarding
`

func TestImportLabConstructs(t *testing.T) {
	o, err := importText(lab)
	if err != nil {
		t.Fatal(err)
	}
	p := o.Parameters
	if p.LogSyslog == nil || *p.LogSyslog != "informational" {
		t.Errorf("log syslog = %v", p.LogSyslog)
	}
	if p.EBGPRequiresPolicy == nil || *p.EBGPRequiresPolicy {
		t.Errorf("ebgp-requires-policy = %v, want false", p.EBGPRequiresPolicy)
	}
	if len(p.BMPTargets) != 1 {
		t.Fatalf("bmp targets = %+v", p.BMPTargets)
	}
	bmp := p.BMPTargets[0]
	if bmp.Connect.SourceInterface == nil || *bmp.Connect.SourceInterface != "lo" ||
		bmp.StatsIntervalMilliseconds == nil || *bmp.StatsIntervalMilliseconds != 60000 {
		t.Errorf("bmp target = %+v", bmp)
	}
	fs := o.Peers[0].Spec.FamilySettings
	if len(fs) != 1 || fs[0].NextHopMode == nil || *fs[0].NextHopMode != networkv1alpha1.BGPNextHopSelfForce ||
		fs[0].ExportPolicyRef != nil {
		t.Errorf("family settings = %+v", fs)
	}
	if len(o.Policies) != 1 || o.Policies[0].Spec.Terms[0].Set == nil ||
		o.Policies[0].Spec.Terms[0].Set.Source == nil || *o.Policies[0].Spec.Terms[0].Set.Source != "2001:db8::1" {
		t.Errorf("policies = %+v", o.Policies)
	}
	if len(o.Advertisements) != 2 {
		t.Fatalf("advertisements = %+v", o.Advertisements)
	}
	for _, a := range o.Advertisements {
		if a.Spec.PolicyRef != nil {
			t.Errorf("advertisement %s has policy %s, want none", a.Name, a.Spec.PolicyRef.Name)
		}
	}
	if agg := o.Advertisements[1].Spec.Aggregation; agg == nil || agg.Prefix != "2001:db8::/32" || !agg.SummaryOnly {
		t.Errorf("aggregate = %+v", agg)
	}
}

// TestImportRouteMapIndentation: FRR keeps a route-map command in its
// entry however it is indented, and returns to the top level for any
// other command.
func TestImportRouteMapIndentation(t *testing.T) {
	for name, set := range map[string]string{"unindented": "set src 2001:db8::1", "tab": "\tset src 2001:db8::1"} {
		t.Run(name, func(t *testing.T) {
			text := strings.Replace(minimal, "route-map OUT permit 10\nexit\n",
				"route-map OUT permit 10\n"+set+"\nroute-map OUT permit 20\nexit\n", 1)
			o, err := importText(text)
			if err != nil {
				t.Fatal(err)
			}
			terms := o.Policies[0].Spec.Terms
			if len(terms) != 2 || terms[0].Set == nil || terms[0].Set.Source == nil || terms[1].Set != nil {
				t.Errorf("terms = %+v", terms)
			}
		})
	}
}

// TestImportSyslogDefaultLevel: `log syslog` alone is FRR's default level.
func TestImportSyslogDefaultLevel(t *testing.T) {
	o, err := importText(strings.Replace(minimal, hostnameLine, hostnameLine+"log syslog\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	if o.Parameters.LogSyslog == nil || *o.Parameters.LogSyslog != networkv1alpha1.FRRLogLevelDebugging {
		t.Errorf("log syslog = %v, want debugging", o.Parameters.LogSyslog)
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
