// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

var ipv6Unicast = networkv1alpha1.AddressFamily{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast}

const (
	testNode             = "node-a"
	testClass            = "fabric-frr"
	fieldRouterClassName = "spec.routerClassName"
	fieldFamilies        = "spec.addressFamilies"
	fieldSpec            = "spec"
	fieldExportPolicy    = "exportPolicyRef"
	internalCommunity    = "64500:310"
	locatorBlock         = "2001:db8:100::/48"
)

// baseline is a small valid router: one profile, one grouped peer, one
// advertisement, one static route, and the policies, list and set they use.
func baseline() Input {
	return Input{
		Router: &networkv1alpha1.BGPRouter{ObjectMeta: om(testNode), Spec: networkv1alpha1.BGPRouterSpec{
			RouterClassName: ptr.To(testClass),
			Plane:           ptr.To(networkv1alpha1.BGPRoutingPlaneUnderlay),
			TargetRef:       networkv1alpha1.TargetRef{Kind: "Node", Name: testNode},
			LocalASN:        64500,
			RouterID:        "192.0.2.1",
			AddressFamilies: []networkv1alpha1.AddressFamily{ipv6Unicast},
		}},
		Class: &networkv1alpha1.BGPRouterClass{
			ObjectMeta: metav1.ObjectMeta{Name: testClass},
			Spec:       networkv1alpha1.BGPRouterClassSpec{ControllerName: networkv1alpha1.FabricRouterControllerName},
		},
		Parameters: &networkv1alpha1.FRRRouterParameters{
			ObjectMeta: metav1.ObjectMeta{Name: "v1"},
			Spec: networkv1alpha1.FRRRouterParametersSpec{
				DefaultsProfile: networkv1alpha1.FRRDefaultsTraditional,
				HostnameSuffix:  "-fabric",
			},
		},
		Peers:          []networkv1alpha1.BGPPeer{baselinePeer()},
		Advertisements: []networkv1alpha1.BGPAdvertisement{baselineAdvertisement()},
		StaticRoutes: []networkv1alpha1.BGPStaticRoute{{
			ObjectMeta: om("node-a-locator"),
			Spec: networkv1alpha1.BGPStaticRouteSpec{
				RouterRef:     networkv1alpha1.RouterRef{Name: testNode},
				AddressFamily: networkv1alpha1.AFIIPv6,
				Destination:   "2001:db8:100::/64",
				Action:        networkv1alpha1.BGPStaticRouteDiscard,
			},
		}},
		Profiles: map[string]*networkv1alpha1.BGPPeerProfile{"upstream": {
			ObjectMeta: om("upstream"),
			Spec: networkv1alpha1.BGPPeerProfileSpec{
				PeerASN: ptr.To[int64](64496),
				AddressFamilies: []networkv1alpha1.BGPPeerFamilySettings{{
					AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast,
					ImportPolicyRef: ref("deny"), ExportPolicyRef: ref("export"),
				}},
			},
		}},
		Policies: map[string]*networkv1alpha1.BGPPolicy{
			"deny": policy("deny", networkv1alpha1.BGPPolicyTerm{Sequence: 1, Action: networkv1alpha1.BGPPolicyActionDeny}),
			"export": policy("export",
				networkv1alpha1.BGPPolicyTerm{
					Sequence: 10, Action: networkv1alpha1.BGPPolicyActionPermit,
					Match: networkv1alpha1.BGPPolicyMatch{PrefixListRef: ref("locator"), CommunitySetRef: ref("internal")},
				},
				networkv1alpha1.BGPPolicyTerm{Sequence: 500, Action: networkv1alpha1.BGPPolicyActionDeny}),
			"originate": policy("originate", networkv1alpha1.BGPPolicyTerm{
				Sequence: 10, Action: networkv1alpha1.BGPPolicyActionPermit,
				Set: &networkv1alpha1.BGPPolicySetActions{StandardCommunities: &networkv1alpha1.StandardCommunityAction{
					Operation: networkv1alpha1.CommunityOperationReplace, Values: []string{internalCommunity},
				}},
			}),
		},
		PrefixLists: map[string]*networkv1alpha1.BGPPrefixList{"locator": {
			ObjectMeta: om("locator"),
			Spec: networkv1alpha1.BGPPrefixListSpec{Entries: []networkv1alpha1.BGPPrefixListEntry{{
				Sequence: 5, Action: networkv1alpha1.BGPPolicyActionPermit,
				Prefix: locatorBlock, GE: ptr.To[int32](49),
			}}},
		}},
		CommunitySets: map[string]*networkv1alpha1.BGPCommunitySet{"internal": {
			ObjectMeta: om("internal"),
			Spec: networkv1alpha1.BGPCommunitySetSpec{
				Type: networkv1alpha1.BGPCommunitySetTypeStandard, Entries: []string{internalCommunity},
			},
		}},
	}
}

func om(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: "galactic-system"}
}

func ref(name string) *networkv1alpha1.LocalObjectRef {
	return &networkv1alpha1.LocalObjectRef{Name: name}
}

func policy(name string, terms ...networkv1alpha1.BGPPolicyTerm) *networkv1alpha1.BGPPolicy {
	return &networkv1alpha1.BGPPolicy{ObjectMeta: om(name), Spec: networkv1alpha1.BGPPolicySpec{Terms: terms}}
}

func baselinePeer() networkv1alpha1.BGPPeer {
	return networkv1alpha1.BGPPeer{ObjectMeta: om("node-a-upstream"), Spec: networkv1alpha1.BGPPeerSpec{
		RouterTarget:   networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: testNode}},
		PeerASN:        64496,
		Address:        "2001:db8::1",
		PeerProfileRef: ref("upstream"),
		FamilySettings: []networkv1alpha1.BGPPeerFamilySettings{{
			AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast,
			FRR: &networkv1alpha1.FRRPeerFamilySettings{Weight: ptr.To[int32](100)},
		}},
	}}
}

func baselineAdvertisement() networkv1alpha1.BGPAdvertisement {
	spec := networkv1alpha1.BGPAdvertisementSpec{
		RouterRef:     networkv1alpha1.RouterRef{Name: testNode},
		AddressFamily: ipv6Unicast,
		Prefixes:      []networkv1alpha1.Prefix{"2001:db8:0100::/64"},
		PolicyRef:     &networkv1alpha1.AdvertisementPolicyRef{Name: "originate"},
	}
	return networkv1alpha1.BGPAdvertisement{ObjectMeta: om("node-a-locator"), Spec: spec}
}

func TestCompileBaseline(t *testing.T) {
	res, err := Compile(baseline())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"frr defaults traditional",
		"hostname node-a-fabric",
		"ipv6 route 2001:db8:100::/64 Null0",
		"router bgp 64500",
		" neighbor upstream peer-group",
		" neighbor upstream remote-as 64496",
		" neighbor 2001:db8::1 peer-group upstream",
		"  network 2001:db8:100::/64 route-map originate",
		"  neighbor upstream route-map export out",
		"  neighbor 2001:db8::1 weight 100",
		"ipv6 prefix-list locator seq 5 permit 2001:db8:100::/48 ge 49",
		"bgp community-list standard internal seq 5 permit 64500:310",
		"route-map export permit 10",
		" match ipv6 address prefix-list locator",
		" set community 64500:310",
	} {
		if !strings.Contains(res.Config, want+"\n") {
			t.Errorf("config lacks %q:\n%s", want, res.Config)
		}
	}
	if strings.Contains(res.Config, "neighbor 2001:db8::1 remote-as") {
		t.Error("a grouped peer repeats the profile's remote-as")
	}
	again, _ := Compile(baseline())
	if again.Digest != res.Digest || len(res.Digest) != 64 {
		t.Errorf("digest not stable: %s then %s", res.Digest, again.Digest)
	}
}

// TestCompileRefuses: each change makes the compile fail with the named
// reason and field, and never yields a configuration.
func TestCompileRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Input)
		reason Reason
		field  string
	}{
		{"classless router", func(in *Input) {
			in.Router.Spec.RouterClassName = nil
		}, ReasonInvalid, fieldRouterClassName},
		{"missing class", func(in *Input) { in.Class = nil }, ReasonUnresolvedRef, fieldRouterClassName},
		{"foreign class", func(in *Input) {
			in.Class.Spec.ControllerName = "example.com/other"
		}, ReasonInvalid, fieldRouterClassName},
		{"missing parameters", func(in *Input) { in.Parameters = nil }, ReasonUnresolvedRef, "spec.parametersRef"},
		{"router listen port", func(in *Input) {
			in.Router.Spec.ListenPort = ptr.To[int32](1790)
		}, ReasonUnsupportedField, "spec.listenPort"},
		{"router srv6 locator", func(in *Input) {
			in.Router.Spec.SRv6Locator = "2001:db8::/48"
		}, ReasonUnsupportedField, "spec.srv6Locator"},
		{"evpn router family", func(in *Input) {
			in.Router.Spec.AddressFamilies = append(in.Router.Spec.AddressFamilies,
				networkv1alpha1.AddressFamily{AFI: networkv1alpha1.AFIL2VPN, SAFI: networkv1alpha1.SAFIEVPN})
		}, ReasonUnsupportedField, fieldFamilies},
		{"legacy peer multihop", func(in *Input) {
			in.Peers[0].Spec.EbgpMultiHop = true
		}, ReasonUnsupportedField, "spec.ebgpMultiHop"},
		{"legacy peer route map", func(in *Input) {
			in.Peers[0].Spec.RouteMapOut = "x"
		}, ReasonUnsupportedField, "spec.routeMapOut"},
		{"peer password", func(in *Input) {
			in.Peers[0].Spec.AuthSecretRef = &networkv1alpha1.LocalSecretRef{Name: "s"}
		}, ReasonUnsupportedField, "spec.authSecretRef"},
		{"missing profile", func(in *Input) {
			delete(in.Profiles, "upstream")
		}, ReasonUnresolvedRef, "spec.peerProfileRef"},
		{"profile ASN mismatch", func(in *Input) { in.Peers[0].Spec.PeerASN = 64497 }, ReasonInvalid, "spec.peerASN"},
		{"no export policy", func(in *Input) {
			in.Profiles["upstream"].Spec.AddressFamilies[0].ExportPolicyRef = nil
		}, ReasonInvalid, fieldFamilySettings},
		{"missing policy", func(in *Input) { delete(in.Policies, "export") }, ReasonUnresolvedRef, fieldExportPolicy},
		{"missing prefix list", func(in *Input) {
			delete(in.PrefixLists, "locator")
		}, ReasonUnresolvedRef, "spec.terms.match.prefixListRef"},
		{"community set type", func(in *Input) {
			in.CommunitySets["internal"].Spec.Type = networkv1alpha1.BGPCommunitySetTypeLarge
		}, ReasonInvalid, "spec.terms.match.communitySetRef"},
		{"interface match on a peer", func(in *Input) {
			in.Policies["export"].Spec.Terms[0].Match.Interface = ptr.To("lo")
		}, ReasonInvalid, fieldExportPolicy},
		{"legacy policy match", func(in *Input) {
			in.Policies["export"].Spec.Terms[0].Match.CommunityMatch = []string{"64500:1"}
		}, ReasonUnsupportedField, "spec.terms.match.communityMatch"},
		{"policy bound to a router", func(in *Input) {
			in.Policies["export"].Spec.RouterRef = &networkv1alpha1.RouterRef{Name: "node-a"}
		}, ReasonUnsupportedField, "spec.routerRef"},
		{"as-path replace", func(in *Input) {
			in.Policies["originate"].Spec.Terms[0].Set.AsPath = &networkv1alpha1.AsPathSet{Replace: []int64{64500}}
		}, ReasonUnsupportedField, "spec.terms.set.asPath"},
		{"redistribution without policy", func(in *Input) {
			in.Advertisements[0].Spec.Prefixes = nil
			in.Advertisements[0].Spec.Redistribute = []networkv1alpha1.RedistributeSource{
				networkv1alpha1.RedistributeSourceConnected,
			}
			in.Advertisements[0].Spec.PolicyRef = nil
		}, ReasonInvalid, "spec.policyRef"},
		{"no export policy with ebgp-requires-policy on", func(in *Input) {
			in.Parameters.Spec.EBGPRequiresPolicy = ptr.To(true)
			in.Profiles["upstream"].Spec.AddressFamilies[0].ExportPolicyRef = nil
		}, ReasonInvalid, fieldFamilySettings},
		{"source outside the peer family", func(in *Input) {
			in.Policies["export"].Spec.Terms[0].Set = &networkv1alpha1.BGPPolicySetActions{Source: ptr.To("192.0.2.1")}
		}, ReasonInvalid, fieldExportPolicy},
		{"source outside the advertisement family", func(in *Input) {
			in.Policies["originate"].Spec.Terms[0].Set.Source = ptr.To("192.0.2.1")
		}, ReasonInvalid, "spec.policyRef"},
		{"source not an address", func(in *Input) {
			in.Policies["originate"].Spec.Terms[0].Set.Source = ptr.To("lo")
		}, ReasonInvalid, "spec.terms.set.source"},
		{"space in a BMP source interface", func(in *Input) {
			in.Parameters.Spec.BMPTargets = []networkv1alpha1.BMPTarget{{
				Name: "collector",
				Connect: networkv1alpha1.BMPConnect{
					Address: "2001:db8::8", Port: 5000, SourceInterface: ptr.To("lo\n exit"),
				},
			}}
		}, ReasonInvalid, "spec.bmpTargets.connect.sourceInterface"},
		{"space in a syslog level", func(in *Input) {
			in.Parameters.Spec.LogSyslog = ptr.To(networkv1alpha1.FRRLogLevel("errors\nip forwarding"))
		}, ReasonInvalid, "spec.logSyslog"},
		{"advertisement communities", func(in *Input) {
			in.Advertisements[0].Spec.Communities = []networkv1alpha1.Community{"64500:1"}
		}, ReasonUnsupportedField, "spec.communities"},
		{"advertisement family not on router", func(in *Input) {
			in.Advertisements[0].Spec.AddressFamily = networkv1alpha1.AddressFamily{
				AFI: networkv1alpha1.AFIIPv4, SAFI: networkv1alpha1.SAFIUnicast,
			}
			in.Advertisements[0].Spec.Prefixes = []networkv1alpha1.Prefix{"192.0.2.0/24"}
		}, ReasonInvalid, "spec.addressFamily"},
		{"redistribution beside prefixes", func(in *Input) {
			in.Advertisements[0].Spec.Redistribute = []networkv1alpha1.RedistributeSource{
				networkv1alpha1.RedistributeSourceConnected,
			}
		}, ReasonInvalid, fieldSpec},
		{"duplicate route-map name", func(in *Input) {
			name := networkv1alpha1.FRRObjectName("export")
			in.Policies["deny"].Spec.FRR = &networkv1alpha1.BGPPolicyFRR{RouteMapName: &name}
		}, ReasonInvalid, ""},
		{"retained policy missing", func(in *Input) {
			in.Router.Spec.FRR = &networkv1alpha1.BGPRouterFRR{Retain: &networkv1alpha1.BGPRouterFRRRetain{
				PolicyRefs: []networkv1alpha1.LocalObjectRef{{Name: "gone"}}}}
		}, ReasonUnresolvedRef, "spec.frr.retain.policyRefs"},
		{"newline in a node name", func(in *Input) {
			in.Router.Spec.TargetRef.Name = "node-a\nip route 0.0.0.0/0 Null0"
		}, ReasonInvalid, "spec.targetRef.name"},
		{"space in a route-map name", func(in *Input) {
			name := networkv1alpha1.FRRObjectName("export permit 1")
			in.Policies["export"].Spec.FRR = &networkv1alpha1.BGPPolicyFRR{RouteMapName: &name}
		}, ReasonInvalid, "spec.frr.routeMapName"},
		{"newline in a description", func(in *Input) {
			in.Peers[0].Spec.Description = "tor\n neighbor 192.0.2.9 remote-as 1"
		}, ReasonInvalid, "spec.description"},
		{"space in a community value", func(in *Input) {
			in.Policies["originate"].Spec.Terms[0].Set.StandardCommunities.Values = []string{"64500:1 additive"}
		}, ReasonInvalid, "standardCommunities.values"},
		{"space in a community-list entry", func(in *Input) {
			in.CommunitySets["internal"].Spec.Entries = []string{"64500:1\nroute-map x permit 1"}
		}, ReasonInvalid, "spec.entries"},
		{"IPv6 router ID", func(in *Input) { in.Router.Spec.RouterID = "2001:db8::1" }, ReasonInvalid, "spec.routerID"},
		{"overlay plane", func(in *Input) {
			in.Router.Spec.Plane = ptr.To(networkv1alpha1.BGPRoutingPlaneOverlay)
		}, ReasonInvalid, "spec.plane"},
		{"peer timers", func(in *Input) {
			in.Peers[0].Spec.HoldTime = &metav1.Duration{Duration: 9e9}
		}, ReasonUnsupportedField, "spec.holdTime"},
		{"peer remote port", func(in *Input) {
			in.Peers[0].Spec.RemotePort = ptr.To[int32](1790)
		}, ReasonUnsupportedField, "spec.remotePort"},
		{"duplicate peer address", func(in *Input) {
			dup := baselinePeer()
			dup.Name = "node-a-upstream-2"
			in.Peers = append(in.Peers, dup)
		}, ReasonInvalid, "spec.address"},
		{"peer family beyond its profile", func(in *Input) {
			in.Router.Spec.AddressFamilies = append(in.Router.Spec.AddressFamilies, networkv1alpha1.AddressFamily{
				AFI: networkv1alpha1.AFIIPv4, SAFI: networkv1alpha1.SAFIUnicast,
			})
			in.Peers[0].Spec.AddressFamilies = []networkv1alpha1.AddressFamily{ipv6Unicast, {
				AFI: networkv1alpha1.AFIIPv4, SAFI: networkv1alpha1.SAFIUnicast,
			}}
		}, ReasonInvalid, fieldFamilies},
		{"member overrides the group's export policy", func(in *Input) {
			in.Peers[0].Spec.FamilySettings[0].ExportPolicyRef = ref("deny")
		}, ReasonUnsupportedField, fieldExportPolicy},
		{"member turns off the group's soft reconfiguration", func(in *Input) {
			in.Profiles["upstream"].Spec.AddressFamilies[0].SoftReconfigurationInbound = ptr.To(true)
			in.Peers[0].Spec.FamilySettings[0].SoftReconfigurationInbound = ptr.To(false)
		}, ReasonUnsupportedField, "softReconfigurationInbound"},
		{"member drops the group's next-hop-self", func(in *Input) {
			in.Profiles["upstream"].Spec.AddressFamilies[0].NextHopMode = ptr.To(networkv1alpha1.BGPNextHopSelf)
			in.Peers[0].Spec.FamilySettings[0].NextHopMode = ptr.To(networkv1alpha1.BGPNextHopUnchanged)
		}, ReasonUnsupportedField, "nextHopMode"},
		{"aggregation beside prefixes", func(in *Input) {
			in.Advertisements[0].Spec.Aggregation = &networkv1alpha1.BGPAggregation{Prefix: locatorBlock}
		}, ReasonInvalid, fieldSpec},
		{"empty advertisement", func(in *Input) { in.Advertisements[0].Spec.Prefixes = nil }, ReasonInvalid, fieldSpec},
		{"duplicate term sequence", func(in *Input) {
			in.Policies["export"].Spec.Terms[1].Sequence = 10
		}, ReasonInvalid, "spec.terms.sequence"},
		{"duplicate prefix-list sequence", func(in *Input) {
			pl := in.PrefixLists["locator"]
			pl.Spec.Entries = append(pl.Spec.Entries, pl.Spec.Entries[0])
		}, ReasonInvalid, "spec.entries.sequence"},
		{"retained profile without members or ASN", func(in *Input) {
			in.Profiles["empty"] = &networkv1alpha1.BGPPeerProfile{ObjectMeta: om("empty")}
			in.Router.Spec.FRR = &networkv1alpha1.BGPRouterFRR{Retain: &networkv1alpha1.BGPRouterFRRRetain{
				PeerProfileRefs: []networkv1alpha1.LocalObjectRef{{Name: "empty"}}}}
		}, ReasonInvalid, "spec.peerASN"},
		{"profile family not on the router", func(in *Input) {
			in.Profiles["upstream"].Spec.AddressFamilies = append(in.Profiles["upstream"].Spec.AddressFamilies,
				networkv1alpha1.BGPPeerFamilySettings{AFI: networkv1alpha1.AFIIPv4, SAFI: networkv1alpha1.SAFIUnicast,
					ExportPolicyRef: ref("export")})
		}, ReasonInvalid, fieldFamilies},
		{"datacenter defaults", func(in *Input) {
			in.Parameters.Spec.DefaultsProfile = networkv1alpha1.FRRDefaultsDatacenter
		}, ReasonUnsupportedField, "spec.defaultsProfile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseline()
			tc.mutate(&in)
			res, err := Compile(in)
			if res.Config != "" {
				t.Error("a refused compile produced a configuration")
			}
			var ps RefusalError
			if !errors.As(err, &ps) {
				t.Fatalf("Compile error = %v, want RefusalError", err)
			}
			for _, p := range ps {
				if p.Reason == tc.reason && strings.Contains(p.Field, tc.field) {
					return
				}
			}
			t.Errorf("problems = %v, want %s on a field containing %q", ps, tc.reason, tc.field)
		})
	}
}

// TestCompileRetainedInterfacePolicy: a retained policy is attached to
// nothing, so an interface match in it is allowed.
func TestCompileRetainedInterfacePolicy(t *testing.T) {
	in := baseline()
	in.Policies["redist"] = &networkv1alpha1.BGPPolicy{ObjectMeta: metav1.ObjectMeta{Name: "redist"},
		Spec: networkv1alpha1.BGPPolicySpec{Terms: []networkv1alpha1.BGPPolicyTerm{{
			Sequence: 10, Action: networkv1alpha1.BGPPolicyActionPermit,
			Match: networkv1alpha1.BGPPolicyMatch{Interface: ptr.To("lo")}}}}}
	in.Router.Spec.FRR = &networkv1alpha1.BGPRouterFRR{Retain: &networkv1alpha1.BGPRouterFRRRetain{
		PolicyRefs: []networkv1alpha1.LocalObjectRef{{Name: "redist"}}}}
	res, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, "route-map redist permit 10\n match interface lo\n") {
		t.Errorf("retained policy not rendered:\n%s", res.Config)
	}
}

// TestCompileCanonicalForms: the compiler writes what FRR displays, so a
// running configuration and a revision compare equal.
func TestCompileCanonicalForms(t *testing.T) {
	in := baseline()
	in.Policies["originate"].Spec.Terms[0].Set.StandardCommunities.Values = []string{
		"64496:2030", "no-export", "64496:989", "0:64511",
	}
	in.Policies["originate"].Spec.Terms[0].Set.LargeCommunities = &networkv1alpha1.LargeCommunityAction{
		Operation: networkv1alpha1.CommunityOperationAdd, Values: []string{"64500:2:1", "64500:1:9", "100:1:1"},
	}
	in.Policies["originate"].Spec.Terms[0].Set.AsPath = &networkv1alpha1.AsPathSet{Prepend: ptr.To[uint32](2)}
	in.CommunitySets["internal"].Spec.Entries = []string{internalCommunity, "64500:302"}
	in.Profiles["upstream"].Spec.AddressFamilies[0].SendCommunity = ptr.To(networkv1alpha1.SendCommunityTypeBoth)
	in.Advertisements[0].Spec.Prefixes = []networkv1alpha1.Prefix{"2001:db8:0100::1/64"}
	res, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		" set community 0:64511 64496:989 64496:2030 no-export",
		" set large-community 100:1:1 64500:1:9 64500:2:1 additive",
		" set as-path prepend 64500 64500",
		"bgp community-list standard internal seq 5 permit 64500:310",
		"bgp community-list standard internal seq 10 permit 64500:302",
		"  no neighbor upstream send-community large",
		"  network 2001:db8:100::/64 route-map originate",
	} {
		if !strings.Contains(res.Config, want+"\n") {
			t.Errorf("config lacks %q:\n%s", want, res.Config)
		}
	}
	if strings.Contains(res.Config, "ipv6 forwarding") || strings.Contains(res.Config, " send-community both") {
		t.Errorf("config holds a line FRR never displays:\n%s", res.Config)
	}
}

// TestCompileIgnoresInputOrder: the configuration and digest do not depend
// on the order the objects arrive in.
func TestCompileIgnoresInputOrder(t *testing.T) {
	in := baseline()
	second := baselinePeer()
	second.Name, second.Spec.Address = "node-a-upstream-2", "2001:db8::2"
	in.Peers = append(in.Peers, second)
	adv := baselineAdvertisement()
	adv.Name, adv.Spec.Prefixes = "node-a-other", []networkv1alpha1.Prefix{"2001:db8:200::/64"}
	in.Advertisements = append(in.Advertisements, adv)
	in.PrefixLists["locator"].Spec.Entries = append(in.PrefixLists["locator"].Spec.Entries,
		networkv1alpha1.BGPPrefixListEntry{Sequence: 1, Action: networkv1alpha1.BGPPolicyActionDeny, Prefix: "2001:db8::/32"})
	first, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Peers[0], in.Peers[1] = in.Peers[1], in.Peers[0]
	in.Advertisements[0], in.Advertisements[1] = in.Advertisements[1], in.Advertisements[0]
	entries := in.PrefixLists["locator"].Spec.Entries
	entries[0], entries[1] = entries[1], entries[0]
	again, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != again.Digest {
		t.Errorf("reordering the input changed the configuration:\n%s\n---\n%s", first.Config, again.Config)
	}
}

// TestCompileLabConstructs: the optional constructs the lab uses render as
// the pinned FRR displays them.
func TestCompileLabConstructs(t *testing.T) {
	in := baseline()
	p := &in.Parameters.Spec
	p.LogFile = &networkv1alpha1.FRRLogFile{Path: "/var/log/frr/frr.log", Level: "informational"}
	p.LogSyslog = ptr.To(networkv1alpha1.FRRLogLevel("errors"))
	p.EBGPRequiresPolicy = ptr.To(false)
	p.BMPTargets = []networkv1alpha1.BMPTarget{{
		Name: "collector",
		Connect: networkv1alpha1.BMPConnect{
			Address: "2001:db8::8", Port: 5000, MinRetryMilliseconds: ptr.To[int32](1000),
			MaxRetryMilliseconds: ptr.To[int32](30000), SourceInterface: ptr.To("lo"),
		},
		StatsIntervalMilliseconds: ptr.To[int32](60000),
		Monitors: []networkv1alpha1.BMPMonitor{{
			AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast, Mode: networkv1alpha1.BMPMonitorLocRIB,
		}},
	}}
	// With the requirement off, a family may export with no policy.
	in.Profiles["upstream"].Spec.AddressFamilies[0].ExportPolicyRef = nil
	in.Profiles["upstream"].Spec.AddressFamilies[0].NextHopMode = ptr.To(networkv1alpha1.BGPNextHopSelfForce)
	in.Profiles["upstream"].Spec.AddressFamilies[0].ImportPolicyRef = ref("set-src")
	in.Policies["set-src"] = policy("set-src", networkv1alpha1.BGPPolicyTerm{
		Sequence: 10, Action: networkv1alpha1.BGPPolicyActionPermit,
		Set: &networkv1alpha1.BGPPolicySetActions{Source: ptr.To("2001:db8:0:0::1")},
	})
	in.Advertisements[0].Spec.PolicyRef = nil
	agg := baselineAdvertisement()
	agg.Name = "node-a-aggregate"
	agg.Spec.Prefixes, agg.Spec.PolicyRef = nil, nil
	agg.Spec.Aggregation = &networkv1alpha1.BGPAggregation{Prefix: locatorBlock, SummaryOnly: true}
	in.Advertisements = append(in.Advertisements, agg)
	res, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"hostname node-a-fabric\nlog syslog errors\nlog file /var/log/frr/frr.log informational\n",
		" bgp router-id 192.0.2.1\n no bgp ebgp-requires-policy\n no bgp default ipv4-unicast\n",
		"  network 2001:db8:100::/64\n",
		"  aggregate-address 2001:db8:100::/48 summary-only\n",
		"  neighbor upstream route-map set-src in\n  neighbor upstream next-hop-self force\n",
		"route-map set-src permit 10\n set src 2001:db8::1\nexit\n",
		" bmp targets collector\n  bmp stats interval 60000\n" +
			"  bmp connect 2001:db8::8 port 5000 min-retry 1000 max-retry 30000 source-interface lo\n",
	} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("config lacks %q:\n%s", want, res.Config)
		}
	}
	if strings.Contains(res.Config, "route-map export") || strings.Contains(res.Config, " out\n") {
		t.Errorf("a family with no export policy rendered one:\n%s", res.Config)
	}
}

// TestCompileOptionalDefaults: each optional construct at its FRR default
// renders what FRR displays for it, which is nothing or the short form.
func TestCompileOptionalDefaults(t *testing.T) {
	base, err := Compile(baseline())
	if err != nil {
		t.Fatal(err)
	}
	in := baseline()
	in.Parameters.Spec.EBGPRequiresPolicy = ptr.To(true)
	res, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Config != base.Config {
		t.Errorf("ebgpRequiresPolicy true changed the configuration:\n%s", res.Config)
	}
	in = baseline()
	in.Parameters.Spec.LogSyslog = ptr.To(networkv1alpha1.FRRLogLevelDebugging)
	if res, err = Compile(in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, "\nlog syslog\n") {
		t.Errorf("the default syslog level is not left out:\n%s", res.Config)
	}
}
