// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// startFabricAPI starts an API server holding every BGP CRD the fabric
// router consumes.
func startFabricAPI(t *testing.T) (client.Client, string) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	names := []string{
		"bgpadvertisements", "bgpcommunitysets", "bgppeerprofiles", "bgppeers", "bgppolicies",
		"bgpprefixlists", "bgprouterclasses", "bgprouters", "bgpstaticroutes", "bgpvrfinstances", "frrrouterparameters",
	}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "galactic.datumapis.com_"+name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		crds = append(crds, crd)
	}
	environment := &envtest.Environment{CRDs: crds}
	cfg, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	const ns = "fabric"
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	return c, ns
}

// admissionCase admits obj when wantErr is empty, and otherwise expects a
// refusal whose message contains wantErr.
type admissionCase struct {
	name    string
	obj     client.Object
	wantErr string
}

func runAdmission(t *testing.T, c client.Client, cases []admissionCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Create(context.Background(), tc.obj)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatal("admitted an invalid object")
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("refused for another reason: %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestFabricRoutingAdmission(t *testing.T) {
	c, ns := startFabricAPI(t)
	meta := func(prefix string, i int) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", prefix, i), Namespace: ns}
	}
	ipv6 := networkv1alpha1.AddressFamily{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast}
	r1 := networkv1alpha1.RouterRef{Name: "r1"}

	t.Run("static routes", func(t *testing.T) {
		route := func(i int, afi networkv1alpha1.AFI, dst string, action networkv1alpha1.BGPStaticRouteAction, nh *string) client.Object {
			return &networkv1alpha1.BGPStaticRoute{ObjectMeta: meta("sr", i), Spec: networkv1alpha1.BGPStaticRouteSpec{
				RouterRef: r1, AddressFamily: afi, Destination: dst, Action: action, NextHop: nh,
			}}
		}
		runAdmission(t, c, []admissionCase{
			{"ipv6 discard", route(0, networkv1alpha1.AFIIPv6, "2607:ed40:10c::/64", networkv1alpha1.BGPStaticRouteDiscard, nil), ""},
			{"ipv4 discard", route(1, networkv1alpha1.AFIIPv4, "192.0.2.0/24", networkv1alpha1.BGPStaticRouteDiscard, nil), ""},
			{"ipv4 next hop", route(2, networkv1alpha1.AFIIPv4, "192.0.2.0/24", networkv1alpha1.BGPStaticRouteNextHop, ptr.To("198.51.100.1")), ""},
			{"family mismatch", route(3, networkv1alpha1.AFIIPv4, "2607:ed40::/32", networkv1alpha1.BGPStaticRouteDiscard, nil), "destination must be in addressFamily"},
			{"next hop family mismatch", route(4, networkv1alpha1.AFIIPv4, "192.0.2.0/24", networkv1alpha1.BGPStaticRouteNextHop, ptr.To("2001:db8::1")), "nextHop must be in addressFamily"},
			{"next hop missing", route(5, networkv1alpha1.AFIIPv4, "192.0.2.0/24", networkv1alpha1.BGPStaticRouteNextHop, nil), "nextHop is required"},
			{"discard with next hop", route(6, networkv1alpha1.AFIIPv4, "192.0.2.0/24", networkv1alpha1.BGPStaticRouteDiscard, ptr.To("198.51.100.1")), "nextHop is required"},
			{"evpn family", route(7, networkv1alpha1.AFIL2VPN, "192.0.2.0/24", networkv1alpha1.BGPStaticRouteDiscard, nil), "addressFamily must be ipv4 or ipv6"},
		})
	})

	t.Run("peers and profiles", func(t *testing.T) {
		limit := func(action networkv1alpha1.BGPPrefixLimitAction, minutes *int32) *networkv1alpha1.BGPPrefixLimit {
			return &networkv1alpha1.BGPPrefixLimit{Maximum: 100, WarningThresholdPercent: ptr.To[int32](80), Action: action, RestartMinutes: minutes}
		}
		profile := func(i int, fam networkv1alpha1.BGPPeerFamilySettings) client.Object {
			return &networkv1alpha1.BGPPeerProfile{ObjectMeta: meta("pp", i), Spec: networkv1alpha1.BGPPeerProfileSpec{
				FRR:             &networkv1alpha1.BGPPeerProfileFRR{PeerGroupName: ptr.To[networkv1alpha1.FRRObjectName]("AS7979-V6")},
				PeerASN:         ptr.To[int64](7979),
				Transport:       &networkv1alpha1.BGPPeerTransport{EBGPMultihopTTL: ptr.To[int32](2), AdvertisementIntervalSeconds: ptr.To[int32](0)},
				AddressFamilies: []networkv1alpha1.BGPPeerFamilySettings{fam},
			}}
		}
		v6 := func(mutate func(*networkv1alpha1.BGPPeerFamilySettings)) networkv1alpha1.BGPPeerFamilySettings {
			f := networkv1alpha1.BGPPeerFamilySettings{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast}
			mutate(&f)
			return f
		}
		peer := func(i int, families []networkv1alpha1.AddressFamily, profileRef *networkv1alpha1.LocalObjectRef) client.Object {
			return &networkv1alpha1.BGPPeer{ObjectMeta: meta("peer", i), Spec: networkv1alpha1.BGPPeerSpec{
				RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &r1}, PeerASN: 7979, Address: "2001:db8::1",
				AddressFamilies: families, PeerProfileRef: profileRef,
			}}
		}
		runAdmission(t, c, []admissionCase{
			{"edge provider profile", profile(0, v6(func(f *networkv1alpha1.BGPPeerFamilySettings) {
				f.PrefixLimit = limit(networkv1alpha1.BGPPrefixLimitWarnOnly, nil)
				f.AllowASIn = ptr.To[int32](1)
				f.SendCommunity = ptr.To(networkv1alpha1.SendCommunityTypeBoth)
				f.ImportPolicyRef = &networkv1alpha1.LocalObjectRef{Name: "deny"}
				f.ExportPolicyRef = &networkv1alpha1.LocalObjectRef{Name: "v6-out"}
				f.FRR = &networkv1alpha1.FRRPeerFamilySettings{Weight: ptr.To[int32](100)}
			})), ""},
			{"restart with minutes", profile(1, v6(func(f *networkv1alpha1.BGPPeerFamilySettings) {
				f.PrefixLimit = limit(networkv1alpha1.BGPPrefixLimitRestart, ptr.To[int32](5))
			})), ""},
			{"restart without minutes", profile(2, v6(func(f *networkv1alpha1.BGPPeerFamilySettings) {
				f.PrefixLimit = limit(networkv1alpha1.BGPPrefixLimitRestart, nil)
			})), "restartMinutes is required"},
			{"warn with minutes", profile(3, v6(func(f *networkv1alpha1.BGPPeerFamilySettings) {
				f.PrefixLimit = limit(networkv1alpha1.BGPPrefixLimitWarnOnly, ptr.To[int32](5))
			})), "restartMinutes is required"},
			{"ipv6 evpn family", profile(4, v6(func(f *networkv1alpha1.BGPPeerFamilySettings) {
				f.SAFI = networkv1alpha1.SAFIEVPN
			})), "IPv6 only supports unicast SAFI"},
			{"peer with families", peer(0, []networkv1alpha1.AddressFamily{ipv6}, nil), ""},
			{"peer with profile only", peer(1, nil, &networkv1alpha1.LocalObjectRef{Name: "pp-0"}), ""},
			{"peer with neither", peer(2, nil, nil), "addressFamilies is required unless peerProfileRef"},
		})
	})

	t.Run("policies", func(t *testing.T) {
		term := func(mutate func(*networkv1alpha1.BGPPolicyTerm)) networkv1alpha1.BGPPolicyTerm {
			tm := networkv1alpha1.BGPPolicyTerm{Sequence: 10, Action: networkv1alpha1.BGPPolicyActionPermit}
			mutate(&tm)
			return tm
		}
		policy := func(i int, bound bool, frr bool, terms ...networkv1alpha1.BGPPolicyTerm) client.Object {
			p := &networkv1alpha1.BGPPolicy{ObjectMeta: meta("pol", i), Spec: networkv1alpha1.BGPPolicySpec{Terms: terms}}
			if bound {
				p.Spec.RouterRef = &r1
				p.Spec.Direction = networkv1alpha1.BGPPolicyDirectionExport
			}
			if frr {
				p.Spec.FRR = &networkv1alpha1.BGPPolicyFRR{RouteMapName: ptr.To[networkv1alpha1.FRRObjectName]("V6-HOSTING-AS7979-OUT")}
			}
			return p
		}
		fabricTerm := term(func(tm *networkv1alpha1.BGPPolicyTerm) {
			tm.Description = "Advertise edge services"
			tm.Match.PrefixListRef = &networkv1alpha1.LocalObjectRef{Name: "v6-edge-services"}
			tm.Match.CommunitySetRef = &networkv1alpha1.LocalObjectRef{Name: "internal"}
			tm.Set = &networkv1alpha1.BGPPolicySetActions{
				StandardCommunities: &networkv1alpha1.StandardCommunityAction{
					Operation: networkv1alpha1.CommunityOperationAdd, Values: []string{"33438:302", "no-export"},
				},
				LargeCommunities: &networkv1alpha1.LargeCommunityAction{
					Operation: networkv1alpha1.CommunityOperationReplace, Values: []string{"33438:1:840"},
				},
				AsPath: &networkv1alpha1.AsPathSet{Prepend: ptr.To[uint32](3), ASN: ptr.To[int64](33438)},
			}
		})
		unbound := &networkv1alpha1.BGPPolicy{ObjectMeta: meta("pol", 9), Spec: networkv1alpha1.BGPPolicySpec{
			RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &r1},
			Terms:        []networkv1alpha1.BGPPolicyTerm{term(func(*networkv1alpha1.BGPPolicyTerm) {})},
		}}
		runAdmission(t, c, []admissionCase{
			{"reusable fabric policy", policy(0, false, true, fabricTerm), ""},
			{"interface match", policy(1, false, false, term(func(tm *networkv1alpha1.BGPPolicyTerm) {
				tm.Match.Interface = ptr.To("lo")
			})), ""},
			{"router-bound legacy policy", policy(2, true, false, term(func(tm *networkv1alpha1.BGPPolicyTerm) {
				tm.Match.Any = true
			})), ""},
			{"router-bound with fabric fields", policy(3, true, false, fabricTerm), "cannot use frr, set references"},
			{"router-bound with frr name", policy(4, true, true, term(func(*networkv1alpha1.BGPPolicyTerm) {})), "cannot use frr, set references"},
			{"router-bound without direction", unbound, "must set direction"},
			{"multi-line description", policy(5, false, false, term(func(tm *networkv1alpha1.BGPPolicyTerm) {
				tm.Description = "one\ntwo"
			})), "spec.terms[0].description"},
			{"invalid standard community", policy(6, false, false, term(func(tm *networkv1alpha1.BGPPolicyTerm) {
				tm.Set = &networkv1alpha1.BGPPolicySetActions{StandardCommunities: &networkv1alpha1.StandardCommunityAction{
					Operation: networkv1alpha1.CommunityOperationAdd, Values: []string{"33438:1:2"},
				}}
			})), "each value must be ASN:NN"},
			{"any with set reference", policy(7, false, false, term(func(tm *networkv1alpha1.BGPPolicyTerm) {
				tm.Match.Any = true
				tm.Match.PrefixListRef = &networkv1alpha1.LocalObjectRef{Name: "x"}
			})), "set references and interface must be unset"},
			{"invalid frr name", &networkv1alpha1.BGPPolicy{ObjectMeta: meta("pol", 8), Spec: networkv1alpha1.BGPPolicySpec{
				FRR:   &networkv1alpha1.BGPPolicyFRR{RouteMapName: ptr.To[networkv1alpha1.FRRObjectName]("bad name")},
				Terms: []networkv1alpha1.BGPPolicyTerm{term(func(*networkv1alpha1.BGPPolicyTerm) {})},
			}}, "routeMapName"},
		})
	})

	t.Run("advertisements", func(t *testing.T) {
		adv := func(i int, afi networkv1alpha1.AFI, agg *networkv1alpha1.BGPAggregation, prefixes ...networkv1alpha1.Prefix) client.Object {
			return &networkv1alpha1.BGPAdvertisement{ObjectMeta: meta("adv", i), Spec: networkv1alpha1.BGPAdvertisementSpec{
				RouterRef: r1, AddressFamily: networkv1alpha1.AddressFamily{AFI: afi, SAFI: networkv1alpha1.SAFIUnicast},
				Aggregation: agg, Prefixes: prefixes,
				PolicyRef: &networkv1alpha1.AdvertisementPolicyRef{Name: "originate"},
			}}
		}
		runAdmission(t, c, []admissionCase{
			{"ipv6 aggregate", adv(0, networkv1alpha1.AFIIPv6, &networkv1alpha1.BGPAggregation{Prefix: "2607:ed40:10c::/48"}), ""},
			{"aggregate family mismatch", adv(1, networkv1alpha1.AFIIPv4, &networkv1alpha1.BGPAggregation{Prefix: "2607:ed40:10c::/48"}), "aggregation prefix must be in"},
			{"aggregate with prefixes", adv(2, networkv1alpha1.AFIIPv6, &networkv1alpha1.BGPAggregation{Prefix: "2607:ed40:10c::/48"}, "2607:ed40:10c::/64"), "aggregation cannot be combined"},
			{"network statements", adv(3, networkv1alpha1.AFIIPv6, nil, "2607:ed40:10c::/64"), ""},
		})
	})

	t.Run("compatibility and bounds", func(t *testing.T) {
		peer := func(i int, mutate func(*networkv1alpha1.BGPPeerSpec)) client.Object {
			p := &networkv1alpha1.BGPPeer{ObjectMeta: meta("compat-peer", i), Spec: networkv1alpha1.BGPPeerSpec{
				RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &r1}, PeerASN: 65001, Address: "2001:db8::2",
				AddressFamilies: []networkv1alpha1.AddressFamily{{AFI: networkv1alpha1.AFIL2VPN, SAFI: networkv1alpha1.SAFIEVPN}},
				Description:     "spine-1", UpdateSource: ptr.To("lo"),
			}}
			mutate(&p.Spec)
			return p
		}
		v4 := []networkv1alpha1.BGPPeerFamilySettings{{AFI: networkv1alpha1.AFIIPv4, SAFI: networkv1alpha1.SAFIUnicast}}
		vrf := func(i int, ref *networkv1alpha1.RouterRef, sel *networkv1alpha1.RouterSelector) client.Object {
			rt := []networkv1alpha1.RouteTarget{{Value: "65000:1"}}
			return &networkv1alpha1.BGPVRFInstance{ObjectMeta: meta("vrf", i), Spec: networkv1alpha1.BGPVRFInstanceSpec{
				RouterTarget: networkv1alpha1.RouterTarget{RouterRef: ref, RouterSelector: sel},
				VRFID:        1, ImportRouteTargets: rt, ExportRouteTargets: rt,
			}}
		}
		sel := &networkv1alpha1.RouterSelector{MatchLabels: map[string]string{"a": "b"}}
		boundPolicy := func(i int, mutate func(*networkv1alpha1.BGPPolicySpec)) client.Object {
			p := &networkv1alpha1.BGPPolicy{ObjectMeta: meta("compat-pol", i), Spec: networkv1alpha1.BGPPolicySpec{
				RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &r1},
				Direction:    networkv1alpha1.BGPPolicyDirectionImport,
				Terms:        []networkv1alpha1.BGPPolicyTerm{{Sequence: 10, Action: networkv1alpha1.BGPPolicyActionPermit}},
			}}
			mutate(&p.Spec)
			return p
		}
		runAdmission(t, c, []admissionCase{
			{"existing EVPN peer", peer(0, func(*networkv1alpha1.BGPPeerSpec) {}), ""},
			{"peer with both router refs", peer(1, func(s *networkv1alpha1.BGPPeerSpec) { s.RouterSelector = sel }),
				"Exactly one of routerRef or routerSelector"},
			{"peer with no router ref", peer(2, func(s *networkv1alpha1.BGPPeerSpec) { s.RouterRef = nil }),
				"Exactly one of routerRef or routerSelector"},
			{"peer description with a newline", peer(3, func(s *networkv1alpha1.BGPPeerSpec) {
				s.Description = "a\n neighbor 192.0.2.1 remote-as 1"
			}), "spec.description"},
			{"peer update source not an address or interface", peer(4, func(s *networkv1alpha1.BGPPeerSpec) {
				s.UpdateSource = ptr.To("lo\nexit")
			}), "updateSource must be an IP address or an interface name"},
			{"family settings outside address families", peer(5, func(s *networkv1alpha1.BGPPeerSpec) {
				s.FamilySettings = v4
			}), "every familySettings entry must be one of addressFamilies"},
			{"family settings without families or profile", peer(6, func(s *networkv1alpha1.BGPPeerSpec) {
				s.AddressFamilies, s.FamilySettings = nil, v4
			}), "addressFamilies is required unless peerProfileRef"},
			{"peer ASN above 32 bits", peer(7, func(s *networkv1alpha1.BGPPeerSpec) { s.PeerASN = 4294967296 }), "spec.peerASN"},
			{"profile ASN above 32 bits", &networkv1alpha1.BGPPeerProfile{ObjectMeta: meta("compat-pp", 0),
				Spec: networkv1alpha1.BGPPeerProfileSpec{PeerASN: ptr.To[int64](4294967296)}}, "spec.peerASN"},
			{"vrf with router ref", vrf(0, &r1, nil), ""},
			{"vrf with both router refs", vrf(1, &r1, sel), "Exactly one of routerRef or routerSelector"},
			{"vrf with no router ref", vrf(2, nil, nil), "Exactly one of routerRef or routerSelector"},
			{"policy with both router refs", boundPolicy(0, func(s *networkv1alpha1.BGPPolicySpec) { s.RouterSelector = sel }),
				"At most one of routerRef or routerSelector"},
			{"bound policy deleting a community set", boundPolicy(1, func(s *networkv1alpha1.BGPPolicySpec) {
				s.Terms[0].Set = &networkv1alpha1.BGPPolicySetActions{DeleteCommunitySetRef: &networkv1alpha1.LocalObjectRef{Name: "x"}}
			}), "cannot use frr, set references"},
			{"bound policy deleting a large community set", boundPolicy(2, func(s *networkv1alpha1.BGPPolicySpec) {
				s.Terms[0].Set = &networkv1alpha1.BGPPolicySetActions{
					DeleteLargeCommunitySetRef: &networkv1alpha1.LocalObjectRef{Name: "x"},
				}
			}), "cannot use frr, set references"},
			{"bound policy matching a large community set", boundPolicy(3, func(s *networkv1alpha1.BGPPolicySpec) {
				s.Terms[0].Match.LargeCommunitySetRef = &networkv1alpha1.LocalObjectRef{Name: "x"}
			}), "cannot use frr, set references"},
			{"prepend ASN above 32 bits", boundPolicy(4, func(s *networkv1alpha1.BGPPolicySpec) {
				s.Terms[0].Set = &networkv1alpha1.BGPPolicySetActions{
					AsPath: &networkv1alpha1.AsPathSet{Prepend: ptr.To[uint32](1), ASN: ptr.To[int64](4294967296)},
				}
			}), "asn"},
			{"standard community above 16 bits", boundPolicy(5, func(s *networkv1alpha1.BGPPolicySpec) {
				s.RouterRef, s.Direction = nil, ""
				s.Terms[0].Set = &networkv1alpha1.BGPPolicySetActions{StandardCommunities: &networkv1alpha1.StandardCommunityAction{
					Operation: networkv1alpha1.CommunityOperationAdd, Values: []string{"70000:1"},
				}}
			}), "each value must be ASN:NN"},
		})
	})

	t.Run("routers and parameters", func(t *testing.T) {
		router := func(i int, class *string) client.Object {
			return &networkv1alpha1.BGPRouter{ObjectMeta: meta("rt", i), Spec: networkv1alpha1.BGPRouterSpec{
				RouterClassName: class, TargetRef: networkv1alpha1.TargetRef{Kind: "Node", Name: "node-a"},
				LocalASN: 33438, RouterID: "10.0.0.1", AddressFamilies: []networkv1alpha1.AddressFamily{ipv6},
				FRR: &networkv1alpha1.BGPRouterFRR{Retain: &networkv1alpha1.BGPRouterFRRRetain{
					PolicyRefs: []networkv1alpha1.LocalObjectRef{{Name: "ibgp-out"}},
				}},
			}}
		}
		params := &networkv1alpha1.FRRRouterParameters{
			ObjectMeta: metav1.ObjectMeta{Name: "fabric-v1"},
			Spec: networkv1alpha1.FRRRouterParametersSpec{
				DefaultsProfile: networkv1alpha1.FRRDefaultsTraditional, HostnameSuffix: "-fabric",
				LogFile:        &networkv1alpha1.FRRLogFile{Path: "/var/log/frr/frr.log", Level: "informational"},
				IPv6Forwarding: true, LogNeighborChanges: true,
				BMPTargets: []networkv1alpha1.BMPTarget{{
					Name: "fabric-api",
					Connect: networkv1alpha1.BMPConnect{
						Address: "127.0.0.1", Port: 9348, MinRetryMilliseconds: ptr.To[int32](1000), MaxRetryMilliseconds: ptr.To[int32](10000),
					},
					Monitors: []networkv1alpha1.BMPMonitor{
						{AFI: networkv1alpha1.AFIIPv4, SAFI: networkv1alpha1.SAFIUnicast, Mode: networkv1alpha1.BMPMonitorLocRIB},
						{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast, Mode: networkv1alpha1.BMPMonitorLocRIB},
					},
				}},
			},
		}
		runAdmission(t, c, []admissionCase{
			{"classed router retains definitions", router(0, ptr.To("fabric-frr")), ""},
			{"classless router with frr settings", router(1, nil), "frr settings apply only"},
			{"local ASN above 32 bits", func() client.Object {
				r := router(2, ptr.To("fabric-frr")).(*networkv1alpha1.BGPRouter)
				r.Spec.LocalASN = 4294967296
				return r
			}(), "spec.localASN"},
			{"staging parameters", params, ""},
			{"evpn bmp monitor", &networkv1alpha1.FRRRouterParameters{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-bmp"},
				Spec: networkv1alpha1.FRRRouterParametersSpec{
					DefaultsProfile: networkv1alpha1.FRRDefaultsTraditional,
					BMPTargets: []networkv1alpha1.BMPTarget{{
						Name:     "x",
						Connect:  networkv1alpha1.BMPConnect{Address: "127.0.0.1", Port: 1},
						Monitors: []networkv1alpha1.BMPMonitor{{AFI: networkv1alpha1.AFIL2VPN, SAFI: networkv1alpha1.SAFIEVPN, Mode: networkv1alpha1.BMPMonitorLocRIB}},
					}},
				},
			}, "BMP monitors cover ipv4 or ipv6 unicast"},
		})
		params.Spec.LogNeighborChanges = false
		if err := c.Update(context.Background(), params); err == nil {
			t.Error("admitted a change to FRRRouterParameters spec")
		}
	})
}
