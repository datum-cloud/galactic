// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	unitNS     = "galactic-system"
	unitDomain = "fabric"
	unitASN    = 64512
	transportP = "public"
	transportM = "private-mesh"
	roleLabel  = "fabric.example/role"
	cellB      = "cell-b"
	rrV6       = "2001:db8:a::1"
	rrProfile  = "rr-clients"
	extRel     = "transit"
	extPeer    = "2001:db8:ffff::1"
	a1v6       = "fd00::1"
	remoteRec  = "remote"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func router(name string, labels map[string]string) *networkv1alpha1.BGPRouter {
	return &networkv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: unitNS, Labels: labels, UID: types.UID("uid-" + name)},
		Spec: networkv1alpha1.BGPRouterSpec{
			RouterClassName: ptr.To("fabric-frr"), LocalASN: unitASN, RouterID: "192.0.2.1",
			TargetRef: networkv1alpha1.TargetRef{Kind: "Node", Name: "node-" + name},
		},
	}
}

// endpoint is a FabricEndpoint created age seconds after epoch.
func endpoint(
	name, cell, routerName, transport, v4, v6 string, age int, labels map[string]string,
) networkv1alpha1.FabricEndpoint {
	ep := networkv1alpha1.FabricEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: unitNS, Labels: labels, UID: types.UID("uid-" + name),
			CreationTimestamp: metav1.NewTime(epoch.Add(time.Duration(age) * time.Second))},
		Spec: networkv1alpha1.FabricEndpointSpec{RoutingDomain: unitDomain, Cell: cell,
			RouterRef: networkv1alpha1.LocalObjectRef{Name: routerName}, Transport: transport, ASN: unitASN},
	}
	if v4 != "" {
		ep.Spec.Addresses.IPv4 = ptr.To(v4)
	}
	if v6 != "" {
		ep.Spec.Addresses.IPv6 = ptr.To(v6)
	}
	return ep
}

func routerMap(rs ...*networkv1alpha1.BGPRouter) map[string]*networkv1alpha1.BGPRouter {
	out := map[string]*networkv1alpha1.BGPRouter{}
	for _, r := range rs {
		out[r.Name] = r
	}
	return out
}

func both() []networkv1alpha1.FabricSessionFamily {
	return []networkv1alpha1.FabricSessionFamily{
		networkv1alpha1.FabricSessionFamilyIPv4, networkv1alpha1.FabricSessionFamilyIPv6,
	}
}

func reflectionTopology(cell string, members ...string) *networkv1alpha1.FabricTopology {
	refs := make([]networkv1alpha1.LocalObjectRef, 0, len(members))
	for _, m := range members {
		refs = append(refs, networkv1alpha1.LocalObjectRef{Name: m})
	}
	return &networkv1alpha1.FabricTopology{
		ObjectMeta: metav1.ObjectMeta{Name: "fabric-" + cell, Namespace: unitNS},
		Spec: networkv1alpha1.FabricTopologySpec{
			RoutingDomain: unitDomain, Cell: cell, MaxSessionsPerRouter: 64,
			FailureDomainLabel: "topology.kubernetes.io/zone",
			Members:            networkv1alpha1.FabricTopologyMembers{Routers: refs},
			Reflection: []networkv1alpha1.FabricReflectionRelationship{{
				Name: "public", Transports: []string{transportP}, Families: both(),
				UpdateSource:      networkv1alpha1.FabricUpdateSourceEndpointAddress,
				ReflectorSelector: metav1.LabelSelector{MatchLabels: map[string]string{roleLabel: "reflector"}},
				ClientSelector:    metav1.LabelSelector{MatchLabels: map[string]string{roleLabel: "client"}},
				Reflector: networkv1alpha1.FabricSessionSettings{FamilySettings: []networkv1alpha1.BGPPeerFamilySettings{{
					AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast,
					NextHopMode: ptr.To(networkv1alpha1.BGPNextHopSelfForce)}}},
			}},
		},
	}
}

var (
	reflectorRole = map[string]string{roleLabel: "reflector"}
	clientRole    = map[string]string{roleLabel: "client"}
)

// twoCells is cell-a with a reflector and a client, and cell-b with a
// client, every endpoint present in both cells.
func twoCells() (
	[]networkv1alpha1.FabricEndpoint, map[string]*networkv1alpha1.BGPRouter, map[string]*networkv1alpha1.BGPRouter,
) {
	eps := []networkv1alpha1.FabricEndpoint{
		endpoint("a-rr-public", cellA, "rr", transportP, "198.51.100.1", rrV6, 0, reflectorRole),
		endpoint("a-c1-public", cellA, "c1", transportP, "198.51.100.2", "2001:db8:a::2", 0, clientRole),
		// cell-b's client is IPv6-only on the public transport.
		endpoint("b-c1-public", cellB, "c1", transportP, "", "2001:db8:b::2", 0, clientRole),
	}
	routersA := routerMap(router("rr", nil), router("c1", nil))
	routersB := routerMap(router("c1", nil))
	return eps, routersA, routersB
}

func generate(t *testing.T, topo *networkv1alpha1.FabricTopology, eps []networkv1alpha1.FabricEndpoint,
	routers map[string]*networkv1alpha1.BGPRouter) Plan {
	t.Helper()
	states := Analyze(eps, map[string]bool{topo.Spec.Cell: true}, routers)
	plan, err := Generate(Input{Topology: topo, Endpoints: states, Routers: routers})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// session is a peer's identity as both ends see it.
type session struct{ router, cell, source, address string }

// TestCrossCellSessionsAreReciprocal: each cell generates only its own
// side from the same records, and the two sides describe the same sessions,
// only in families both ends carry. A reflector in one cell serves another
// cell's client.
func TestCrossCellSessionsAreReciprocal(t *testing.T) {
	eps, routersA, routersB := twoCells()
	a := generate(t, reflectionTopology(cellA, "rr", "c1"), eps, routersA)
	b := generate(t, reflectionTopology(cellB, "c1"), eps, routersB)

	sides := map[session]bool{}
	for _, plan := range []struct {
		cell string
		p    Plan
	}{{cellA, a}, {cellB, b}} {
		for _, s := range plan.p.Sessions {
			sides[session{s.Peer.Spec.RouterRef.Name, plan.cell, *s.Peer.Spec.UpdateSource, s.Peer.Spec.Address}] = true
		}
	}
	want := []struct{ a, b session }{
		{session{"rr", cellA, "198.51.100.1", "198.51.100.2"}, session{"c1", cellA, "198.51.100.2", "198.51.100.1"}},
		{session{"rr", cellA, rrV6, "2001:db8:a::2"}, session{"c1", cellA, "2001:db8:a::2", rrV6}},
		{session{"rr", cellA, rrV6, "2001:db8:b::2"}, session{"c1", cellB, "2001:db8:b::2", rrV6}},
	}
	for _, w := range want {
		if !sides[w.a] || !sides[w.b] {
			t.Errorf("session %v / %v: generated %t / %t", w.a, w.b, sides[w.a], sides[w.b])
		}
		delete(sides, w.a)
		delete(sides, w.b)
	}
	for s := range sides {
		t.Errorf("unexpected session %v", s)
	}
	if len(b.Sessions) != 1 || b.Sessions[0].Peer.Spec.RouterRef.Name != "c1" {
		t.Errorf("cell-b generated %d sessions, want only c1's one", len(b.Sessions))
	}
}

// TestReflectorSettings: the reflector side marks its clients as
// route-reflector clients with its own family settings; the client side
// does not.
func TestReflectorSettings(t *testing.T) {
	eps, routersA, _ := twoCells()
	plan := generate(t, reflectionTopology(cellA, "rr", "c1"), eps, routersA)
	for _, s := range plan.Sessions {
		p := s.Peer
		rrc := false
		for _, fs := range p.Spec.FamilySettings {
			if fs.RouteReflectorClient != nil && *fs.RouteReflectorClient {
				rrc = true
			}
		}
		if (p.Spec.RouterRef.Name == "rr") != rrc {
			t.Errorf("%s: route-reflector client %t", p.Name, rrc)
		}
		if p.Spec.RouterRef.Name == "rr" && strings.HasSuffix(p.Name, "ipv6") {
			if fs := p.Spec.FamilySettings; len(fs) != 1 || fs[0].NextHopMode == nil ||
				*fs[0].NextHopMode != networkv1alpha1.BGPNextHopSelfForce {
				t.Errorf("%s: family settings %+v, want next-hop-self force", p.Name, fs)
			}
		}
		if len(p.Spec.AddressFamilies) != 1 || len(p.Spec.FamilySettings) > 1 {
			t.Errorf("%s: families %+v settings %+v, want only its own family", p.Name, p.Spec.AddressFamilies,
				p.Spec.FamilySettings)
		}
	}
}

// TestProfileFamilies: with a profile, a peer activates the profile's
// families and the reflector marks each of them.
func TestProfileFamilies(t *testing.T) {
	eps, routersA, _ := twoCells()
	topo := reflectionTopology(cellA, "rr", "c1")
	topo.Spec.Reflection[0].Families = []networkv1alpha1.FabricSessionFamily{networkv1alpha1.FabricSessionFamilyIPv6}
	topo.Spec.Reflection[0].Reflector.PeerProfileRef = &networkv1alpha1.LocalObjectRef{Name: rrProfile}
	profile := &networkv1alpha1.BGPPeerProfile{ObjectMeta: metav1.ObjectMeta{Name: rrProfile},
		Spec: networkv1alpha1.BGPPeerProfileSpec{AddressFamilies: []networkv1alpha1.BGPPeerFamilySettings{
			{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast}}}}
	states := Analyze(eps, map[string]bool{cellA: true}, routersA)
	plan, err := Generate(Input{Topology: topo, Endpoints: states, Routers: routersA,
		Profiles: map[string]*networkv1alpha1.BGPPeerProfile{rrProfile: profile}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Profiles[0] != rrProfile {
		t.Errorf("profiles %v", plan.Profiles)
	}
	for _, s := range plan.Sessions {
		p := s.Peer
		if p.Spec.RouterRef.Name != "rr" {
			continue
		}
		if p.Spec.PeerProfileRef == nil || len(p.Spec.AddressFamilies) != 0 {
			t.Errorf("%s: profile %v families %v, want the profile's", p.Name, p.Spec.PeerProfileRef, p.Spec.AddressFamilies)
		}
		if len(p.Spec.FamilySettings) != 1 || !*p.Spec.FamilySettings[0].RouteReflectorClient {
			t.Errorf("%s: family settings %+v", p.Name, p.Spec.FamilySettings)
		}
	}
}

// TestNoSessionWithoutBothFamilies: an endpoint without an address in a
// family gets no session in it, and a member without any endpoint is
// reported, not peered.
func TestNoSessionWithoutBothFamilies(t *testing.T) {
	eps, routersA, _ := twoCells()
	routersA["lonely"] = router("lonely", nil)
	plan := generate(t, reflectionTopology(cellA, "rr", "c1", "lonely"), eps, routersA)
	for _, s := range plan.Sessions {
		remote := s.Peer.Annotations[networkv1alpha1.AnnotationRemoteEndpoint]
		if a, _ := netip.ParseAddr(s.Peer.Spec.Address); a.Is4() && remote == "b-c1-public" {
			t.Errorf("%s: an IPv4 session toward an IPv6-only endpoint", s.Peer.Name)
		}
	}
	if len(plan.MissingEndpoints) != 1 || !strings.Contains(plan.MissingEndpoints[0], "lonely") {
		t.Errorf("missing endpoints %v, want lonely", plan.MissingEndpoints)
	}
}

// TestAnalyzeConflicts: of two endpoints sharing an identity or an address,
// the one whose name sorts first keeps it, however recently it was created;
// the other is unusable. Endpoints of a local cell need
// their router with the same ASN; remote ones cannot be checked.
func TestAnalyzeConflicts(t *testing.T) {
	routers := routerMap(router("r1", nil), router("r2", nil))
	asn := endpoint("asn", cellA, "r2", transportM, "", "2001:db8:1::9", 0, nil)
	asn.Spec.ASN = 64999
	withIf := endpoint("if", cellB, "x", transportM, "", "fe80::1", 0, nil)
	withIf.Spec.Interface = ptr.To("eth0")
	eps := []networkv1alpha1.FabricEndpoint{
		endpoint("dup-b", cellA, "r1", transportM, "", "2001:db8:1::2", 0, nil),
		endpoint("dup-a", cellA, "r1", transportM, "", "2001:db8:1::1", 5, nil),
		endpoint("zz-addr", cellB, "r9", transportM, "", "2001:db8:1::1", 0, nil),
		endpoint("other-transport", cellB, "r9", transportP, "", "2001:db8:1::1", 5, nil),
		endpoint("ghost", cellA, "missing", transportM, "", "2001:db8:1::3", 0, nil),
		asn, withIf,
	}
	got := Analyze(eps, map[string]bool{cellA: true}, routers)
	for name, want := range map[string]struct {
		usable bool
		reason string
	}{
		"dup-a":           {true, networkv1alpha1.FabricEndpointReasonLocal},
		"dup-b":           {false, networkv1alpha1.FabricEndpointReasonDuplicate},
		"zz-addr":         {false, networkv1alpha1.FabricEndpointReasonAddressInUse},
		"other-transport": {true, networkv1alpha1.FabricEndpointReasonRemote},
		"ghost":           {false, networkv1alpha1.FabricEndpointReasonRouterNotFound},
		"asn":             {false, networkv1alpha1.FabricEndpointReasonASNMismatch},
		"if":              {false, networkv1alpha1.FabricEndpointReasonInterfaceUnsupported},
	} {
		s := got[name]
		if s.Usable != want.usable || s.ReadyReason != want.reason {
			t.Errorf("%s: usable %t reason %s, want %t %s", name, s.Usable, s.ReadyReason, want.usable, want.reason)
		}
	}
}

// TestNamesAreDeterministic: the same input names the same peers in the
// same order, whatever order the endpoints arrive in, and every name is a
// valid object name, however long its parts.
func TestNamesAreDeterministic(t *testing.T) {
	eps, routersA, _ := twoCells()
	topo := reflectionTopology(cellA, "rr", "c1")
	first := generate(t, topo, eps, routersA)
	reversed := append([]networkv1alpha1.FabricEndpoint(nil), eps...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	second := generate(t, topo, reversed, routersA)
	if len(first.Sessions) != len(second.Sessions) {
		t.Fatalf("%d then %d sessions", len(first.Sessions), len(second.Sessions))
	}
	for i := range first.Sessions {
		if first.Sessions[i].Peer.Name != second.Sessions[i].Peer.Name {
			t.Errorf("session %d: %s then %s", i, first.Sessions[i].Peer.Name, second.Sessions[i].Peer.Name)
		}
	}
	if got := first.Sessions[0].Peer.Name; got != peerName("c1", "a-rr-public", "ipv4") ||
		!strings.HasPrefix(got, "c1-a-rr-public-ipv4-") {
		t.Errorf("first name %s", got)
	}

	long := strings.Repeat("r", 200)
	n1, n2 := peerName(long, strings.Repeat("e", 200), "ipv6"), peerName(long, strings.Repeat("e", 200), "ipv4")
	if n1 == n2 || len(n1) > maxNameLength {
		t.Errorf("long names %d %q / %q", len(n1), n1[len(n1)-20:], n2[len(n2)-20:])
	}
	for _, n := range []string{n1, peerName("r", "ext", addressToken(netip.MustParseAddr("2001:db8::"))),
		peerName("r", "ext", addressToken(netip.MustParseAddr("::1")))} {
		if errs := validation.IsDNS1123Subdomain(n); len(errs) > 0 {
			t.Errorf("%q: %v", n, errs)
		}
	}
}

// TestOverlapKeepsFirst: two relationships generating one router and
// address keep the first and report the second.
func TestOverlapKeepsFirst(t *testing.T) {
	eps, routersA, _ := twoCells()
	topo := reflectionTopology(cellA, "rr", "c1")
	topo.Spec.Mesh = []networkv1alpha1.FabricMeshRelationship{{
		Name: "everyone", Transports: []string{transportP}, Families: both(),
		EndpointSelector: metav1.LabelSelector{},
	}}
	plan := generate(t, topo, eps, routersA)
	if len(plan.Overlaps) == 0 {
		t.Fatal("no overlap reported")
	}
	for _, s := range plan.Sessions {
		if !strings.HasPrefix(s.Peer.Annotations[networkv1alpha1.AnnotationRelationship], KindMesh+"/") {
			t.Errorf("%s came from %s, want the mesh, listed first", s.Peer.Name,
				s.Peer.Annotations[networkv1alpha1.AnnotationRelationship])
		}
	}
}

// TestExternal: external peers apply to the selected members only, run in
// their address's family, and need the source endpoint when sourced from
// it.
func TestExternal(t *testing.T) {
	eps, routersA, _ := twoCells()
	topo := reflectionTopology(cellA, "rr", "c1")
	topo.Spec.Reflection = nil
	topo.Spec.External = []networkv1alpha1.FabricExternalRelationship{{
		Name: extRel, Transport: ptr.To(transportP),
		UpdateSource: networkv1alpha1.FabricUpdateSourceEndpointAddress,
		Routers: networkv1alpha1.FabricTopologyMembers{
			Routers: []networkv1alpha1.LocalObjectRef{{Name: "c1"}, {Name: "not-a-member"}}},
		Peers: []networkv1alpha1.FabricExternalPeer{
			{Address: "203.0.113.1", ASN: 64999}, {Address: extPeer, ASN: 64999}},
	}}
	plan := generate(t, topo, eps, routersA)
	if len(plan.Sessions) != 2 {
		t.Fatalf("%d sessions, want c1's two", len(plan.Sessions))
	}
	for _, s := range plan.Sessions {
		p := s.Peer
		if p.Spec.RouterRef.Name != "c1" || p.Spec.PeerASN != 64999 {
			t.Errorf("%s: router %s asn %d", p.Name, p.Spec.RouterRef.Name, p.Spec.PeerASN)
		}
		a := netip.MustParseAddr(p.Spec.Address)
		src := netip.MustParseAddr(*p.Spec.UpdateSource)
		afi := networkv1alpha1.AFIIPv6
		if a.Is4() {
			afi = networkv1alpha1.AFIIPv4
		}
		if a.Is4() != src.Is4() || p.Spec.AddressFamilies[0].AFI != afi {
			t.Errorf("%s: address %s source %s families %v", p.Name, a, src, p.Spec.AddressFamilies)
		}
	}

	// Without an IPv4 address on the transport, the IPv4 peer is missing.
	eps[1].Spec.Addresses.IPv4 = nil
	plan = generate(t, topo, eps, routersA)
	if len(plan.Sessions) != 1 || len(plan.MissingEndpoints) != 1 {
		t.Errorf("%d sessions, missing %v; want the IPv6 one and a missing IPv4 source", len(plan.Sessions),
			plan.MissingEndpoints)
	}
}

// TestSessionLimit: a member over the limit is reported.
func TestSessionLimit(t *testing.T) {
	eps, routersA, _ := twoCells()
	topo := reflectionTopology(cellA, "rr", "c1")
	topo.Spec.MaxSessionsPerRouter = 2
	plan := generate(t, topo, eps, routersA)
	if fmt.Sprint(plan.OverLimit) != "[rr]" {
		t.Errorf("over limit %v, want [rr] with three sessions", plan.OverLimit)
	}
}

// TestOnlyLocalMembersGenerate: only records of the topology's cell whose
// router is a member generate peers. Another cell's router of the same
// name is a different router, and a router of this cell outside the
// members is neither a source nor a target.
func TestOnlyLocalMembersGenerate(t *testing.T) {
	routers := routerMap(router("a1", nil), router("a2", nil))
	eps := []networkv1alpha1.FabricEndpoint{
		endpoint("a1-mesh", cellA, "a1", transportM, "", a1v6, 0, nil),
		endpoint("a2-mesh", cellA, "a2", transportM, "", "fd00::2", 0, nil),
		endpoint("b-a1-mesh", cellB, "a1", transportM, "", "fd00::b1", 0, nil),
	}
	topo := reflectionTopology(cellA, "a1")
	topo.Spec.Reflection = nil
	topo.Spec.Mesh = []networkv1alpha1.FabricMeshRelationship{{
		Name: "all", Transports: []string{transportM}, Families: both(),
		UpdateSource: networkv1alpha1.FabricUpdateSourceEndpointAddress,
	}}
	plan := generate(t, topo, eps, routers)
	if len(plan.Sessions) != 1 {
		t.Fatalf("sessions %d, want a1's one toward cell-b's a1", len(plan.Sessions))
	}
	p := plan.Sessions[0].Peer
	if p.Name != peerName("a1", "b-a1-mesh", "ipv6") || p.Spec.Address != "fd00::b1" || *p.Spec.UpdateSource != a1v6 {
		t.Errorf("session %s toward %s from %s", p.Name, p.Spec.Address, *p.Spec.UpdateSource)
	}
}

// TestNamesNeverCollide: routers and records whose readable names join to
// the same string still get different peer names, and a plan that would
// hold two sessions under one name reports it instead.
func TestNamesNeverCollide(t *testing.T) {
	if a, b := peerName("a", "b-c", "ipv6"), peerName("a-b", "c", "ipv6"); a == b {
		t.Fatalf("a/b-c and a-b/c share the name %s", a)
	}
	routers := routerMap(router("a", nil), router("a-b", nil))
	eps := []networkv1alpha1.FabricEndpoint{
		endpoint("b-c", cellB, "x", transportM, "", a1v6, 0, nil),
		endpoint("c", cellB, "y", transportM, "", "fd00::2", 0, nil),
		endpoint("a-mesh", cellA, "a", transportM, "", "fd00::a", 0, nil),
		endpoint("a-b-mesh", cellA, "a-b", transportM, "", "fd00::ab", 0, nil),
	}
	topo := reflectionTopology(cellA, "a", "a-b")
	topo.Spec.Reflection = nil
	topo.Spec.Mesh = []networkv1alpha1.FabricMeshRelationship{{
		Name: "all", Transports: []string{transportM}, Families: both()}}
	plan := generate(t, topo, eps, routers)
	seen := map[string]bool{}
	for _, s := range plan.Sessions {
		if seen[s.Peer.Name] {
			t.Errorf("two sessions named %s", s.Peer.Name)
		}
		seen[s.Peer.Name] = true
	}
	if len(plan.Sessions) != 6 || len(plan.NameClashes) != 0 {
		t.Errorf("%d sessions, clashes %v; want 6 and none", len(plan.Sessions), plan.NameClashes)
	}

	// Two sessions forced onto one name: the second is reported, not kept.
	g := &generator{topo: topo, byKey: map[key]string{}, byName: map[string]key{}}
	for _, addr := range []string{a1v6, "fd00::2"} {
		p := &networkv1alpha1.BGPPeer{}
		p.Name = "same"
		p.Annotations = map[string]string{networkv1alpha1.AnnotationRelationship: "mesh/all"}
		g.add(p, "a", netip.MustParseAddr(addr))
	}
	if len(g.out.Sessions) != 1 || len(g.out.NameClashes) != 1 {
		t.Errorf("sessions %d clashes %v, want one of each", len(g.out.Sessions), g.out.NameClashes)
	}
}

// TestDigests: the same records and relationships give the same digests in
// every cell, whatever order the records arrive in; a changed record or
// relationship changes them.
func TestDigests(t *testing.T) {
	eps, routersA, routersB := twoCells()
	a := generate(t, reflectionTopology(cellA, "rr", "c1"), eps, routersA)
	if len(a.RecordsDigest) != 64 || len(a.RelationshipsDigest) != 64 {
		t.Fatalf("digests %q %q", a.RecordsDigest, a.RelationshipsDigest)
	}
	// Map iteration orders the records differently from run to run; every
	// run must agree.
	for i := range 50 {
		shuffled := []networkv1alpha1.FabricEndpoint{eps[i%3], eps[(i+1)%3], eps[(i+2)%3]}
		b := generate(t, reflectionTopology(cellB, "c1"), shuffled, routersB)
		if a.RecordsDigest != b.RecordsDigest || a.RelationshipsDigest != b.RelationshipsDigest {
			t.Fatalf("cells disagree: %s/%s, %s/%s", a.RecordsDigest, b.RecordsDigest, a.RelationshipsDigest,
				b.RelationshipsDigest)
		}
	}
	eps[0].Spec.Addresses.IPv6 = ptr.To("2001:db8:a::99")
	topo := reflectionTopology(cellA, "rr", "c1")
	topo.Spec.Reflection[0].Families = topo.Spec.Reflection[0].Families[1:]
	c := generate(t, topo, eps, routersA)
	if c.RecordsDigest == a.RecordsDigest || c.RelationshipsDigest == a.RelationshipsDigest {
		t.Error("a changed record and relationship kept the digests")
	}
}
