// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Relationship kinds, the prefix of AnnotationRelationship.
const (
	KindMesh       = "mesh"
	KindReflection = "reflection"
	KindExternal   = "external"
)

const (
	// maxNameLength is a Kubernetes object name's limit.
	maxNameLength = 253
	// nameHashLength is how many hex digits of a session's hash its name
	// carries.
	nameHashLength = 10
)

// Input is everything one topology's peers depend on.
type Input struct {
	Topology *networkv1alpha1.FabricTopology

	// Endpoints are the namespace's endpoints, as Analyze returned them.
	Endpoints map[string]*EndpointState

	// Routers are the namespace's BGPRouters by name.
	Routers map[string]*networkv1alpha1.BGPRouter

	// Profiles are the namespace's BGPPeerProfiles by name.
	Profiles map[string]*networkv1alpha1.BGPPeerProfile

	// NodeLabels are the labels of the Nodes members run on, by Node name.
	NodeLabels map[string]map[string]string
}

// Session is one peer the topology wants.
type Session struct {
	// Peer is the BGPPeer to write, without its owner reference.
	Peer *networkv1alpha1.BGPPeer
}

// Overlap is a session two relationships both generate; the first keeps it.
type Overlap struct {
	Router, Address, Kept, Dropped string
}

// Plan is what a topology wants.
type Plan struct {
	// Members are the member routers' names, sorted.
	Members []string

	// Sessions are the peers to hold, sorted by name.
	Sessions []Session

	// Overlaps are sessions dropped because an earlier relationship
	// generates the same router and address.
	Overlaps []Overlap

	// MissingEndpoints names members with no usable endpoint in the routing
	// domain, and external sessions whose source endpoint is missing.
	MissingEndpoints []string

	// NameClashes are sessions dropped because an earlier session of the
	// plan has the same name.
	NameClashes []string

	// OverLimit names members that would exceed MaxSessionsPerRouter.
	OverLimit []string

	// RecordsDigest and RelationshipsDigest identify the records and
	// relationships the plan came from.
	RecordsDigest, RelationshipsDigest string

	// Profiles and Policies are every name the relationships reference.
	Profiles, Policies []string
}

// Generate computes the peers a topology wants. It returns an error only for
// a selector that does not parse.
func Generate(in Input) (Plan, error) {
	g := &generator{in: in, topo: in.Topology, byKey: map[key]string{}, byName: map[string]key{}}
	if err := g.members(); err != nil {
		return Plan{}, err
	}
	g.localEndpoints()
	for i := range g.topo.Spec.Mesh {
		if err := g.mesh(&g.topo.Spec.Mesh[i]); err != nil {
			return Plan{}, err
		}
	}
	for i := range g.topo.Spec.Reflection {
		if err := g.reflection(&g.topo.Spec.Reflection[i]); err != nil {
			return Plan{}, err
		}
	}
	for i := range g.topo.Spec.External {
		if err := g.external(&g.topo.Spec.External[i]); err != nil {
			return Plan{}, err
		}
	}
	g.references()
	g.digests()
	return g.plan(), nil
}

type key struct {
	router string
	addr   netip.Addr
}

type generator struct {
	in     Input
	topo   *networkv1alpha1.FabricTopology
	out    Plan
	byKey  map[key]string
	byName map[string]key

	memberSet map[string]*networkv1alpha1.BGPRouter
	// local maps a member to its usable endpoints in the routing domain.
	local map[string][]*EndpointState
}

func (g *generator) members() error {
	set, err := selectRouters(g.topo.Spec.Members, g.in.Routers, nil)
	if err != nil {
		return fmt.Errorf("spec.members: %w", err)
	}
	g.memberSet = set
	for name := range set {
		g.out.Members = append(g.out.Members, name)
	}
	sort.Strings(g.out.Members)
	return nil
}

// selectRouters returns the fabric-class routers of routers, not being
// deleted, that m selects, restricted to within when it is not nil.
func selectRouters(
	m networkv1alpha1.FabricTopologyMembers, routers, within map[string]*networkv1alpha1.BGPRouter,
) (map[string]*networkv1alpha1.BGPRouter, error) {
	var sel labels.Selector
	if m.RouterSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(m.RouterSelector)
		if err != nil {
			return nil, err
		}
		sel = s
	}
	named := map[string]bool{}
	for _, r := range m.Routers {
		named[r.Name] = true
	}
	out := map[string]*networkv1alpha1.BGPRouter{}
	for name, r := range routers {
		if r.Spec.RouterClassName == nil || !r.DeletionTimestamp.IsZero() {
			continue
		}
		if within != nil && within[name] == nil {
			continue
		}
		if named[name] || (sel != nil && sel.Matches(labels.Set(r.Labels))) {
			out[name] = r
		}
	}
	return out, nil
}

// localEndpoints finds each member's usable endpoints in the routing
// domain, and records members with none.
func (g *generator) localEndpoints() {
	g.local = map[string][]*EndpointState{}
	for _, s := range g.domainEndpoints() {
		if g.isLocal(s) {
			g.local[s.Endpoint.Spec.RouterRef.Name] = append(g.local[s.Endpoint.Spec.RouterRef.Name], s)
		}
	}
	for _, m := range g.out.Members {
		if len(g.local[m]) == 0 {
			g.out.MissingEndpoints = append(g.out.MissingEndpoints, "router "+m)
		}
	}
}

// domainEndpoints are the usable endpoints of the topology's routing
// domain, sorted by name, leaving out endpoints of this cell whose router
// is not a member: no topology here generates their side.
func (g *generator) domainEndpoints() []*EndpointState {
	var out []*EndpointState
	for _, s := range g.in.Endpoints {
		ep := s.Endpoint
		if !s.Usable || ep.Spec.RoutingDomain != g.topo.Spec.RoutingDomain {
			continue
		}
		if ep.Spec.Cell == g.topo.Spec.Cell && g.memberSet[ep.Spec.RouterRef.Name] == nil {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint.Name < out[j].Endpoint.Name })
	return out
}

func (g *generator) isLocal(s *EndpointState) bool {
	return s.Endpoint.Spec.Cell == g.topo.Spec.Cell && g.memberSet[s.Endpoint.Spec.RouterRef.Name] != nil
}

// matching are the domain endpoints on one of transports that sel selects.
func (g *generator) matching(sel *metav1.LabelSelector, transports []string) ([]*EndpointState, error) {
	s, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return nil, err
	}
	on := map[string]bool{}
	for _, t := range transports {
		on[t] = true
	}
	var out []*EndpointState
	for _, e := range g.domainEndpoints() {
		if on[e.Endpoint.Spec.Transport] && s.Matches(labels.Set(e.Endpoint.Labels)) {
			out = append(out, e)
		}
	}
	return out, nil
}

func sameRouter(a, b *EndpointState) bool {
	return a.Endpoint.Spec.Cell == b.Endpoint.Spec.Cell && a.Endpoint.Spec.RouterRef.Name == b.Endpoint.Spec.RouterRef.Name
}

func (g *generator) mesh(rel *networkv1alpha1.FabricMeshRelationship) error {
	eps, err := g.matching(&rel.EndpointSelector, rel.Transports)
	if err != nil {
		return fmt.Errorf("mesh %s endpointSelector: %w", rel.Name, err)
	}
	for _, l := range eps {
		if !g.isLocal(l) {
			continue
		}
		for _, e := range eps {
			if e.Endpoint.Spec.Transport != l.Endpoint.Spec.Transport || sameRouter(l, e) {
				continue
			}
			g.pair(KindMesh+"/"+rel.Name, l, e, rel.Families, rel.UpdateSource, &rel.Settings, false)
		}
	}
	return nil
}

func (g *generator) reflection(rel *networkv1alpha1.FabricReflectionRelationship) error {
	reflectors, err := g.matching(&rel.ReflectorSelector, rel.Transports)
	if err != nil {
		return fmt.Errorf("reflection %s reflectorSelector: %w", rel.Name, err)
	}
	clients, err := g.matching(&rel.ClientSelector, rel.Transports)
	if err != nil {
		return fmt.Errorf("reflection %s clientSelector: %w", rel.Name, err)
	}
	name := KindReflection + "/" + rel.Name
	for _, pass := range []struct {
		from, to []*EndpointState
		settings *networkv1alpha1.FabricSessionSettings
		rrClient bool
	}{
		{reflectors, clients, &rel.Reflector, true},
		{clients, reflectors, &rel.Client, false},
	} {
		for _, l := range pass.from {
			if !g.isLocal(l) {
				continue
			}
			for _, e := range pass.to {
				if e.Endpoint.Spec.Transport != l.Endpoint.Spec.Transport || sameRouter(l, e) {
					continue
				}
				g.pair(name, l, e, rel.Families, rel.UpdateSource, pass.settings, pass.rrClient)
			}
		}
	}
	return nil
}

// pair generates the local endpoint l's sessions toward e, one per family
// both carry.
func (g *generator) pair(
	relationship string, l, e *EndpointState, families []networkv1alpha1.FabricSessionFamily,
	source networkv1alpha1.FabricUpdateSource, settings *networkv1alpha1.FabricSessionSettings, rrClient bool,
) {
	for _, f := range sortedFamilies(families) {
		local, ok1 := l.Address(f)
		remote, ok2 := e.Address(f)
		if !ok1 || !ok2 {
			continue
		}
		router := l.Endpoint.Spec.RouterRef.Name
		var src *netip.Addr
		if source != networkv1alpha1.FabricUpdateSourceNone {
			src = &local
		}
		peer := g.peer(peerName(router, e.Endpoint.Name, string(f)), router, e.Endpoint.Spec.ASN, remote, f,
			src, settings, rrClient)
		peer.Annotations[networkv1alpha1.AnnotationRelationship] = relationship
		peer.Annotations[networkv1alpha1.AnnotationLocalEndpoint] = l.Endpoint.Name
		peer.Annotations[networkv1alpha1.AnnotationRemoteEndpoint] = e.Endpoint.Name
		peer.Annotations[networkv1alpha1.AnnotationRemoteEndpointUID] = string(e.Endpoint.UID)
		peer.Annotations[networkv1alpha1.AnnotationRemoteRouter] = e.Endpoint.Spec.RouterRef.Name
		peer.Labels[networkv1alpha1.LabelPeerCell] = e.Endpoint.Spec.Cell
		if fd := g.failureDomain(e); fd != "" {
			peer.Labels[networkv1alpha1.LabelPeerFailureDomain] = fd
		}
		g.add(peer, router, remote)
	}
}

// failureDomain is the endpoint's own failure domain, or for a local
// endpoint without one, its router's Node label.
func (g *generator) failureDomain(e *EndpointState) string {
	if fd := e.Endpoint.Spec.FailureDomain; fd != nil {
		return *fd
	}
	if !g.isLocal(e) {
		return ""
	}
	router := g.memberSet[e.Endpoint.Spec.RouterRef.Name]
	return g.in.NodeLabels[router.Spec.TargetRef.Name][g.topo.Spec.FailureDomainLabel]
}

func (g *generator) external(rel *networkv1alpha1.FabricExternalRelationship) error {
	routers, err := selectRouters(rel.Routers, g.in.Routers, g.memberSet)
	if err != nil {
		return fmt.Errorf("external %s routers: %w", rel.Name, err)
	}
	names := make([]string, 0, len(routers))
	for name := range routers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, router := range names {
		for _, p := range rel.Peers {
			remote, err := netip.ParseAddr(p.Address)
			if err != nil {
				continue
			}
			f := networkv1alpha1.FabricSessionFamilyIPv6
			if remote.Is4() {
				f = networkv1alpha1.FabricSessionFamilyIPv4
			}
			var src *netip.Addr
			var source *EndpointState
			if rel.UpdateSource != networkv1alpha1.FabricUpdateSourceNone {
				source = g.localOn(router, rel.Transport)
				var a netip.Addr
				ok := false
				if source != nil {
					a, ok = source.Address(f)
				}
				if !ok {
					g.out.MissingEndpoints = append(g.out.MissingEndpoints,
						fmt.Sprintf("external %s: router %s has no %s endpoint on its transport", rel.Name, router, f))
					continue
				}
				src = &a
			}
			peer := g.peer(peerName(router, rel.Name, addressToken(remote)), router, p.ASN, remote, f, src,
				&rel.Settings, false)
			peer.Annotations[networkv1alpha1.AnnotationRelationship] = KindExternal + "/" + rel.Name
			if source != nil {
				peer.Annotations[networkv1alpha1.AnnotationLocalEndpoint] = source.Endpoint.Name
			}
			g.add(peer, router, remote)
		}
	}
	return nil
}

// localOn is the member's usable endpoint on transport, if it has one.
func (g *generator) localOn(router string, transport *string) *EndpointState {
	if transport == nil {
		return nil
	}
	for _, s := range g.local[router] {
		if s.Endpoint.Spec.Transport == *transport {
			return s
		}
	}
	return nil
}

// add keeps peer unless an earlier relationship generates the same router
// and address.
func (g *generator) add(peer *networkv1alpha1.BGPPeer, router string, remote netip.Addr) {
	k := key{router, remote}
	if kept, dup := g.byKey[k]; dup {
		g.out.Overlaps = append(g.out.Overlaps, Overlap{Router: router, Address: remote.String(), Kept: kept,
			Dropped: peer.Annotations[networkv1alpha1.AnnotationRelationship]})
		return
	}
	if other, clash := g.byName[peer.Name]; clash {
		g.out.NameClashes = append(g.out.NameClashes, fmt.Sprintf("%s for router %s toward %s and toward %s",
			peer.Name, router, other.addr, remote))
		return
	}
	g.byKey[k] = peer.Annotations[networkv1alpha1.AnnotationRelationship]
	g.byName[peer.Name] = k
	g.out.Sessions = append(g.out.Sessions, Session{Peer: peer})
}

// peer builds the generated BGPPeer's object.
func (g *generator) peer(
	name, router string, asn int64, remote netip.Addr, f networkv1alpha1.FabricSessionFamily,
	source *netip.Addr, settings *networkv1alpha1.FabricSessionSettings, rrClient bool,
) *networkv1alpha1.BGPPeer {
	p := &networkv1alpha1.BGPPeer{}
	p.Name, p.Namespace = name, g.topo.Namespace
	p.Labels = map[string]string{
		networkv1alpha1.LabelManagedBy:      networkv1alpha1.ManagedByFabricTopology,
		networkv1alpha1.LabelFabricTopology: g.topo.Name,
	}
	p.Annotations = map[string]string{networkv1alpha1.AnnotationFabricTopologyUID: string(g.topo.UID)}
	p.Spec.RouterRef = &networkv1alpha1.RouterRef{Name: router}
	p.Spec.PeerASN = asn
	p.Spec.Address = remote.String()
	if source != nil {
		s := source.String()
		p.Spec.UpdateSource = &s
	}
	if settings.Transport != nil {
		p.Spec.Transport = settings.Transport.DeepCopy()
	}
	unicast := networkv1alpha1.AddressFamily{AFI: networkv1alpha1.AFI(f), SAFI: networkv1alpha1.SAFIUnicast}
	active := []networkv1alpha1.AddressFamily{unicast}
	if settings.PeerProfileRef != nil {
		p.Spec.PeerProfileRef = &networkv1alpha1.LocalObjectRef{Name: settings.PeerProfileRef.Name}
		if profile := g.in.Profiles[settings.PeerProfileRef.Name]; profile != nil && len(profile.Spec.AddressFamilies) > 0 {
			active = active[:0]
			for _, pf := range profile.Spec.AddressFamilies {
				active = append(active, networkv1alpha1.AddressFamily{AFI: pf.AFI, SAFI: pf.SAFI})
			}
		}
		for i := range settings.FamilySettings {
			p.Spec.FamilySettings = append(p.Spec.FamilySettings, *settings.FamilySettings[i].DeepCopy())
		}
	} else {
		p.Spec.AddressFamilies = active
		for i := range settings.FamilySettings {
			if settings.FamilySettings[i].AFI == unicast.AFI && settings.FamilySettings[i].SAFI == unicast.SAFI {
				p.Spec.FamilySettings = append(p.Spec.FamilySettings, *settings.FamilySettings[i].DeepCopy())
			}
		}
	}
	if rrClient {
		for _, af := range active {
			fs := familySetting(&p.Spec.FamilySettings, af)
			fs.RouteReflectorClient = ptrTo(true)
		}
	}
	sort.Slice(p.Spec.FamilySettings, func(i, j int) bool {
		a, b := p.Spec.FamilySettings[i], p.Spec.FamilySettings[j]
		if a.AFI != b.AFI {
			return a.AFI < b.AFI
		}
		return a.SAFI < b.SAFI
	})
	return p
}

// familySetting returns the entry for af in list, adding it if missing.
func familySetting(
	list *[]networkv1alpha1.BGPPeerFamilySettings, af networkv1alpha1.AddressFamily,
) *networkv1alpha1.BGPPeerFamilySettings {
	for i := range *list {
		if (*list)[i].AFI == af.AFI && (*list)[i].SAFI == af.SAFI {
			return &(*list)[i]
		}
	}
	*list = append(*list, networkv1alpha1.BGPPeerFamilySettings{AFI: af.AFI, SAFI: af.SAFI})
	return &(*list)[len(*list)-1]
}

func ptrTo[T any](v T) *T { return &v }

// references collects every profile and policy the relationships name.
func (g *generator) references() {
	profiles, policies := map[string]bool{}, map[string]bool{}
	add := func(s *networkv1alpha1.FabricSessionSettings) {
		if s.PeerProfileRef != nil {
			profiles[s.PeerProfileRef.Name] = true
		}
		for _, f := range s.FamilySettings {
			if f.ImportPolicyRef != nil {
				policies[f.ImportPolicyRef.Name] = true
			}
			if f.ExportPolicyRef != nil {
				policies[f.ExportPolicyRef.Name] = true
			}
		}
	}
	for i := range g.topo.Spec.Mesh {
		add(&g.topo.Spec.Mesh[i].Settings)
	}
	for i := range g.topo.Spec.Reflection {
		add(&g.topo.Spec.Reflection[i].Reflector)
		add(&g.topo.Spec.Reflection[i].Client)
	}
	for i := range g.topo.Spec.External {
		add(&g.topo.Spec.External[i].Settings)
	}
	g.out.Profiles, g.out.Policies = sortedKeys(profiles), sortedKeys(policies)
}

func (g *generator) plan() Plan {
	sort.Slice(g.out.Sessions, func(i, j int) bool { return g.out.Sessions[i].Peer.Name < g.out.Sessions[j].Peer.Name })
	count := map[string]int32{}
	for _, s := range g.out.Sessions {
		count[s.Peer.Spec.RouterRef.Name]++
	}
	for _, m := range g.out.Members {
		if count[m] > g.topo.Spec.MaxSessionsPerRouter && g.topo.Spec.MaxSessionsPerRouter > 0 {
			g.out.OverLimit = append(g.out.OverLimit, m)
		}
	}
	return g.out
}

// digests hashes the domain's records and the relationships, so cells can
// tell whether they generate from the same ones.
func (g *generator) digests() {
	type record struct {
		Name string                             `json:"name"`
		Spec networkv1alpha1.FabricEndpointSpec `json:"spec"`
	}
	var records []record
	for _, s := range g.in.Endpoints {
		if s.Endpoint.Spec.RoutingDomain == g.topo.Spec.RoutingDomain {
			records = append(records, record{s.Endpoint.Name, s.Endpoint.Spec})
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	g.out.RecordsDigest = digest(records)
	g.out.RelationshipsDigest = digest(struct {
		RoutingDomain string                                         `json:"routingDomain"`
		Mesh          []networkv1alpha1.FabricMeshRelationship       `json:"mesh"`
		Reflection    []networkv1alpha1.FabricReflectionRelationship `json:"reflection"`
		External      []networkv1alpha1.FabricExternalRelationship   `json:"external"`
	}{g.topo.Spec.RoutingDomain, g.topo.Spec.Mesh, g.topo.Spec.Reflection, g.topo.Spec.External})
}

// digest is the SHA-256 of v's JSON encoding, which orders struct fields
// and map keys deterministically.
func digest(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("encode %T: %v", v, err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedFamilies(fs []networkv1alpha1.FabricSessionFamily) []networkv1alpha1.FabricSessionFamily {
	out := append([]networkv1alpha1.FabricSessionFamily(nil), fs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// addressToken spells an address as a name segment.
func addressToken(a netip.Addr) string {
	return strings.Trim(strings.NewReplacer(":", "-", ".", "-").Replace(a.String()), "-")
}

// peerName is a new generated peer's name: router-remote-suffix for
// reading, cut to fit, then a hash of the three parts. The readable part
// alone is ambiguous, since every part may contain '-'; the hash is taken
// over the parts kept apart, so different sessions never share a name.
func peerName(router, remote, suffix string) string {
	sum := sha256.Sum256([]byte(router + "\x00" + remote + "\x00" + suffix))
	hash := hex.EncodeToString(sum[:])[:nameHashLength]
	readable := router + "-" + remote + "-" + suffix
	if limit := maxNameLength - nameHashLength - 1; len(readable) > limit {
		readable = strings.TrimRight(readable[:limit], "-.")
	}
	return readable + "-" + hash
}
