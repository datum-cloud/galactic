// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"net/netip"
	"reflect"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// policyUse is where a policy is attached, which decides what it may match.
type policyUse int

const (
	// usePeer is a peer family's import or export policy.
	usePeer policyUse = iota
	// useOrigination is a network statement's or aggregate's policy.
	useOrigination
	// useRedistribution is a redistribute statement's policy, the only use
	// an interface match means anything in.
	useRedistribution
)

func (c *compiler) validate() {
	if !c.validateRouter() {
		return
	}
	for i := range c.in.Peers {
		c.validatePeer(&c.in.Peers[i])
	}
	for i := range c.in.Advertisements {
		c.validateAdvertisement(&c.in.Advertisements[i])
	}
	for i := range c.in.StaticRoutes {
		c.validateStaticRoute(&c.in.StaticRoutes[i])
	}
	c.validateRetained()
	c.validateUniqueNames()
}

// validateRouter checks the router, its class and parameters. It reports
// whether the rest of the graph is worth checking.
func (c *compiler) validateRouter() bool {
	r := c.in.Router
	if r == nil {
		c.problems.add(ReasonInvalid, "BGPRouter/", "", "no router")
		return false
	}
	obj := objectName("BGPRouter", r.Name)
	if r.Spec.RouterClassName == nil {
		c.problems.add(ReasonInvalid, obj, "spec.routerClassName", "a fabric router must name a class")
		return false
	}
	switch {
	case c.in.Class == nil:
		c.problems.add(ReasonUnresolvedRef, obj, "spec.routerClassName", "BGPRouterClass %q not found",
			*r.Spec.RouterClassName)
		return false
	case c.in.Class.Spec.ControllerName != networkv1alpha1.FabricRouterControllerName:
		c.problems.add(ReasonInvalid, obj, "spec.routerClassName", "class %q belongs to controller %q",
			c.in.Class.Name, c.in.Class.Spec.ControllerName)
		return false
	case c.in.Parameters == nil:
		c.problems.add(ReasonUnresolvedRef, objectName("BGPRouterClass", c.in.Class.Name), "spec.parametersRef",
			"FRRRouterParameters not found")
		return false
	}
	if r.Spec.TargetRef.Kind != "" && r.Spec.TargetRef.Kind != "Node" {
		c.problems.add(ReasonInvalid, obj, "spec.targetRef.kind", "a fabric router targets a Node")
	}
	if !nodeName.MatchString(r.Spec.TargetRef.Name) {
		c.problems.add(ReasonInvalid, obj, "spec.targetRef.name", "%q is not a Node name", r.Spec.TargetRef.Name)
	}
	if r.Spec.Plane != nil && *r.Spec.Plane != networkv1alpha1.BGPRoutingPlaneUnderlay {
		c.problems.add(ReasonInvalid, obj, "spec.plane", "a fabric router is an Underlay router")
	}
	c.validateParameters()
	if r.Spec.ListenPort != nil {
		c.problems.unsupported(obj, "spec.listenPort", "bgpd's listen port is a daemon flag, not configuration")
	}
	if r.Spec.SRv6Locator != "" {
		c.problems.unsupported(obj, "spec.srv6Locator", "an EVPN overlay field")
	}
	if r.Spec.NodeID != 0 {
		c.problems.unsupported(obj, "spec.nodeID", "an EVPN overlay field")
	}
	if id, err := netip.ParseAddr(r.Spec.RouterID); err != nil || !id.Is4() {
		c.problems.add(ReasonInvalid, obj, "spec.routerID", "not an IPv4 address")
	}
	for _, af := range r.Spec.AddressFamilies {
		if !unicastFamily(af.AFI, af.SAFI) {
			c.problems.unsupported(obj, "spec.addressFamilies", "only ipv4 and ipv6 unicast are implemented")
			continue
		}
		c.families[family{af.AFI, af.SAFI}] = true
	}
	return true
}

// validateParameters checks the class parameters' rendered strings.
func (c *compiler) validateParameters() {
	p := c.in.Parameters.Spec
	obj := objectName("FRRRouterParameters", c.in.Parameters.Name)
	if p.DefaultsProfile != networkv1alpha1.FRRDefaultsTraditional {
		// FRR displays profile-specific defaults, such as datacenter's
		// use-underlays-nexthop-weight, that a reload of a file without
		// them would turn off.
		c.problems.unsupported(obj, "spec.defaultsProfile", "only the traditional profile is implemented")
	}
	if p.HostnameSuffix != "" && !frrToken.MatchString(p.HostnameSuffix) {
		c.problems.add(ReasonInvalid, obj, "spec.hostnameSuffix", "%q is not a hostname suffix", p.HostnameSuffix)
	}
	if p.LogFile != nil {
		c.token(obj, "spec.logFile.path", p.LogFile.Path)
		c.token(obj, "spec.logFile.level", string(p.LogFile.Level))
	}
	for _, t := range p.BMPTargets {
		c.token(obj, "spec.bmpTargets.name", string(t.Name))
		c.token(obj, "spec.bmpTargets.connect.address", t.Connect.Address)
	}
}

func unicastFamily(afi networkv1alpha1.AFI, safi networkv1alpha1.SAFI) bool {
	return (afi == networkv1alpha1.AFIIPv4 || afi == networkv1alpha1.AFIIPv6) && safi == networkv1alpha1.SAFIUnicast
}

func (c *compiler) validatePeer(p *networkv1alpha1.BGPPeer) {
	obj := objectName("BGPPeer", p.Name)
	s := &p.Spec
	rejected := map[string]bool{
		"spec.routerSelector":     s.RouterSelector != nil,
		"spec.ebgpMultiHop":       s.EbgpMultiHop,
		"spec.bfd":                s.BFD != nil,
		"spec.gracefulRestart":    s.GracefulRestart != nil,
		"spec.multiSession":       s.MultiSession,
		"spec.routeMapIn":         s.RouteMapIn != "",
		"spec.routeMapOut":        s.RouteMapOut != "",
		"spec.nextHopSelf":        s.NextHopSelf,
		"spec.removePrivateAS":    s.RemovePrivateAS != nil,
		"spec.sendCommunity":      s.SendCommunity != nil,
		"spec.allowASIn":          s.AllowASIn != nil,
		"spec.maximumPrefix":      s.MaximumPrefix != nil,
		"spec.defaultOriginRoute": s.DefaultOriginRoute != nil,
		"spec.authentication":     s.Authentication != nil,
		"spec.authSecretRef":      s.AuthSecretRef != nil,
		"spec.holdTime":           s.HoldTime != nil,
		"spec.keepaliveTime":      s.KeepaliveTime != nil,
		"spec.remotePort":         s.RemotePort != nil,
	}
	for field, set := range rejected {
		if set {
			c.problems.unsupported(obj, field, "not implemented by the FRR fabric router; use the typed equivalent")
		}
	}
	if addr, err := netip.ParseAddr(s.Address); err != nil {
		c.problems.add(ReasonInvalid, obj, "spec.address", "%q is not an address", s.Address)
	} else if other, dup := c.peerAddresses[addr]; dup {
		c.problems.add(ReasonInvalid, obj, "spec.address", "%s is also BGPPeer %s", addr, other)
	} else {
		c.peerAddresses[addr] = p.Name
	}
	c.text(obj, "spec.description", s.Description)
	if s.UpdateSource != nil {
		c.token(obj, "spec.updateSource", *s.UpdateSource)
	}

	var profile *networkv1alpha1.BGPPeerProfile
	if s.PeerProfileRef != nil {
		profile = c.resolveProfile(obj, "spec.peerProfileRef", s.PeerProfileRef.Name)
		if profile != nil && profile.Spec.PeerASN != nil && *profile.Spec.PeerASN != s.PeerASN {
			c.problems.add(ReasonInvalid, obj, "spec.peerASN", "differs from profile %s peerASN %d",
				profile.Name, *profile.Spec.PeerASN)
		}
	}

	for _, f := range peerFamilies(p, profile) {
		fobj := obj
		if !c.families[f] {
			c.problems.add(ReasonInvalid, fobj, "spec.addressFamilies", "%s %s is not one of the router's families",
				f.afi, f.safi)
		}
		eff := effectiveFamily(p, profile, f)
		if eff.ExportPolicyRef == nil {
			c.problems.add(ReasonInvalid, fobj, "spec.familySettings",
				"%s %s has no export policy; an implicit export-everything default is not allowed", f.afi, f.safi)
		} else {
			c.usePolicy(fobj, "exportPolicyRef", eff.ExportPolicyRef.Name, usePeer)
		}
		if eff.ImportPolicyRef != nil {
			c.usePolicy(fobj, "importPolicyRef", eff.ImportPolicyRef.Name, usePeer)
		}
	}
	if profile != nil && len(s.AddressFamilies) > 0 {
		for _, af := range profileFamilies(profile) {
			if !containsFamily(s.AddressFamilies, af) {
				c.problems.unsupported(obj, "spec.addressFamilies",
					"a peer activating fewer families than its profile is not implemented")
				break
			}
		}
		for _, af := range s.AddressFamilies {
			if !containsFamilyKey(profileFamilies(profile), family{af.AFI, af.SAFI}) {
				c.problems.add(ReasonInvalid, obj, "spec.addressFamilies",
					"%s %s is not one of profile %s's families", af.AFI, af.SAFI, profile.Name)
			}
		}
	}
	if profile != nil {
		for i := range s.FamilySettings {
			own := &s.FamilySettings[i]
			c.checkOverrides(obj, own, profileFamily(profile, family{own.AFI, own.SAFI}))
		}
	}
	for _, fs := range s.FamilySettings {
		f := family{fs.AFI, fs.SAFI}
		if !containsFamilyKey(peerFamilies(p, profile), f) {
			c.problems.add(ReasonInvalid, obj, "spec.familySettings", "%s %s is not one of the peer's families",
				f.afi, f.safi)
		}
	}
}

// checkOverrides refuses a peer setting that differs from its profile's
// where FRR cannot override a peer-group member: outbound settings are
// shared by the group's update group, and switching a group setting off on
// one member needs a negated line this renderer does not write. Import
// policy, prefix limit, allowas-in, weight, and turning soft
// reconfiguration on may differ.
func (c *compiler) checkOverrides(obj string, own, group *networkv1alpha1.BGPPeerFamilySettings) {
	field := "spec.familySettings"
	differs := func(a, b any) bool { return !reflect.DeepEqual(a, b) }
	var g networkv1alpha1.BGPPeerFamilySettings
	if group != nil {
		g = *group
	}
	if own.ExportPolicyRef != nil && differs(own.ExportPolicyRef, g.ExportPolicyRef) {
		c.problems.unsupported(obj, field+".exportPolicyRef", "a peer-group member shares the group's export policy")
	}
	if own.SendCommunity != nil && differs(own.SendCommunity, g.SendCommunity) {
		c.problems.unsupported(obj, field+".sendCommunity", "a peer-group member shares the group's community sending")
	}
	if own.NextHopMode != nil && differs(own.NextHopMode, g.NextHopMode) {
		c.problems.unsupported(obj, field+".nextHopMode", "a peer-group member shares the group's next-hop mode")
	}
	if own.RouteReflectorClient != nil && differs(own.RouteReflectorClient, g.RouteReflectorClient) {
		c.problems.unsupported(obj, field+".routeReflectorClient", "a peer-group member shares the group's reflector role")
	}
	if own.SoftReconfigurationInbound != nil && !*own.SoftReconfigurationInbound &&
		g.SoftReconfigurationInbound != nil && *g.SoftReconfigurationInbound {
		c.problems.unsupported(obj, field+".softReconfigurationInbound",
			"turning a group's soft reconfiguration off for one member is not implemented")
	}
}

// peerFamilies is the families a peer activates: its own list, or its
// profile's when it has none.
func peerFamilies(p *networkv1alpha1.BGPPeer, profile *networkv1alpha1.BGPPeerProfile) []family {
	if len(p.Spec.AddressFamilies) > 0 {
		out := make([]family, 0, len(p.Spec.AddressFamilies))
		for _, af := range p.Spec.AddressFamilies {
			out = append(out, family{af.AFI, af.SAFI})
		}
		return out
	}
	if profile == nil {
		return nil
	}
	return profileFamilies(profile)
}

func profileFamilies(profile *networkv1alpha1.BGPPeerProfile) []family {
	out := make([]family, 0, len(profile.Spec.AddressFamilies))
	for _, fs := range profile.Spec.AddressFamilies {
		out = append(out, family{fs.AFI, fs.SAFI})
	}
	return out
}

func containsFamily(list []networkv1alpha1.AddressFamily, f family) bool {
	for _, af := range list {
		if af.AFI == f.afi && af.SAFI == f.safi {
			return true
		}
	}
	return false
}

func containsFamilyKey(list []family, f family) bool {
	for _, x := range list {
		if x == f {
			return true
		}
	}
	return false
}

func (c *compiler) resolveProfile(obj, field, name string) *networkv1alpha1.BGPPeerProfile {
	profile, ok := c.in.Profiles[name]
	if !ok {
		c.problems.add(ReasonUnresolvedRef, obj, field, "BGPPeerProfile %q not found", name)
		return nil
	}
	if _, seen := c.profiles[name]; !seen {
		c.profiles[name] = profile
		c.validateProfile(profile)
	}
	return profile
}

func (c *compiler) validateProfile(profile *networkv1alpha1.BGPPeerProfile) {
	obj := objectName("BGPPeerProfile", profile.Name)
	c.token(obj, "spec.frr.peerGroupName", profileName(profile))
	for i := range profile.Spec.AddressFamilies {
		fs := &profile.Spec.AddressFamilies[i]
		if !unicastFamily(fs.AFI, fs.SAFI) {
			c.problems.unsupported(obj, "spec.addressFamilies", "only ipv4 and ipv6 unicast are implemented")
		} else if !c.families[family{fs.AFI, fs.SAFI}] {
			c.problems.add(ReasonInvalid, obj, "spec.addressFamilies", "%s %s is not one of the router's families",
				fs.AFI, fs.SAFI)
		}
		if fs.ImportPolicyRef != nil {
			c.usePolicy(obj, "importPolicyRef", fs.ImportPolicyRef.Name, usePeer)
		}
		if fs.ExportPolicyRef != nil {
			c.usePolicy(obj, "exportPolicyRef", fs.ExportPolicyRef.Name, usePeer)
		}
	}
}

func (c *compiler) validateAdvertisement(a *networkv1alpha1.BGPAdvertisement) {
	obj := objectName("BGPAdvertisement", a.Name)
	s := &a.Spec
	rejected := map[string]bool{
		"spec.originateFrom":   s.OriginateFrom != nil,
		"spec.communities":     len(s.Communities) > 0,
		"spec.localPreference": s.LocalPreference != nil,
		"spec.vrfID":           s.VRFID != nil,
		"spec.function":        s.Function != nil,
	}
	for field, set := range rejected {
		if set {
			c.problems.unsupported(obj, field, "an EVPN overlay field")
		}
	}
	f := family{s.AddressFamily.AFI, s.AddressFamily.SAFI}
	if !unicastFamily(f.afi, f.safi) {
		c.problems.unsupported(obj, "spec.addressFamily", "only ipv4 and ipv6 unicast are implemented")
		return
	}
	if !c.families[f] {
		c.problems.add(ReasonInvalid, obj, "spec.addressFamily", "%s %s is not one of the router's families",
			f.afi, f.safi)
	}
	if s.PolicyRef == nil {
		c.problems.add(ReasonInvalid, obj, "spec.policyRef", "a fabric advertisement needs a policy")
		return
	}
	kinds := 0
	for _, set := range []bool{len(s.Prefixes) > 0, len(s.Redistribute) > 0, s.Aggregation != nil} {
		if set {
			kinds++
		}
	}
	switch {
	case kinds == 0:
		c.problems.add(ReasonInvalid, obj, "spec", "advertises nothing: set prefixes, redistribute or aggregation")
	case kinds > 1:
		c.problems.add(ReasonInvalid, obj, "spec",
			"prefixes, redistribute and aggregation share one policy; split them into separate advertisements")
	}
	use := useOrigination
	if len(s.Redistribute) > 0 {
		use = useRedistribution
	}
	c.usePolicy(obj, "spec.policyRef", s.PolicyRef.Name, use)
	for _, p := range s.Prefixes {
		c.checkPrefixFamily(obj, "spec.prefixes", string(p), f.afi)
	}
	if s.Aggregation != nil {
		c.checkPrefixFamily(obj, "spec.aggregation.prefix", s.Aggregation.Prefix, f.afi)
	}
}

func (c *compiler) checkPrefixFamily(obj, field, prefix string, afi networkv1alpha1.AFI) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		c.problems.add(ReasonInvalid, obj, field, "%q is not a prefix", prefix)
		return
	}
	if p.Addr().Is4() != (afi == networkv1alpha1.AFIIPv4) {
		c.problems.add(ReasonInvalid, obj, field, "%s is not in %s", prefix, afi)
	}
}

func (c *compiler) validateStaticRoute(sr *networkv1alpha1.BGPStaticRoute) {
	obj := objectName("BGPStaticRoute", sr.Name)
	if sr.Spec.AddressFamily != networkv1alpha1.AFIIPv4 && sr.Spec.AddressFamily != networkv1alpha1.AFIIPv6 {
		c.problems.add(ReasonInvalid, obj, "spec.addressFamily", "must be ipv4 or ipv6")
		return
	}
	c.checkPrefixFamily(obj, "spec.destination", sr.Spec.Destination, sr.Spec.AddressFamily)
	if sr.Spec.Action == networkv1alpha1.BGPStaticRouteNextHop {
		addr, err := netip.ParseAddr(ptrString(sr.Spec.NextHop))
		if err != nil || addr.Is4() != (sr.Spec.AddressFamily == networkv1alpha1.AFIIPv4) {
			c.problems.add(ReasonInvalid, obj, "spec.nextHop", "must be an address in %s", sr.Spec.AddressFamily)
		}
	}
}

// usePolicy resolves a policy reference and checks the policy may be used as
// use.
func (c *compiler) usePolicy(obj, field, name string, use policyUse) {
	policy, ok := c.in.Policies[name]
	if !ok {
		c.problems.add(ReasonUnresolvedRef, obj, field, "BGPPolicy %q not found", name)
		return
	}
	if _, seen := c.policies[name]; !seen {
		c.policies[name] = policy
		c.validatePolicy(policy)
	}
	if use != useRedistribution {
		for _, t := range policy.Spec.Terms {
			if t.Match.Interface != nil {
				c.problems.add(ReasonInvalid, obj, field,
					"policy %s matches an interface, which only means something on a redistribution", name)
				break
			}
		}
	}
}

func (c *compiler) validatePolicy(p *networkv1alpha1.BGPPolicy) {
	obj := objectName("BGPPolicy", p.Name)
	if p.Spec.RouterRef != nil || p.Spec.RouterSelector != nil {
		c.problems.unsupported(obj, "spec.routerRef",
			"a fabric policy binds through the peer or advertisement that references it")
	}
	if p.Spec.Direction != "" {
		c.problems.unsupported(obj, "spec.direction", "a fabric policy takes its direction from its attachment")
	}
	c.token(obj, "spec.frr.routeMapName", policyName(p))
	sequences := map[int32]bool{}
	for _, t := range p.Spec.Terms {
		if sequences[t.Sequence] {
			c.problems.add(ReasonInvalid, obj, "spec.terms.sequence", "sequence %d is used twice", t.Sequence)
		}
		sequences[t.Sequence] = true
		c.text(obj, "spec.terms.description", t.Description)
		c.checkTermValues(obj, t)
		m, field := t.Match, "spec.terms.match"
		matchRejected := map[string]bool{
			"addressFamilies": len(m.AddressFamilies) > 0,
			"prefixList":      len(m.PrefixList) > 0,
			"asPathFilter":    m.ASPathFilter != nil,
			"communityMatch":  len(m.CommunityMatch) > 0,
			"evpnRouteType":   len(m.EVPNRouteType) > 0,
			"vni":             m.VNI != nil,
			"macAddress":      m.MACAddress != nil,
			"ipPrefix":        m.IPPrefix != nil,
			"localPreference": m.LocalPreference != nil,
			"med":             m.MED != nil,
		}
		for name, set := range matchRejected {
			if set {
				c.problems.unsupported(obj, field+"."+name, "use the set-reference matches")
			}
		}
		if m.PrefixListRef != nil {
			c.usePrefixList(obj, field+".prefixListRef", m.PrefixListRef.Name)
		}
		if m.CommunitySetRef != nil {
			c.useCommunitySet(obj, field+".communitySetRef", m.CommunitySetRef.Name,
				networkv1alpha1.BGPCommunitySetTypeStandard)
		}
		if m.LargeCommunitySetRef != nil {
			c.useCommunitySet(obj, field+".largeCommunitySetRef", m.LargeCommunitySetRef.Name,
				networkv1alpha1.BGPCommunitySetTypeLarge)
		}
		if t.Set == nil {
			continue
		}
		s, field := t.Set, "spec.terms.set"
		setRejected := map[string]bool{
			"communities":    s.Communities != nil,
			"extCommunities": s.ExtCommunities != nil,
			"origin":         s.Origin != nil,
			"nextHop":        s.NextHop != nil,
			"metric":         s.Metric != nil,
			"color":          s.Color != nil,
		}
		for name, set := range setRejected {
			if set {
				c.problems.unsupported(obj, field+"."+name, "not implemented by the FRR fabric router")
			}
		}
		if s.AsPath != nil && (len(s.AsPath.Replace) > 0 || s.AsPath.Prepend == nil) {
			c.problems.unsupported(obj, field+".asPath", "only prepend is implemented")
		}
		if s.DeleteCommunitySetRef != nil {
			c.useCommunitySet(obj, field+".deleteCommunitySetRef", s.DeleteCommunitySetRef.Name,
				networkv1alpha1.BGPCommunitySetTypeStandard)
		}
		if s.DeleteLargeCommunitySetRef != nil {
			c.useCommunitySet(obj, field+".deleteLargeCommunitySetRef", s.DeleteLargeCommunitySetRef.Name,
				networkv1alpha1.BGPCommunitySetTypeLarge)
		}
	}
}

// checkTermValues checks the free values a term renders.
func (c *compiler) checkTermValues(obj string, t networkv1alpha1.BGPPolicyTerm) {
	if t.Match.Interface != nil {
		c.token(obj, "spec.terms.match.interface", *t.Match.Interface)
	}
	if t.Set == nil {
		return
	}
	if t.Set.StandardCommunities != nil {
		for _, v := range t.Set.StandardCommunities.Values {
			c.token(obj, "spec.terms.set.standardCommunities.values", v)
		}
	}
	if t.Set.LargeCommunities != nil {
		for _, v := range t.Set.LargeCommunities.Values {
			c.token(obj, "spec.terms.set.largeCommunities.values", v)
		}
	}
}

func (c *compiler) usePrefixList(obj, field, name string) {
	pl, ok := c.in.PrefixLists[name]
	if !ok {
		c.problems.add(ReasonUnresolvedRef, obj, field, "BGPPrefixList %q not found", name)
		return
	}
	if _, seen := c.prefixLists[name]; !seen {
		c.prefixLists[name] = pl
		c.validatePrefixList(pl)
	}
}

func (c *compiler) validatePrefixList(pl *networkv1alpha1.BGPPrefixList) {
	obj := objectName("BGPPrefixList", pl.Name)
	c.token(obj, "spec.frr.name", prefixListName(pl))
	sequences := map[int64]bool{}
	var v4, v6 bool
	for _, e := range pl.Spec.Entries {
		if sequences[e.Sequence] {
			c.problems.add(ReasonInvalid, obj, "spec.entries.sequence", "sequence %d is used twice", e.Sequence)
		}
		sequences[e.Sequence] = true
		p, err := netip.ParsePrefix(e.Prefix)
		if err != nil {
			c.problems.add(ReasonInvalid, obj, "spec.entries.prefix", "%q is not a prefix", e.Prefix)
			continue
		}
		v4, v6 = v4 || p.Addr().Is4(), v6 || !p.Addr().Is4()
	}
	if v4 && v6 {
		c.problems.add(ReasonInvalid, obj, "spec.entries", "mixes IPv4 and IPv6 prefixes")
	}
}

// addCommunitySet records a set to render and checks its rendered values.
func (c *compiler) addCommunitySet(cs *networkv1alpha1.BGPCommunitySet) {
	if _, seen := c.communitySets[cs.Name]; seen {
		return
	}
	c.communitySets[cs.Name] = cs
	obj := objectName("BGPCommunitySet", cs.Name)
	c.token(obj, "spec.frr.name", communitySetName(cs))
	for _, v := range cs.Spec.Entries {
		c.token(obj, "spec.entries", v)
	}
}

func (c *compiler) useCommunitySet(obj, field, name string, want networkv1alpha1.BGPCommunitySetType) {
	cs, ok := c.in.CommunitySets[name]
	if !ok {
		c.problems.add(ReasonUnresolvedRef, obj, field, "BGPCommunitySet %q not found", name)
		return
	}
	if cs.Spec.Type != want {
		c.problems.add(ReasonInvalid, obj, field, "BGPCommunitySet %q is %s, want %s", name, cs.Spec.Type, want)
		return
	}
	c.addCommunitySet(cs)
}

// validateRetained resolves the definitions the router renders while
// unreferenced.
func (c *compiler) validateRetained() {
	if c.in.Router.Spec.FRR == nil || c.in.Router.Spec.FRR.Retain == nil {
		return
	}
	obj := objectName("BGPRouter", c.in.Router.Name)
	retain := c.in.Router.Spec.FRR.Retain
	for _, ref := range retain.PeerProfileRefs {
		profile := c.resolveProfile(obj, "spec.frr.retain.peerProfileRefs", ref.Name)
		// With no member to supply one, FRR needs the group's own ASN.
		if profile != nil && profile.Spec.PeerASN == nil && !c.memberProfiles[ref.Name] {
			c.problems.add(ReasonInvalid, objectName("BGPPeerProfile", ref.Name), "spec.peerASN",
				"a retained profile with no members needs a peerASN")
		}
	}
	for _, ref := range retain.PolicyRefs {
		// A retained policy is attached to nothing, so it may hold an
		// interface match.
		c.usePolicy(obj, "spec.frr.retain.policyRefs", ref.Name, useRedistribution)
	}
	for _, ref := range retain.PrefixListRefs {
		c.usePrefixList(obj, "spec.frr.retain.prefixListRefs", ref.Name)
	}
	for _, ref := range retain.CommunitySetRefs {
		cs, ok := c.in.CommunitySets[ref.Name]
		if !ok {
			c.problems.add(ReasonUnresolvedRef, obj, "spec.frr.retain.communitySetRefs",
				"BGPCommunitySet %q not found", ref.Name)
			continue
		}
		c.addCommunitySet(cs)
	}
}

// validateUniqueNames refuses two objects rendering under one FRR name.
func (c *compiler) validateUniqueNames() {
	check := func(kind string, names map[string]string, frrName, objName string) {
		if other, ok := names[frrName]; ok {
			c.problems.add(ReasonInvalid, objectName(kind, objName), "", "renders as %q, as does %s", frrName, other)
			return
		}
		names[frrName] = objName
	}
	routeMaps := map[string]string{}
	for _, name := range sortedKeys(c.policies) {
		check("BGPPolicy", routeMaps, policyName(c.policies[name]), name)
	}
	groups := map[string]string{}
	for _, name := range sortedKeys(c.profiles) {
		check("BGPPeerProfile", groups, profileName(c.profiles[name]), name)
	}
	lists := map[string]string{}
	for _, name := range sortedKeys(c.prefixLists) {
		check("BGPPrefixList", lists, prefixListName(c.prefixLists[name]), name)
	}
	// Standard and large community lists are separate FRR namespaces.
	sets := map[networkv1alpha1.BGPCommunitySetType]map[string]string{}
	for _, name := range sortedKeys(c.communitySets) {
		cs := c.communitySets[name]
		if sets[cs.Spec.Type] == nil {
			sets[cs.Spec.Type] = map[string]string{}
		}
		check("BGPCommunitySet", sets[cs.Spec.Type], communitySetName(cs), name)
	}
}

func ptrString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
