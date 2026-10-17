// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
)

// render writes the configuration. Within each FRR context the lines follow
// the order the previous renderer used, so a diff against a legacy file
// reads naturally; FRR itself treats the contexts as unordered.
func (c *compiler) render() string {
	w := &writer{}
	c.renderGlobal(w)
	c.renderStaticRoutes(w)
	c.renderRouterBGP(w)
	c.renderPrefixLists(w)
	c.renderCommunitySets(w)
	c.renderPolicies(w)
	return w.String()
}

type writer struct{ strings.Builder }

func (w *writer) line(format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
	w.WriteByte('\n')
}

func (c *compiler) renderGlobal(w *writer) {
	p := c.in.Parameters.Spec
	w.line("frr defaults %s", p.DefaultsProfile)
	w.line("hostname %s%s", c.in.Router.Spec.TargetRef.Name, p.HostnameSuffix)
	if p.LogFile != nil {
		w.line("log file %s %s", p.LogFile.Path, p.LogFile.Level)
	}
	w.line("!")
}

func (c *compiler) renderStaticRoutes(w *writer) {
	routes := append([]networkv1alpha1.BGPStaticRoute(nil), c.in.StaticRoutes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].Name < routes[j].Name })
	for _, sr := range routes {
		keyword := "ipv6 route"
		if sr.Spec.AddressFamily == networkv1alpha1.AFIIPv4 {
			keyword = "ip route"
		}
		target := "Null0"
		if sr.Spec.Action == networkv1alpha1.BGPStaticRouteNextHop {
			target = *sr.Spec.NextHop
		}
		w.line("%s %s %s", keyword, canonicalPrefix(sr.Spec.Destination), target)
	}
	w.line("!")
}

func (c *compiler) renderRouterBGP(w *writer) {
	r := c.in.Router.Spec
	p := c.in.Parameters.Spec
	w.line("router bgp %d", r.LocalASN)
	w.line(" bgp router-id %s", r.RouterID)
	if p.LogNeighborChanges {
		w.line(" bgp log-neighbor-changes")
	}
	if !p.IPv4UnicastDefault {
		w.line(" no bgp default ipv4-unicast")
	}
	if p.AllowMartianNexthop {
		w.line(" bgp allow-martian-nexthop")
	}

	for _, name := range sortedKeys(c.profiles) {
		c.renderProfileSession(w, c.profiles[name])
	}
	peers := c.sortedPeers()
	for i := range peers {
		c.renderPeerSession(w, &peers[i])
	}

	for _, f := range []family{
		{networkv1alpha1.AFIIPv4, networkv1alpha1.SAFIUnicast},
		{networkv1alpha1.AFIIPv6, networkv1alpha1.SAFIUnicast},
	} {
		if c.families[f] {
			c.renderAddressFamily(w, f, peers)
		}
	}
	for _, t := range p.BMPTargets {
		renderBMPTarget(w, t)
	}
	w.line("exit")
	w.line("!")
}

func (c *compiler) sortedPeers() []networkv1alpha1.BGPPeer {
	peers := append([]networkv1alpha1.BGPPeer(nil), c.in.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	return peers
}

func (c *compiler) renderProfileSession(w *writer, profile *networkv1alpha1.BGPPeerProfile) {
	group := profileName(profile)
	w.line(" neighbor %s peer-group", group)
	if profile.Spec.PeerASN != nil {
		w.line(" neighbor %s remote-as %d", group, *profile.Spec.PeerASN)
	}
	renderTransport(w, group, profile.Spec.Transport)
}

func (c *compiler) renderPeerSession(w *writer, p *networkv1alpha1.BGPPeer) {
	s := p.Spec
	profile := c.peerProfile(p)
	if profile == nil || profile.Spec.PeerASN == nil {
		w.line(" neighbor %s remote-as %d", s.Address, s.PeerASN)
	}
	if profile != nil {
		w.line(" neighbor %s peer-group %s", s.Address, profileName(profile))
	}
	if s.Description != "" {
		w.line(" neighbor %s description %s", s.Address, s.Description)
	}
	if s.UpdateSource != nil {
		w.line(" neighbor %s update-source %s", s.Address, *s.UpdateSource)
	}
	var inherited *networkv1alpha1.BGPPeerTransport
	if profile != nil {
		inherited = profile.Spec.Transport
	}
	renderTransport(w, s.Address, overriddenTransport(s.Transport, inherited))
}

func renderTransport(w *writer, who string, t *networkv1alpha1.BGPPeerTransport) {
	if t == nil {
		return
	}
	if t.EBGPMultihopTTL != nil {
		w.line(" neighbor %s ebgp-multihop %d", who, *t.EBGPMultihopTTL)
	}
	if t.AdvertisementIntervalSeconds != nil {
		w.line(" neighbor %s advertisement-interval %d", who, *t.AdvertisementIntervalSeconds)
	}
}

// overriddenTransport is the part of a peer's transport that differs from
// what it inherits.
func overriddenTransport(own, inherited *networkv1alpha1.BGPPeerTransport) *networkv1alpha1.BGPPeerTransport {
	if own == nil {
		return nil
	}
	if inherited == nil {
		return own
	}
	out := &networkv1alpha1.BGPPeerTransport{}
	if own.EBGPMultihopTTL != nil && !equalInt32(own.EBGPMultihopTTL, inherited.EBGPMultihopTTL) {
		out.EBGPMultihopTTL = own.EBGPMultihopTTL
	}
	if own.AdvertisementIntervalSeconds != nil &&
		!equalInt32(own.AdvertisementIntervalSeconds, inherited.AdvertisementIntervalSeconds) {
		out.AdvertisementIntervalSeconds = own.AdvertisementIntervalSeconds
	}
	return out
}

func (c *compiler) peerProfile(p *networkv1alpha1.BGPPeer) *networkv1alpha1.BGPPeerProfile {
	if p.Spec.PeerProfileRef == nil {
		return nil
	}
	return c.profiles[p.Spec.PeerProfileRef.Name]
}

func (c *compiler) renderAddressFamily(w *writer, f family, peers []networkv1alpha1.BGPPeer) {
	w.line(" address-family %s %s", f.afi, f.safi)

	advs := append([]networkv1alpha1.BGPAdvertisement(nil), c.in.Advertisements...)
	sort.Slice(advs, func(i, j int) bool { return advs[i].Name < advs[j].Name })
	for _, a := range advs {
		if a.Spec.AddressFamily.AFI != f.afi || a.Spec.AddressFamily.SAFI != f.safi {
			continue
		}
		routeMap := policyName(c.policies[a.Spec.PolicyRef.Name])
		for _, p := range a.Spec.Prefixes {
			w.line("  network %s route-map %s", canonicalPrefix(string(p)), routeMap)
		}
		if agg := a.Spec.Aggregation; agg != nil {
			opts := ""
			if agg.SummaryOnly {
				opts += " summary-only"
			}
			if agg.ASSet {
				opts += " as-set"
			}
			w.line("  aggregate-address %s%s route-map %s", canonicalPrefix(agg.Prefix), opts, routeMap)
		}
		for _, src := range a.Spec.Redistribute {
			w.line("  redistribute %s route-map %s", src, routeMap)
		}
	}

	for _, name := range sortedKeys(c.profiles) {
		profile := c.profiles[name]
		for i := range profile.Spec.AddressFamilies {
			fs := &profile.Spec.AddressFamilies[i]
			if fs.AFI == f.afi && fs.SAFI == f.safi {
				c.renderFamilySettings(w, profileName(profile), fs, true)
			}
		}
	}
	for i := range peers {
		p := &peers[i]
		profile := c.peerProfile(p)
		if !containsFamilyKey(peerFamilies(p, profile), f) {
			continue
		}
		own := ownFamilySettings(p, f)
		if profile == nil {
			if own == nil {
				own = &networkv1alpha1.BGPPeerFamilySettings{AFI: f.afi, SAFI: f.safi}
			}
			c.renderFamilySettings(w, p.Spec.Address, own, true)
			continue
		}
		if own != nil {
			c.renderFamilySettings(w, p.Spec.Address, overriddenFamily(own, profileFamily(profile, f)), false)
		}
	}
	w.line(" exit-address-family")
}

func ownFamilySettings(p *networkv1alpha1.BGPPeer, f family) *networkv1alpha1.BGPPeerFamilySettings {
	for i := range p.Spec.FamilySettings {
		fs := &p.Spec.FamilySettings[i]
		if fs.AFI == f.afi && fs.SAFI == f.safi {
			return fs
		}
	}
	return nil
}

func profileFamily(profile *networkv1alpha1.BGPPeerProfile, f family) *networkv1alpha1.BGPPeerFamilySettings {
	for i := range profile.Spec.AddressFamilies {
		fs := &profile.Spec.AddressFamilies[i]
		if fs.AFI == f.afi && fs.SAFI == f.safi {
			return fs
		}
	}
	return nil
}

func (c *compiler) renderFamilySettings(
	w *writer, who string, fs *networkv1alpha1.BGPPeerFamilySettings, activate bool,
) {
	if activate {
		w.line("  neighbor %s activate", who)
	}
	if fs.SoftReconfigurationInbound != nil && *fs.SoftReconfigurationInbound {
		w.line("  neighbor %s soft-reconfiguration inbound", who)
	}
	if l := fs.PrefixLimit; l != nil {
		line := fmt.Sprintf("  neighbor %s maximum-prefix %d", who, l.Maximum)
		if l.WarningThresholdPercent != nil {
			line += " " + strconv.Itoa(int(*l.WarningThresholdPercent))
		}
		switch l.Action {
		case networkv1alpha1.BGPPrefixLimitWarnOnly:
			line += " warning-only"
		case networkv1alpha1.BGPPrefixLimitRestart:
			line += " restart " + strconv.Itoa(int(*l.RestartMinutes))
		}
		w.line("%s", line)
	}
	if fs.SendCommunity != nil {
		// FRR sends every attribute by default; a restriction turns the
		// others off.
		for _, kind := range withheldCommunities(*fs.SendCommunity) {
			w.line("  no neighbor %s send-community %s", who, kind)
		}
	}
	if fs.AllowASIn != nil {
		w.line("  neighbor %s allowas-in %d", who, *fs.AllowASIn)
	}
	if fs.ImportPolicyRef != nil {
		w.line("  neighbor %s route-map %s in", who, policyName(c.policies[fs.ImportPolicyRef.Name]))
	}
	if fs.ExportPolicyRef != nil {
		w.line("  neighbor %s route-map %s out", who, policyName(c.policies[fs.ExportPolicyRef.Name]))
	}
	if fs.NextHopMode != nil && *fs.NextHopMode == networkv1alpha1.BGPNextHopSelf {
		w.line("  neighbor %s next-hop-self", who)
	}
	if fs.RouteReflectorClient != nil && *fs.RouteReflectorClient {
		w.line("  neighbor %s route-reflector-client", who)
	}
	if fs.FRR != nil && fs.FRR.Weight != nil {
		w.line("  neighbor %s weight %d", who, *fs.FRR.Weight)
	}
}

func renderBMPTarget(w *writer, t networkv1alpha1.BMPTarget) {
	w.line(" bmp targets %s", t.Name)
	connect := fmt.Sprintf("  bmp connect %s port %d", t.Connect.Address, t.Connect.Port)
	if t.Connect.MinRetryMilliseconds != nil {
		connect += fmt.Sprintf(" min-retry %d", *t.Connect.MinRetryMilliseconds)
	}
	if t.Connect.MaxRetryMilliseconds != nil {
		connect += fmt.Sprintf(" max-retry %d", *t.Connect.MaxRetryMilliseconds)
	}
	w.line("%s", connect)
	modes := map[networkv1alpha1.BMPMonitorMode]string{
		networkv1alpha1.BMPMonitorLocRIB:     "loc-rib",
		networkv1alpha1.BMPMonitorPrePolicy:  "pre-policy",
		networkv1alpha1.BMPMonitorPostPolicy: "post-policy",
	}
	for _, m := range t.Monitors {
		w.line("  bmp monitor %s %s %s", m.AFI, m.SAFI, modes[m.Mode])
	}
	w.line(" exit")
}

func (c *compiler) renderPrefixLists(w *writer) {
	for _, name := range sortedKeys(c.prefixLists) {
		pl := c.prefixLists[name]
		entries := append([]networkv1alpha1.BGPPrefixListEntry(nil), pl.Spec.Entries...)
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
		for _, e := range entries {
			keyword := "ipv6 prefix-list"
			if isIPv4Prefix(e.Prefix) {
				keyword = "ip prefix-list"
			}
			line := fmt.Sprintf("%s %s seq %d %s %s", keyword, prefixListName(pl), e.Sequence, e.Action,
				canonicalPrefix(e.Prefix))
			if e.GE != nil {
				line += fmt.Sprintf(" ge %d", *e.GE)
			}
			if e.LE != nil {
				line += fmt.Sprintf(" le %d", *e.LE)
			}
			w.line("%s", line)
		}
	}
	w.line("!")
}

func (c *compiler) renderCommunitySets(w *writer) {
	for _, name := range sortedKeys(c.communitySets) {
		cs := c.communitySets[name]
		keyword := "bgp community-list standard"
		if cs.Spec.Type == networkv1alpha1.BGPCommunitySetTypeLarge {
			keyword = "bgp large-community-list standard"
		}
		// FRR numbers the entries 5, 10, 15, ... and displays the numbers.
		for i, v := range cs.Spec.Entries {
			w.line("%s %s seq %d permit %s", keyword, communitySetName(cs), (i+1)*5, v)
		}
	}
	w.line("!")
}

func (c *compiler) renderPolicies(w *writer) {
	for _, name := range sortedKeys(c.policies) {
		p := c.policies[name]
		terms := append([]networkv1alpha1.BGPPolicyTerm(nil), p.Spec.Terms...)
		sort.SliceStable(terms, func(i, j int) bool { return terms[i].Sequence < terms[j].Sequence })
		for _, t := range terms {
			c.renderTerm(w, policyName(p), t)
		}
	}
}

func (c *compiler) renderTerm(w *writer, routeMap string, t networkv1alpha1.BGPPolicyTerm) {
	w.line("route-map %s %s %d", routeMap, t.Action, t.Sequence)
	if t.Description != "" {
		w.line(" description %s", t.Description)
	}
	m := t.Match
	if m.Interface != nil {
		w.line(" match interface %s", *m.Interface)
	}
	if m.PrefixListRef != nil {
		pl := c.prefixLists[m.PrefixListRef.Name]
		keyword := "ipv6"
		if len(pl.Spec.Entries) > 0 && isIPv4Prefix(pl.Spec.Entries[0].Prefix) {
			keyword = "ip"
		}
		w.line(" match %s address prefix-list %s", keyword, prefixListName(pl))
	}
	if m.CommunitySetRef != nil {
		w.line(" match community %s", communitySetName(c.communitySets[m.CommunitySetRef.Name]))
	}
	if m.LargeCommunitySetRef != nil {
		w.line(" match large-community %s", communitySetName(c.communitySets[m.LargeCommunitySetRef.Name]))
	}
	if s := t.Set; s != nil {
		if s.StandardCommunities != nil {
			w.line(" set community %s%s", strings.Join(frrtext.SortedStandard(s.StandardCommunities.Values), " "),
				additive(s.StandardCommunities.Operation))
		}
		if s.LargeCommunities != nil {
			w.line(" set large-community %s%s", strings.Join(frrtext.SortedLarge(s.LargeCommunities.Values), " "),
				additive(s.LargeCommunities.Operation))
		}
		if s.DeleteCommunitySetRef != nil {
			w.line(" set comm-list %s delete", communitySetName(c.communitySets[s.DeleteCommunitySetRef.Name]))
		}
		if s.DeleteLargeCommunitySetRef != nil {
			w.line(" set large-comm-list %s delete",
				communitySetName(c.communitySets[s.DeleteLargeCommunitySetRef.Name]))
		}
		if s.AsPath != nil && s.AsPath.Prepend != nil {
			asn := c.in.Router.Spec.LocalASN
			if s.AsPath.ASN != nil {
				asn = *s.AsPath.ASN
			}
			repeated := make([]string, *s.AsPath.Prepend)
			for i := range repeated {
				repeated[i] = strconv.FormatInt(asn, 10)
			}
			w.line(" set as-path prepend %s", strings.Join(repeated, " "))
		}
		if s.LocalPreference != nil {
			w.line(" set local-preference %d", *s.LocalPreference)
		}
	}
	w.line("exit")
	w.line("!")
}

func additive(op networkv1alpha1.CommunityOperation) string {
	if op == networkv1alpha1.CommunityOperationAdd {
		return " additive"
	}
	return ""
}

// canonicalPrefix writes a prefix the way FRR stores it, so a spelling with
// leading zeros does not read as a change.
func canonicalPrefix(s string) string {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return s
	}
	return p.Masked().String()
}

func isIPv4Prefix(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4()
}

func equalInt32(a, b *int32) bool {
	return a != nil && b != nil && *a == *b
}

func policyName(p *networkv1alpha1.BGPPolicy) string {
	if p.Spec.FRR != nil && p.Spec.FRR.RouteMapName != nil {
		return string(*p.Spec.FRR.RouteMapName)
	}
	return p.Name
}

func profileName(p *networkv1alpha1.BGPPeerProfile) string {
	if p.Spec.FRR != nil && p.Spec.FRR.PeerGroupName != nil {
		return string(*p.Spec.FRR.PeerGroupName)
	}
	return p.Name
}

func prefixListName(p *networkv1alpha1.BGPPrefixList) string {
	if p.Spec.FRR != nil && p.Spec.FRR.Name != nil {
		return string(*p.Spec.FRR.Name)
	}
	return p.Name
}

func communitySetName(cs *networkv1alpha1.BGPCommunitySet) string {
	if cs.Spec.FRR != nil && cs.Spec.FRR.Name != nil {
		return string(*cs.Spec.FRR.Name)
	}
	return cs.Name
}
