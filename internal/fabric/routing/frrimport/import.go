// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package frrimport turns a rendered fabric frr.conf into the typed BGP
// resources that compile back to it. It is the migration path from a
// hand-rendered configuration to the typed API: compiling its output and
// comparing the result with the original file is the parity check.
//
// The importer is strict. Any line outside the constructs the conformance
// matrix covers is an error naming the line, so nothing is dropped silently.
package frrimport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Options names what the configuration itself does not say.
type Options struct {
	// Namespace receives every namespaced object.
	Namespace string
	// NodeName is the Node the router runs on; the router is named after it.
	NodeName string
	// RouterClassName is the class the router names.
	RouterClassName string
}

// Objects is one router's imported resources. Parameters is a spec only:
// parameters are shared by every router of a class, so naming and
// deduplicating them is the caller's choice.
type Objects struct {
	Router         *networkv1alpha1.BGPRouter
	Parameters     networkv1alpha1.FRRRouterParametersSpec
	Peers          []*networkv1alpha1.BGPPeer
	Profiles       []*networkv1alpha1.BGPPeerProfile
	Policies       []*networkv1alpha1.BGPPolicy
	PrefixLists    []*networkv1alpha1.BGPPrefixList
	CommunitySets  []*networkv1alpha1.BGPCommunitySet
	Advertisements []*networkv1alpha1.BGPAdvertisement
	StaticRoutes   []*networkv1alpha1.BGPStaticRoute
}

// Import parses r.
func Import(r io.Reader, opts Options) (*Objects, error) {
	p := newParser(opts)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		if err := p.line(sc.Text()); err != nil {
			return nil, fmt.Errorf("line %d %q: %w", n, strings.TrimSpace(sc.Text()), err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return p.finish()
}

type contextKind int

const (
	ctxTop contextKind = iota
	ctxBGP
	ctxAddressFamily
	ctxBMP
	ctxRouteMap
)

type parser struct {
	opts Options
	ctx  contextKind

	router   *networkv1alpha1.BGPRouter
	params   networkv1alpha1.FRRRouterParametersSpec
	sawIPv4D bool

	family    networkv1alpha1.AddressFamily
	bmp       *networkv1alpha1.BMPTarget
	routeMap  *networkv1alpha1.BGPPolicy
	term      *networkv1alpha1.BGPPolicyTerm
	hostname  string
	localASN  int64
	sawRouter bool

	// Keyed by FRR name, in first-seen order.
	profiles      map[string]*networkv1alpha1.BGPPeerProfile
	peers         map[string]*networkv1alpha1.BGPPeer
	policies      map[string]*networkv1alpha1.BGPPolicy
	prefixLists   map[string]*networkv1alpha1.BGPPrefixList
	communitySets map[string]*networkv1alpha1.BGPCommunitySet
	advs          map[string]*networkv1alpha1.BGPAdvertisement
	statics       []*networkv1alpha1.BGPStaticRoute
	order         map[string][]string

	// activated is the who|afi pairs with an activate line; withheld is the
	// community attributes `no ... send-community` turns off, by who|afi.
	activated map[string]bool
	withheld  map[string]map[string]bool

	// settings is every neighbor setting seen, as who|verb or
	// who|afi|verb.
	settings map[string]bool
}

func newParser(opts Options) *parser {
	return &parser{
		opts:          opts,
		profiles:      map[string]*networkv1alpha1.BGPPeerProfile{},
		peers:         map[string]*networkv1alpha1.BGPPeer{},
		policies:      map[string]*networkv1alpha1.BGPPolicy{},
		prefixLists:   map[string]*networkv1alpha1.BGPPrefixList{},
		communitySets: map[string]*networkv1alpha1.BGPCommunitySet{},
		advs:          map[string]*networkv1alpha1.BGPAdvertisement{},
		order:         map[string][]string{},
		activated:     map[string]bool{},
		withheld:      map[string]map[string]bool{},
		settings:      map[string]bool{},
	}
}

func (p *parser) remember(kind, key string) {
	p.order[kind] = append(p.order[kind], key)
}

func (p *parser) meta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: p.opts.Namespace}
}

// routeMapCommands are the commands FRR reads inside a route-map entry.
var routeMapCommands = map[string]bool{
	kwMatch: true, "set": true, "call": true, "on-match": true, "continue": true, kwDesc: true,
}

func (p *parser) line(raw string) error {
	trimmed := strings.TrimSpace(raw)
	// FRR reads a line starting with ! or # as a comment, wherever it is.
	if trimmed == "" || strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "#") {
		return nil
	}
	f := strings.Fields(trimmed)
	indented := raw[0] == ' '

	switch p.ctx {
	case ctxRouteMap:
		if trimmed == kwExit {
			p.ctx = ctxTop
			return nil
		}
		// FRR keeps a route-map command in the entry however it is
		// indented, and falls back to the top level for any other.
		if routeMapCommands[f[0]] {
			return p.routeMapLine(f, trimmed)
		}
		p.ctx = ctxTop
	case ctxBMP:
		if trimmed == kwExit {
			p.ctx = ctxBGP
			return nil
		}
		return p.bmpLine(f)
	case ctxAddressFamily:
		if trimmed == "exit-address-family" {
			p.ctx = ctxBGP
			return nil
		}
		return p.addressFamilyLine(f)
	case ctxBGP:
		if indented {
			return p.bgpLine(f, trimmed)
		}
		if trimmed == kwExit {
			p.ctx = ctxTop
			return nil
		}
		p.ctx = ctxTop
	}
	return p.topLine(f, trimmed)
}

func (p *parser) topLine(f []string, line string) error {
	switch {
	case len(f) == 3 && f[0] == "frr" && f[1] == "defaults":
		p.params.DefaultsProfile = networkv1alpha1.FRRDefaultsProfile(f[2])
	case len(f) == 2 && f[0] == "hostname":
		p.hostname = f[1]
	case len(f) >= 2 && f[0] == "log":
		return p.logLine(f)
	case line == "ip forwarding" || line == "ipv6 forwarding":
		// Zebra's command writes the kernel sysctl, which is host
		// configuration, and FRR never displays it while forwarding is on.
	case (f[0] == "ip" || f[0] == "ipv6") && len(f) >= 2 && f[1] == "route":
		return p.staticRoute(f)
	case (f[0] == "ip" || f[0] == "ipv6") && len(f) >= 2 && f[1] == "prefix-list":
		return p.prefixListLine(f)
	case len(f) >= 3 && f[0] == "bgp" && (f[1] == "community-list" || f[1] == "large-community-list"):
		return p.communityListLine(f)
	case len(f) == 3 && f[0] == "router" && f[1] == "bgp":
		return p.routerBGP(f[2])
	case len(f) == 4 && f[0] == "route-map":
		return p.routeMapHeader(f)
	default:
		return errUnsupported
	}
	return nil
}

// logLine handles a top-level `log file` or `log syslog` line.
func (p *parser) logLine(f []string) error {
	switch {
	case len(f) == 4 && f[1] == "file":
		p.params.LogFile = &networkv1alpha1.FRRLogFile{Path: f[2], Level: networkv1alpha1.FRRLogLevel(f[3])}
	case len(f) <= 3 && f[1] == "syslog":
		// FRR leaves the default level out of `log syslog`.
		level := networkv1alpha1.FRRLogLevelDebugging
		if len(f) == 3 {
			level = networkv1alpha1.FRRLogLevel(f[2])
		}
		p.params.LogSyslog = &level
	default:
		return errUnsupported
	}
	return nil
}

// FRR keywords the parser matches in more than one place.
const (
	kwBGP       = "bgp"
	kwBMP       = "bmp"
	kwCommunity = "community"
	kwDesc      = "description"
	kwExit      = "exit"
	kwIPv6      = "ipv6"
	kwLarge     = "large-community"
	kwMatch     = "match"
	kwNeighbor  = "neighbor"
	kwStandard  = "standard"
	kwPermit    = "permit"
	kwRouteMap  = "route-map"
	kwSet       = "set"
)

var errUnsupported = errors.New("not a construct the fabric conformance matrix covers")

func (p *parser) routerBGP(asn string) error {
	if p.sawRouter {
		return errors.New("a second router bgp")
	}
	n, err := strconv.ParseInt(asn, 10, 64)
	if err != nil {
		return err
	}
	p.sawRouter, p.localASN, p.ctx = true, n, ctxBGP
	p.router = &networkv1alpha1.BGPRouter{
		ObjectMeta: p.meta(p.opts.NodeName),
		Spec: networkv1alpha1.BGPRouterSpec{
			RouterClassName: ptr.To(p.opts.RouterClassName),
			Plane:           ptr.To(networkv1alpha1.BGPRoutingPlaneUnderlay),
			TargetRef:       networkv1alpha1.TargetRef{Kind: "Node", Name: p.opts.NodeName},
			LocalASN:        n,
		},
	}
	return nil
}

func (p *parser) bgpLine(f []string, line string) error {
	switch {
	case len(f) == 3 && f[0] == kwBGP && f[1] == "router-id":
		p.router.Spec.RouterID = f[2]
	case line == "bgp log-neighbor-changes":
		p.params.LogNeighborChanges = true
	case line == "no bgp default ipv4-unicast":
		p.sawIPv4D = true
	case line == "no bgp ebgp-requires-policy":
		p.params.EBGPRequiresPolicy = ptr.To(false)
	case line == "bgp ebgp-requires-policy":
		p.params.EBGPRequiresPolicy = ptr.To(true)
	case line == "bgp allow-martian-nexthop":
		p.params.AllowMartianNexthop = true
	case len(f) == 3 && f[0] == "address-family":
		af := networkv1alpha1.AddressFamily{AFI: networkv1alpha1.AFI(f[1]), SAFI: networkv1alpha1.SAFI(f[2])}
		unicast := af.SAFI == networkv1alpha1.SAFIUnicast
		if (af.AFI != networkv1alpha1.AFIIPv4 && af.AFI != networkv1alpha1.AFIIPv6) || !unicast {
			return errUnsupported
		}
		p.family, p.ctx = af, ctxAddressFamily
		p.router.Spec.AddressFamilies = append(p.router.Spec.AddressFamilies, af)
	case len(f) == 3 && f[0] == kwBMP && f[1] == "targets":
		p.params.BMPTargets = append(p.params.BMPTargets, networkv1alpha1.BMPTarget{
			Name: networkv1alpha1.FRRObjectName(f[2]),
		})
		p.bmp, p.ctx = &p.params.BMPTargets[len(p.params.BMPTargets)-1], ctxBMP
	case len(f) >= 3 && f[0] == kwNeighbor:
		return p.neighborSession(f, line)
	default:
		return errUnsupported
	}
	return nil
}

func (p *parser) isGroup(name string) bool {
	_, ok := p.profiles[name]
	return ok
}

func (p *parser) peer(addr string) (*networkv1alpha1.BGPPeer, error) {
	if pe, ok := p.peers[addr]; ok {
		return pe, nil
	}
	if _, err := netip.ParseAddr(addr); err != nil {
		return nil, fmt.Errorf("neighbor %q is neither a peer group nor an address", addr)
	}
	pe := &networkv1alpha1.BGPPeer{
		ObjectMeta: p.meta(objectName(p.opts.NodeName, addr)),
		Spec: networkv1alpha1.BGPPeerSpec{
			RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: p.opts.NodeName}},
			Address:      addr,
		},
	}
	p.peers[addr] = pe
	p.remember("peer", addr)
	return pe, nil
}

func (p *parser) neighborSession(f []string, line string) error {
	who, verb := f[1], f[2]
	if verb == "peer-group" && len(f) == 3 {
		if p.isGroup(who) {
			return fmt.Errorf("peer group %s defined twice", who)
		}
		p.profiles[who] = &networkv1alpha1.BGPPeerProfile{
			ObjectMeta: p.meta(objectName(who)),
			Spec:       networkv1alpha1.BGPPeerProfileSpec{FRR: &networkv1alpha1.BGPPeerProfileFRR{PeerGroupName: frrName(who)}},
		}
		p.remember("profile", who)
		return nil
	}

	if err := p.once(who + "|" + verb); err != nil {
		return err
	}
	var transport **networkv1alpha1.BGPPeerTransport
	var asn **int64
	var pe *networkv1alpha1.BGPPeer
	if p.isGroup(who) {
		profile := p.profiles[who]
		transport, asn = &profile.Spec.Transport, &profile.Spec.PeerASN
	} else {
		var err error
		if pe, err = p.peer(who); err != nil {
			return err
		}
		transport = &pe.Spec.Transport
	}

	switch {
	case verb == "remote-as" && len(f) == 4:
		n, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil {
			return err
		}
		if pe != nil {
			pe.Spec.PeerASN = n
		} else {
			*asn = &n
		}
	case verb == "peer-group" && len(f) == 4 && pe != nil:
		if !p.isGroup(f[3]) {
			return fmt.Errorf("peer group %s is not defined", f[3])
		}
		pe.Spec.PeerProfileRef = &networkv1alpha1.LocalObjectRef{Name: objectName(f[3])}
	case verb == kwDesc && pe != nil:
		pe.Spec.Description = strings.TrimSpace(strings.SplitN(line, " description ", 2)[1])
	case verb == "update-source" && len(f) == 4 && pe != nil:
		pe.Spec.UpdateSource = ptr.To(f[3])
	case verb == "ebgp-multihop" && len(f) == 4:
		n, err := strconv.ParseInt(f[3], 10, 32)
		if err != nil {
			return err
		}
		ensure(transport).EBGPMultihopTTL = ptr.To(int32(n))
	case verb == "advertisement-interval" && len(f) == 4:
		n, err := strconv.ParseInt(f[3], 10, 32)
		if err != nil {
			return err
		}
		ensure(transport).AdvertisementIntervalSeconds = ptr.To(int32(n))
	default:
		return errUnsupported
	}
	return nil
}

func ensure(t **networkv1alpha1.BGPPeerTransport) *networkv1alpha1.BGPPeerTransport {
	if *t == nil {
		*t = &networkv1alpha1.BGPPeerTransport{}
	}
	return *t
}

func (p *parser) addressFamilyLine(f []string) error {
	switch {
	case len(f) == 4 && f[0] == "network" && f[2] == kwRouteMap:
		a := p.advertisement("network", f[3], "")
		a.Spec.Prefixes = append(a.Spec.Prefixes, networkv1alpha1.Prefix(f[1]))
	case len(f) == 2 && f[0] == "network":
		a := p.advertisement("network", "", "")
		a.Spec.Prefixes = append(a.Spec.Prefixes, networkv1alpha1.Prefix(f[1]))
	case len(f) >= 2 && f[0] == "aggregate-address":
		routeMap, opts := "", f[2:]
		if len(f) >= 4 && f[len(f)-2] == kwRouteMap {
			routeMap, opts = f[len(f)-1], f[2:len(f)-2]
		}
		agg := &networkv1alpha1.BGPAggregation{Prefix: f[1]}
		for _, opt := range opts {
			switch opt {
			case "summary-only":
				agg.SummaryOnly = true
			case "as-set":
				agg.ASSet = true
			default:
				return errUnsupported
			}
		}
		p.advertisement("aggregate", routeMap, f[1]).Spec.Aggregation = agg
	case len(f) == 4 && f[0] == "redistribute" && f[2] == kwRouteMap:
		src := networkv1alpha1.RedistributeSource(f[1])
		if !slices.Contains([]networkv1alpha1.RedistributeSource{
			networkv1alpha1.RedistributeSourceConnected, networkv1alpha1.RedistributeSourceStatic,
			networkv1alpha1.RedistributeSourceKernel,
		}, src) {
			return errUnsupported
		}
		a := p.advertisement("redistribute", f[3], "")
		a.Spec.Redistribute = append(a.Spec.Redistribute, src)
	case len(f) >= 3 && f[0] == kwNeighbor:
		return p.neighborFamily(f)
	case len(f) == 5 && f[0] == "no" && f[1] == kwNeighbor && f[3] == "send-community":
		key := f[2] + "|" + string(p.family.AFI)
		if p.withheld[key] == nil {
			p.withheld[key] = map[string]bool{}
		}
		p.withheld[key][f[4]] = true
	default:
		return errUnsupported
	}
	return nil
}

// advertisement returns the advertisement for kind and route-map in the
// current family; each aggregate gets its own. An empty routeMap is a
// statement with no route-map, whose advertisement has no policy.
func (p *parser) advertisement(kind, routeMap, aggregate string) *networkv1alpha1.BGPAdvertisement {
	key := strings.Join([]string{string(p.family.AFI), kind, routeMap, aggregate}, "|")
	if a, ok := p.advs[key]; ok {
		return a
	}
	parts := []string{p.opts.NodeName, string(p.family.AFI), kind, routeMap}
	if aggregate != "" {
		parts = append(parts, aggregate)
	}
	a := &networkv1alpha1.BGPAdvertisement{
		ObjectMeta: p.meta(objectName(parts...)),
		Spec: networkv1alpha1.BGPAdvertisementSpec{
			RouterRef:     networkv1alpha1.RouterRef{Name: p.opts.NodeName},
			AddressFamily: p.family,
		},
	}
	if routeMap != "" {
		a.Spec.PolicyRef = &networkv1alpha1.AdvertisementPolicyRef{Name: objectName(routeMap)}
	}
	p.advs[key] = a
	p.remember("adv", key)
	return a
}

func (p *parser) neighborFamily(f []string) error {
	who, verb := f[1], f[2]
	var fs *networkv1alpha1.BGPPeerFamilySettings
	var pe *networkv1alpha1.BGPPeer
	if p.isGroup(who) {
		fs = familyIn(&p.profiles[who].Spec.AddressFamilies, p.family)
	} else {
		var err error
		if pe, err = p.peer(who); err != nil {
			return err
		}
		fs = familyIn(&pe.Spec.FamilySettings, p.family)
	}

	key := who + "|" + string(p.family.AFI)
	setting := key + "|" + verb
	if verb == kwRouteMap && len(f) == 5 {
		setting += "|" + f[4]
	}
	if err := p.once(setting); err != nil {
		return err
	}
	switch {
	case verb == "activate" && len(f) == 3:
		if pe != nil {
			if pe.Spec.PeerProfileRef != nil {
				return errors.New("activating a grouped peer on its own is not implemented")
			}
			pe.Spec.AddressFamilies = append(pe.Spec.AddressFamilies, p.family)
		}
		p.activated[key] = true
		return nil
	case verb == "send-community" && len(f) <= 4:
		// FRR 10 sends every community attribute by default and never
		// displays an enabling line, so it is a no-op.
		return nil
	}
	return familySetting(fs, verb, f[3:])
}

// familySetting applies one `neighbor X <verb> <args>` line inside an
// address family.
func familySetting(fs *networkv1alpha1.BGPPeerFamilySettings, verb string, args []string) error {
	number := func() (int32, error) {
		n, err := strconv.ParseInt(args[0], 10, 32)
		return int32(n), err
	}
	switch {
	case verb == "soft-reconfiguration" && len(args) == 1 && args[0] == "inbound":
		fs.SoftReconfigurationInbound = ptr.To(true)
	case verb == "maximum-prefix" && len(args) >= 1:
		limit, err := parsePrefixLimit(args)
		if err != nil {
			return err
		}
		fs.PrefixLimit = limit
	case verb == "allowas-in" && len(args) == 1:
		n, err := number()
		if err != nil {
			return err
		}
		fs.AllowASIn = &n
	case verb == kwRouteMap && len(args) == 2 && (args[1] == "in" || args[1] == "out"):
		ref := &networkv1alpha1.LocalObjectRef{Name: objectName(args[0])}
		if args[1] == "in" {
			fs.ImportPolicyRef = ref
		} else {
			fs.ExportPolicyRef = ref
		}
	case verb == "next-hop-self" && len(args) == 0:
		fs.NextHopMode = ptr.To(networkv1alpha1.BGPNextHopSelf)
	case verb == "next-hop-self" && len(args) == 1 && args[0] == "force":
		fs.NextHopMode = ptr.To(networkv1alpha1.BGPNextHopSelfForce)
	case verb == "route-reflector-client" && len(args) == 0:
		fs.RouteReflectorClient = ptr.To(true)
	case verb == "weight" && len(args) == 1:
		n, err := number()
		if err != nil {
			return err
		}
		fs.FRR = &networkv1alpha1.FRRPeerFamilySettings{Weight: &n}
	default:
		return errUnsupported
	}
	return nil
}

func familyIn(
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

func parsePrefixLimit(f []string) (*networkv1alpha1.BGPPrefixLimit, error) {
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return nil, err
	}
	limit := &networkv1alpha1.BGPPrefixLimit{Maximum: n, Action: networkv1alpha1.BGPPrefixLimitShutdown}
	rest := f[1:]
	if len(rest) > 0 {
		if pct, err := strconv.ParseInt(rest[0], 10, 32); err == nil {
			limit.WarningThresholdPercent = ptr.To(int32(pct))
			rest = rest[1:]
		}
	}
	switch {
	case len(rest) == 0:
	case len(rest) == 1 && rest[0] == "warning-only":
		limit.Action = networkv1alpha1.BGPPrefixLimitWarnOnly
	case len(rest) == 2 && rest[0] == "restart":
		m, err := strconv.ParseInt(rest[1], 10, 32)
		if err != nil {
			return nil, err
		}
		limit.Action, limit.RestartMinutes = networkv1alpha1.BGPPrefixLimitRestart, ptr.To(int32(m))
	default:
		return nil, errUnsupported
	}
	return limit, nil
}

func (p *parser) bmpLine(f []string) error {
	switch {
	case len(f) >= 5 && f[0] == kwBMP && f[1] == "connect" && f[3] == "port":
		port, err := strconv.ParseInt(f[4], 10, 32)
		if err != nil {
			return err
		}
		p.bmp.Connect = networkv1alpha1.BMPConnect{Address: f[2], Port: int32(port)}
		rest := f[5:]
		for len(rest) >= 2 {
			if rest[0] == "source-interface" {
				p.bmp.Connect.SourceInterface = ptr.To(rest[1])
				rest = rest[2:]
				continue
			}
			ms, err := strconv.ParseInt(rest[1], 10, 32)
			if err != nil {
				return err
			}
			switch rest[0] {
			case "min-retry":
				p.bmp.Connect.MinRetryMilliseconds = ptr.To(int32(ms))
			case "max-retry":
				p.bmp.Connect.MaxRetryMilliseconds = ptr.To(int32(ms))
			default:
				return errUnsupported
			}
			rest = rest[2:]
		}
		if len(rest) != 0 {
			return errUnsupported
		}
	case len(f) == 4 && f[0] == kwBMP && f[1] == "stats" && f[2] == "interval":
		ms, err := strconv.ParseInt(f[3], 10, 32)
		if err != nil {
			return err
		}
		p.bmp.StatsIntervalMilliseconds = ptr.To(int32(ms))
	case len(f) == 5 && f[0] == kwBMP && f[1] == "monitor":
		modes := map[string]networkv1alpha1.BMPMonitorMode{
			"loc-rib": networkv1alpha1.BMPMonitorLocRIB, "pre-policy": networkv1alpha1.BMPMonitorPrePolicy,
			"post-policy": networkv1alpha1.BMPMonitorPostPolicy,
		}
		mode, ok := modes[f[4]]
		if !ok {
			return errUnsupported
		}
		p.bmp.Monitors = append(p.bmp.Monitors, networkv1alpha1.BMPMonitor{
			AFI: networkv1alpha1.AFI(f[2]), SAFI: networkv1alpha1.SAFI(f[3]), Mode: mode,
		})
	default:
		return errUnsupported
	}
	return nil
}

func (p *parser) staticRoute(f []string) error {
	if len(f) != 4 {
		return errUnsupported
	}
	afi := networkv1alpha1.AFIIPv6
	if f[0] == "ip" {
		afi = networkv1alpha1.AFIIPv4
	}
	sr := &networkv1alpha1.BGPStaticRoute{
		ObjectMeta: p.meta(objectName(p.opts.NodeName, f[2])),
		Spec: networkv1alpha1.BGPStaticRouteSpec{
			RouterRef:     networkv1alpha1.RouterRef{Name: p.opts.NodeName},
			AddressFamily: afi,
			Destination:   f[2],
			Action:        networkv1alpha1.BGPStaticRouteDiscard,
		},
	}
	if f[3] != "Null0" {
		if _, err := netip.ParseAddr(f[3]); err != nil {
			return errUnsupported
		}
		sr.Spec.Action, sr.Spec.NextHop = networkv1alpha1.BGPStaticRouteNextHop, ptr.To(f[3])
	}
	p.statics = append(p.statics, sr)
	return nil
}

func (p *parser) prefixListLine(f []string) error {
	// ip|ipv6 prefix-list NAME seq N permit|deny PREFIX [ge G] [le L]
	if len(f) < 7 || f[3] != "seq" || (f[5] != kwPermit && f[5] != "deny") {
		return errUnsupported
	}
	seq, err := strconv.ParseInt(f[4], 10, 64)
	if err != nil {
		return err
	}
	entry := networkv1alpha1.BGPPrefixListEntry{
		Sequence: seq, Action: networkv1alpha1.BGPPolicyAction(f[5]), Prefix: f[6],
	}
	for rest := f[7:]; len(rest) > 0; rest = rest[2:] {
		if len(rest) < 2 {
			return errUnsupported
		}
		n, err := strconv.ParseInt(rest[1], 10, 32)
		if err != nil {
			return err
		}
		switch rest[0] {
		case "ge":
			entry.GE = ptr.To(int32(n))
		case "le":
			entry.LE = ptr.To(int32(n))
		default:
			return errUnsupported
		}
	}
	name := f[2]
	pl, ok := p.prefixLists[name]
	if !ok {
		pl = &networkv1alpha1.BGPPrefixList{
			ObjectMeta: p.meta(objectName(name)),
			Spec:       networkv1alpha1.BGPPrefixListSpec{FRR: &networkv1alpha1.FRRNameOverride{Name: frrName(name)}},
		}
		p.prefixLists[name] = pl
		p.remember("prefixList", name)
	}
	pl.Spec.Entries = append(pl.Spec.Entries, entry)
	return nil
}

func (p *parser) communityListLine(f []string) error {
	// bgp [large-]community-list standard NAME permit VALUE
	if len(f) != 6 || f[2] != kwStandard || f[4] != kwPermit {
		return errUnsupported
	}
	kind := networkv1alpha1.BGPCommunitySetTypeStandard
	if f[1] == "large-community-list" {
		kind = networkv1alpha1.BGPCommunitySetTypeLarge
	}
	key := string(kind) + "|" + f[3]
	cs, ok := p.communitySets[key]
	if !ok {
		cs = &networkv1alpha1.BGPCommunitySet{
			ObjectMeta: p.meta(objectName(f[3])),
			Spec: networkv1alpha1.BGPCommunitySetSpec{
				FRR: &networkv1alpha1.FRRNameOverride{Name: frrName(f[3])}, Type: kind,
			},
		}
		p.communitySets[key] = cs
		p.remember("communitySet", key)
	}
	cs.Spec.Entries = append(cs.Spec.Entries, f[5])
	return nil
}

func (p *parser) routeMapHeader(f []string) error {
	name := f[1]
	seq, err := strconv.ParseInt(f[3], 10, 32)
	if err != nil || (f[2] != kwPermit && f[2] != "deny") {
		return errUnsupported
	}
	pol, ok := p.policies[name]
	if !ok {
		pol = &networkv1alpha1.BGPPolicy{
			ObjectMeta: p.meta(objectName(name)),
			Spec:       networkv1alpha1.BGPPolicySpec{FRR: &networkv1alpha1.BGPPolicyFRR{RouteMapName: frrName(name)}},
		}
		p.policies[name] = pol
		p.remember("policy", name)
	}
	pol.Spec.Terms = append(pol.Spec.Terms, networkv1alpha1.BGPPolicyTerm{
		Sequence: int32(seq), Action: networkv1alpha1.BGPPolicyAction(f[2]),
	})
	p.routeMap, p.term, p.ctx = pol, &pol.Spec.Terms[len(pol.Spec.Terms)-1], ctxRouteMap
	return nil
}

func (p *parser) routeMapLine(f []string, line string) error {
	switch f[0] {
	case kwDesc:
		p.term.Description = strings.TrimSpace(strings.TrimPrefix(line, kwDesc))
		return nil
	case kwMatch:
		return p.matchLine(f[1:])
	case kwSet:
		if p.term.Set == nil {
			p.term.Set = &networkv1alpha1.BGPPolicySetActions{}
		}
		return p.setLine(p.term.Set, f[1:])
	}
	return errUnsupported
}

// matchLine handles a route-map `match` line without its keyword.
func (p *parser) matchLine(f []string) error {
	m := &p.term.Match
	once := func(set bool) error {
		if set {
			return errors.New("a second match of the same kind is not implemented")
		}
		return nil
	}
	if err := once((len(f) == 4 && m.PrefixListRef != nil) ||
		(len(f) == 2 && f[0] == kwCommunity && m.CommunitySetRef != nil) ||
		(len(f) == 2 && f[0] == kwLarge && m.LargeCommunitySetRef != nil) ||
		(len(f) == 2 && f[0] == "interface" && m.Interface != nil)); err != nil {
		return err
	}
	switch {
	case len(f) == 4 && (f[0] == "ip" || f[0] == kwIPv6) && f[1] == "address" && f[2] == "prefix-list":
		m.PrefixListRef = &networkv1alpha1.LocalObjectRef{Name: objectName(f[3])}
	case len(f) == 2 && f[0] == kwCommunity:
		m.CommunitySetRef = &networkv1alpha1.LocalObjectRef{Name: objectName(f[1])}
	case len(f) == 2 && f[0] == kwLarge:
		m.LargeCommunitySetRef = &networkv1alpha1.LocalObjectRef{Name: objectName(f[1])}
	case len(f) == 2 && f[0] == "interface":
		m.Interface = ptr.To(f[1])
	default:
		return errUnsupported
	}
	return nil
}

// setLine handles a route-map `set` line without its keyword.
func (p *parser) setLine(s *networkv1alpha1.BGPPolicySetActions, f []string) error {
	if len(f) > 0 {
		repeated := map[string]bool{
			kwCommunity:        s.StandardCommunities != nil,
			kwLarge:            s.LargeCommunities != nil,
			"comm-list":        s.DeleteCommunitySetRef != nil,
			"large-comm-list":  s.DeleteLargeCommunitySetRef != nil,
			"as-path":          s.AsPath != nil,
			"local-preference": s.LocalPreference != nil,
			"src":              s.Source != nil,
		}[f[0]]
		if repeated {
			return errors.New("a second set of the same kind is not implemented")
		}
	}
	switch {
	case len(f) >= 2 && (f[0] == kwCommunity || f[0] == kwLarge):
		values, op := f[1:], networkv1alpha1.CommunityOperationReplace
		if values[len(values)-1] == "additive" {
			values, op = values[:len(values)-1], networkv1alpha1.CommunityOperationAdd
		}
		if len(values) == 0 || slices.Contains(values, "none") {
			return errUnsupported
		}
		if f[0] == kwCommunity {
			s.StandardCommunities = &networkv1alpha1.StandardCommunityAction{Operation: op, Values: values}
		} else {
			s.LargeCommunities = &networkv1alpha1.LargeCommunityAction{Operation: op, Values: values}
		}
	case len(f) == 3 && f[0] == "comm-list" && f[2] == "delete":
		s.DeleteCommunitySetRef = &networkv1alpha1.LocalObjectRef{Name: objectName(f[1])}
	case len(f) == 3 && f[0] == "large-comm-list" && f[2] == "delete":
		s.DeleteLargeCommunitySetRef = &networkv1alpha1.LocalObjectRef{Name: objectName(f[1])}
	case len(f) >= 3 && f[0] == "as-path" && f[1] == "prepend":
		ap, err := p.prepend(f[2:])
		if err != nil {
			return err
		}
		s.AsPath = ap
	case len(f) == 2 && f[0] == "local-preference":
		n, err := strconv.ParseInt(f[1], 10, 32)
		if err != nil {
			return err
		}
		s.LocalPreference = ptr.To(int32(n))
	case len(f) == 2 && f[0] == "src":
		if _, err := netip.ParseAddr(f[1]); err != nil {
			return err
		}
		s.Source = ptr.To(f[1])
	default:
		return errUnsupported
	}
	return nil
}

// prepend reads `set as-path prepend A A A`; the ASN is left unset when it
// is the router's own.
func (p *parser) prepend(asns []string) (*networkv1alpha1.AsPathSet, error) {
	for _, a := range asns {
		if a != asns[0] {
			return nil, errors.New("prepending different ASNs is not implemented")
		}
	}
	asn, err := strconv.ParseInt(asns[0], 10, 64)
	if err != nil {
		return nil, err
	}
	ap := &networkv1alpha1.AsPathSet{Prepend: ptr.To(uint32(len(asns)))}
	if asn != p.localASN {
		ap.ASN = &asn
	}
	return ap, nil
}

// once refuses a neighbor setting given twice: FRR keeps the last value,
// and importing it would silently drop the first.
func (p *parser) once(setting string) error {
	if p.settings[setting] {
		return errors.New("the same neighbor setting appears twice")
	}
	p.settings[setting] = true
	return nil
}

// applyWithheld turns `no neighbor X send-community <type>` lines into the
// restriction they express.
func (p *parser) applyWithheld() error {
	for key, off := range p.withheld {
		who, afi, _ := strings.Cut(key, "|")
		var sent []string
		for _, kind := range []string{kwStandard, "extended", "large"} {
			if !off[kind] {
				sent = append(sent, kind)
			}
		}
		kinds := map[string]networkv1alpha1.SendCommunityType{
			kwStandard: networkv1alpha1.SendCommunityTypeStandard, "extended": networkv1alpha1.SendCommunityTypeExtended,
			"large": networkv1alpha1.SendCommunityTypeLarge, "standard,extended": networkv1alpha1.SendCommunityTypeBoth,
		}
		kind, ok := kinds[strings.Join(sent, ",")]
		if !ok {
			return fmt.Errorf("neighbor %s sends %v communities in %s, which the API cannot express", who, sent, afi)
		}
		af := networkv1alpha1.AddressFamily{AFI: networkv1alpha1.AFI(afi), SAFI: networkv1alpha1.SAFIUnicast}
		if p.isGroup(who) {
			familyIn(&p.profiles[who].Spec.AddressFamilies, af).SendCommunity = &kind
			continue
		}
		pe, err := p.peer(who)
		if err != nil {
			return err
		}
		familyIn(&pe.Spec.FamilySettings, af).SendCommunity = &kind
	}
	return nil
}

// finish resolves names and the retained definitions.
func (p *parser) finish() (*Objects, error) {
	if p.router == nil {
		return nil, errors.New("no router bgp")
	}
	if p.ctx != ctxTop && p.ctx != ctxBGP {
		return nil, errors.New("the configuration ends inside a block")
	}
	if err := p.applyWithheld(); err != nil {
		return nil, err
	}
	for _, k := range p.order["profile"] {
		for _, fs := range p.profiles[k].Spec.AddressFamilies {
			if !p.activated[k+"|"+string(fs.AFI)] {
				return nil, fmt.Errorf("peer group %s has %s settings but is not activated there", k, fs.AFI)
			}
		}
	}
	p.params.IPv4UnicastDefault = !p.sawIPv4D
	if p.hostname != "" {
		suffix, ok := strings.CutPrefix(p.hostname, p.opts.NodeName)
		if !ok || (suffix != "" && suffix[0] != '-' && suffix[0] != '.') {
			return nil, fmt.Errorf("hostname %q is not node name %q with a suffix", p.hostname, p.opts.NodeName)
		}
		p.params.HostnameSuffix = suffix
	}

	out := &Objects{Router: p.router, Parameters: p.params, StaticRoutes: p.statics}
	for _, k := range p.order["profile"] {
		out.Profiles = append(out.Profiles, p.profiles[k])
	}
	for _, k := range p.order["peer"] {
		pe := p.peers[k]
		if err := p.completePeer(pe); err != nil {
			return nil, err
		}
		out.Peers = append(out.Peers, pe)
	}
	for _, k := range p.order["policy"] {
		out.Policies = append(out.Policies, p.policies[k])
	}
	for _, k := range p.order["prefixList"] {
		out.PrefixLists = append(out.PrefixLists, p.prefixLists[k])
	}
	for _, k := range p.order["communitySet"] {
		out.CommunitySets = append(out.CommunitySets, p.communitySets[k])
	}
	for _, k := range p.order["adv"] {
		out.Advertisements = append(out.Advertisements, p.advs[k])
	}
	if err := uniqueNames(out); err != nil {
		return nil, err
	}
	out.Router.Spec.FRR = &networkv1alpha1.BGPRouterFRR{Retain: retained(out)}
	return out, nil
}

// completePeer fills the remote ASN a grouped peer inherits and drops
// family settings that hold only the family key.
func (p *parser) completePeer(pe *networkv1alpha1.BGPPeer) error {
	if pe.Spec.PeerASN == 0 && pe.Spec.PeerProfileRef != nil {
		for _, profile := range p.profiles {
			if profile.Name == pe.Spec.PeerProfileRef.Name && profile.Spec.PeerASN != nil {
				pe.Spec.PeerASN = *profile.Spec.PeerASN
			}
		}
	}
	if pe.Spec.PeerASN == 0 {
		return fmt.Errorf("neighbor %s has no remote-as", pe.Spec.Address)
	}
	if pe.Spec.PeerProfileRef == nil && len(pe.Spec.AddressFamilies) == 0 {
		return fmt.Errorf("neighbor %s activates no address family", pe.Spec.Address)
	}
	kept := pe.Spec.FamilySettings[:0]
	for _, fs := range pe.Spec.FamilySettings {
		if !reflect.DeepEqual(networkv1alpha1.BGPPeerFamilySettings{AFI: fs.AFI, SAFI: fs.SAFI}, fs) {
			kept = append(kept, fs)
		}
	}
	pe.Spec.FamilySettings = kept
	if len(kept) == 0 {
		pe.Spec.FamilySettings = nil
	}
	return nil
}

func uniqueNames(o *Objects) error {
	seen := map[string]string{}
	check := func(kind, name, from string) error {
		key := kind + "/" + name
		if other, ok := seen[key]; ok && other != from {
			return fmt.Errorf("%s %q and %q both map to object name %q", kind, other, from, name)
		}
		seen[key] = from
		return nil
	}
	for _, x := range o.Policies {
		if err := check("BGPPolicy", x.Name, string(*x.Spec.FRR.RouteMapName)); err != nil {
			return err
		}
	}
	for _, x := range o.Profiles {
		if err := check("BGPPeerProfile", x.Name, string(*x.Spec.FRR.PeerGroupName)); err != nil {
			return err
		}
	}
	for _, x := range o.PrefixLists {
		if err := check("BGPPrefixList", x.Name, string(*x.Spec.FRR.Name)); err != nil {
			return err
		}
	}
	for _, x := range o.CommunitySets {
		if err := check("BGPCommunitySet", x.Name, string(x.Spec.Type)+" "+string(*x.Spec.FRR.Name)); err != nil {
			return err
		}
	}
	for _, x := range o.Peers {
		if err := check("BGPPeer", x.Name, x.Spec.Address); err != nil {
			return err
		}
	}
	for _, x := range o.Advertisements {
		if err := check("BGPAdvertisement", x.Name, x.Name); err != nil {
			return err
		}
	}
	routes := map[string]bool{}
	for _, x := range o.StaticRoutes {
		if routes[x.Name] {
			return fmt.Errorf("static route %s %s is defined twice or collides with another", x.Spec.Destination, x.Name)
		}
		routes[x.Name] = true
	}
	return nil
}

// retained lists every definition no peer, profile or advertisement
// reaches, so the router renders it anyway.
func retained(o *Objects) *networkv1alpha1.BGPRouterFRRRetain {
	usedProfiles, usedPolicies := map[string]bool{}, map[string]bool{}
	usePolicy := func(ref *networkv1alpha1.LocalObjectRef) {
		if ref != nil {
			usedPolicies[ref.Name] = true
		}
	}
	useFamilies := func(list []networkv1alpha1.BGPPeerFamilySettings) {
		for _, fs := range list {
			usePolicy(fs.ImportPolicyRef)
			usePolicy(fs.ExportPolicyRef)
		}
	}
	for _, pe := range o.Peers {
		if pe.Spec.PeerProfileRef != nil {
			usedProfiles[pe.Spec.PeerProfileRef.Name] = true
		}
		useFamilies(pe.Spec.FamilySettings)
	}
	for _, pr := range o.Profiles {
		if usedProfiles[pr.Name] {
			useFamilies(pr.Spec.AddressFamilies)
		}
	}
	for _, a := range o.Advertisements {
		if a.Spec.PolicyRef != nil {
			usedPolicies[a.Spec.PolicyRef.Name] = true
		}
	}

	r := &networkv1alpha1.BGPRouterFRRRetain{}
	for _, pr := range o.Profiles {
		if !usedProfiles[pr.Name] {
			r.PeerProfileRefs = append(r.PeerProfileRefs, networkv1alpha1.LocalObjectRef{Name: pr.Name})
			useFamilies(pr.Spec.AddressFamilies)
		}
	}
	for _, pol := range o.Policies {
		if !usedPolicies[pol.Name] {
			r.PolicyRefs = append(r.PolicyRefs, networkv1alpha1.LocalObjectRef{Name: pol.Name})
		}
	}
	// Every policy renders now, so its lists and sets do too.
	usedLists, usedSets := map[string]bool{}, map[string]bool{}
	for _, pol := range o.Policies {
		for _, t := range pol.Spec.Terms {
			for _, ref := range []*networkv1alpha1.LocalObjectRef{t.Match.CommunitySetRef, t.Match.LargeCommunitySetRef} {
				if ref != nil {
					usedSets[ref.Name] = true
				}
			}
			if t.Match.PrefixListRef != nil {
				usedLists[t.Match.PrefixListRef.Name] = true
			}
			if t.Set != nil {
				deletes := []*networkv1alpha1.LocalObjectRef{t.Set.DeleteCommunitySetRef, t.Set.DeleteLargeCommunitySetRef}
				for _, ref := range deletes {
					if ref != nil {
						usedSets[ref.Name] = true
					}
				}
			}
		}
	}
	for _, pl := range o.PrefixLists {
		if !usedLists[pl.Name] {
			r.PrefixListRefs = append(r.PrefixListRefs, networkv1alpha1.LocalObjectRef{Name: pl.Name})
		}
	}
	for _, cs := range o.CommunitySets {
		if !usedSets[cs.Name] {
			r.CommunitySetRefs = append(r.CommunitySetRefs, networkv1alpha1.LocalObjectRef{Name: cs.Name})
		}
	}
	return r
}

var invalidName = regexp.MustCompile(`[^a-z0-9.-]+`)

// objectName joins parts into a lowercase RFC 1123 subdomain.
func objectName(parts ...string) string {
	name := strings.ToLower(strings.Join(parts, "-"))
	name = invalidName.ReplaceAllString(name, "-")
	name = strings.Trim(strings.ReplaceAll(name, "..", "."), "-.")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return name
}

func frrName(s string) *networkv1alpha1.FRRObjectName {
	return ptr.To(networkv1alpha1.FRRObjectName(s))
}
