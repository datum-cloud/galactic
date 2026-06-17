package gobgp

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	providerv1alpha1 "go.miloapis.com/cosmos/api/proto/bgp/provider/v1alpha1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	safiUnicast       = "unicast"
	globalPolicyTable = "global"
)

// ProviderServer implements providerv1alpha1.BGPProviderServiceServer, translating
// cosmos BGP provider calls into direct GoBGP BgpServer API calls.
type ProviderServer struct {
	providerv1alpha1.UnimplementedBGPProviderServiceServer
	srv *Server
}

// NewProviderServer creates a ProviderServer backed by the given gobgp.Server.
func NewProviderServer(srv *Server) *ProviderServer {
	return &ProviderServer{srv: srv}
}

// bgp returns the running BgpServer or an Unavailable error if not yet started.
func (p *ProviderServer) bgp() (*gobgpserver.BgpServer, error) {
	b := p.srv.bgp.Load()
	if b == nil {
		return nil, status.Error(codes.Unavailable, "gobgp not started")
	}
	return b, nil
}

// Ready returns OK once the GoBGP server is initialized and ready to accept calls.
func (p *ProviderServer) Ready(_ context.Context, _ *providerv1alpha1.ReadyRequest) (*providerv1alpha1.ReadyResponse, error) {
	if _, err := p.bgp(); err != nil {
		return nil, err
	}
	return &providerv1alpha1.ReadyResponse{}, nil
}

// Capabilities reports the address families and features this provider supports.
func (p *ProviderServer) Capabilities(_ context.Context, _ *providerv1alpha1.CapabilitiesRequest) (*providerv1alpha1.CapabilitiesResponse, error) {
	return &providerv1alpha1.CapabilitiesResponse{
		Capabilities: &providerv1alpha1.CapabilitySet{
			AddressFamilies: []*providerv1alpha1.AddressFamily{
				{Afi: "IPv4", Safi: "Unicast"},
				{Afi: "IPv6", Safi: "Unicast"},
			},
			RouteReflection: false,
			Bfd:             false,
		},
	}, nil
}

// ConfigureSpeaker applies global BGP speaker configuration by calling StartBgp.
// If BGP is already running, a fresh BgpServer is created because StopBgp in
// GoBGP v4 permanently terminates the Serve loop.
func (p *ProviderServer) ConfigureSpeaker(ctx context.Context, req *providerv1alpha1.ConfigureSpeakerRequest) (*providerv1alpha1.ConfigureSpeakerResponse, error) {
	b, err := p.bgp()
	if err != nil {
		return nil, err
	}
	spec := req.GetSpec()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "spec is required")
	}

	restarted := false
	resp, getErr := b.GetBgp(ctx, &api.GetBgpRequest{})
	if getErr == nil && resp.Global != nil && resp.Global.Asn != 0 {
		b, err = p.srv.Reconfigure()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reconfigure bgp server: %v", err)
		}
		restarted = true
	}

	global := &api.Global{
		Asn:        uint32(spec.GetAsNumber()),
		RouterId:   spec.GetRouterId(),
		ListenPort: spec.GetListenPort(),
	}

	if rr := spec.GetRouteReflector(); rr != nil && rr.GetClusterId() != "" {
		global.RouteSelectionOptions = &api.RouteSelectionOptionsConfig{
			AlwaysCompareMed:        spec.GetBestPath().GetAlwaysCompareMed(),
			IgnoreAsPathLength:      false,
			ExternalCompareRouterId: spec.GetBestPath().GetCompareRouterId(),
		}
	}

	if err := b.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
		return nil, status.Errorf(codes.Internal, "start bgp: %v", err)
	}

	return &providerv1alpha1.ConfigureSpeakerResponse{Restarted: restarted}, nil
}

// AddOrUpdatePeer adds or updates a BGP peer.
func (p *ProviderServer) AddOrUpdatePeer(ctx context.Context, req *providerv1alpha1.AddOrUpdatePeerRequest) (*providerv1alpha1.AddOrUpdatePeerResponse, error) {
	b, err := p.bgp()
	if err != nil {
		return nil, err
	}
	spec := req.GetPeer()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "peer is required")
	}

	peer := peerFromSpec(spec)
	addErr := b.AddPeer(ctx, &api.AddPeerRequest{Peer: peer})
	if addErr != nil {
		switch {
		case strings.Contains(addErr.Error(), "can't overwrite the existing peer"):
			if _, updateErr := b.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer}); updateErr != nil {
				return nil, status.Errorf(codes.Internal, "update peer %s: %v", spec.GetAddress(), updateErr)
			}
		case strings.Contains(addErr.Error(), "bgp server hasn't started yet"):
			return nil, status.Errorf(codes.Unavailable, "bgp speaker not yet configured")
		default:
			return nil, status.Errorf(codes.Internal, "add peer %s: %v", spec.GetAddress(), addErr)
		}
	}

	return &providerv1alpha1.AddOrUpdatePeerResponse{}, nil
}

// DeletePeer removes a BGP peer.
func (p *ProviderServer) DeletePeer(ctx context.Context, req *providerv1alpha1.DeletePeerRequest) (*providerv1alpha1.DeletePeerResponse, error) {
	b, err := p.bgp()
	if err != nil {
		return nil, err
	}
	if err := b.DeletePeer(ctx, &api.DeletePeerRequest{Address: req.GetAddress()}); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return &providerv1alpha1.DeletePeerResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "delete peer %s: %v", req.GetAddress(), err)
	}
	return &providerv1alpha1.DeletePeerResponse{}, nil
}

// AddOrUpdateAdvertisement injects prefixes into the global RIB for advertisement.
func (p *ProviderServer) AddOrUpdateAdvertisement(_ context.Context, req *providerv1alpha1.AddOrUpdateAdvertisementRequest) (*providerv1alpha1.AddOrUpdateAdvertisementResponse, error) {
	b, err := p.bgp()
	if err != nil {
		return nil, err
	}
	spec := req.GetAdvertisement()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "advertisement is required")
	}

	for _, prefixStr := range spec.GetPrefixes() {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid prefix %q: %v", prefixStr, err)
		}
		path, err := buildPath(prefix, false)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "build path for %q: %v", prefixStr, err)
		}
		if _, err := b.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}}); err != nil {
			return nil, status.Errorf(codes.Internal, "add path %q: %v", prefixStr, err)
		}
	}

	return &providerv1alpha1.AddOrUpdateAdvertisementResponse{}, nil
}

// DeleteAdvertisement withdraws a prefix from the global RIB.
func (p *ProviderServer) DeleteAdvertisement(_ context.Context, req *providerv1alpha1.DeleteAdvertisementRequest) (*providerv1alpha1.DeleteAdvertisementResponse, error) {
	b, err := p.bgp()
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(req.GetPrefix())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid prefix %q: %v", req.GetPrefix(), err)
	}
	path, err := buildPath(prefix, true)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build path for %q: %v", req.GetPrefix(), err)
	}
	if err := b.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{path}}); err != nil {
		return nil, status.Errorf(codes.Internal, "delete path %q: %v", req.GetPrefix(), err)
	}
	return &providerv1alpha1.DeleteAdvertisementResponse{}, nil
}

// AddOrUpdatePolicy creates or replaces a named routing policy in GoBGP.
func (p *ProviderServer) AddOrUpdatePolicy(ctx context.Context, req *providerv1alpha1.AddOrUpdatePolicyRequest) (*providerv1alpha1.AddOrUpdatePolicyResponse, error) {
	b, err := p.bgp()
	if err != nil {
		return nil, err
	}
	spec := req.GetPolicy()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "policy is required")
	}

	if err := upsertPolicy(ctx, b, spec); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert policy %q: %v", spec.GetName(), err)
	}
	return &providerv1alpha1.AddOrUpdatePolicyResponse{}, nil
}

// DeletePolicy removes a named routing policy from GoBGP.
func (p *ProviderServer) DeletePolicy(ctx context.Context, req *providerv1alpha1.DeletePolicyRequest) (*providerv1alpha1.DeletePolicyResponse, error) {
	b, err := p.bgp()
	if err != nil {
		return nil, err
	}
	name := req.GetPolicyName()

	// Remove policy assignments (both directions), then the policy itself.
	for _, dir := range []api.PolicyDirection{api.PolicyDirection_POLICY_DIRECTION_IMPORT, api.PolicyDirection_POLICY_DIRECTION_EXPORT} {
		_ = b.DeletePolicyAssignment(ctx, &api.DeletePolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{
				Name:      globalPolicyTable,
				Direction: dir,
				Policies:  []*api.Policy{{Name: name}},
			},
		})
	}
	_ = b.DeletePolicy(ctx, &api.DeletePolicyRequest{
		Policy:             &api.Policy{Name: name},
		PreserveStatements: false,
		All:                true,
	})
	return &providerv1alpha1.DeletePolicyResponse{}, nil
}

// peerFromSpec converts a cosmos PeerSpec to a GoBGP api.Peer.
func peerFromSpec(spec *providerv1alpha1.PeerSpec) *api.Peer {
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: spec.GetAddress(),
			PeerAsn:         uint32(spec.GetAsNumber()),
			AllowOwnAsn:     uint32(spec.GetAllowAsIn()),
		},
	}

	for _, af := range spec.GetFamilies() {
		peer.AfiSafis = append(peer.AfiSafis, &api.AfiSafi{
			Config: &api.AfiSafiConfig{Family: familyFromSpec(af)},
		})
	}

	if t := spec.GetTimers(); t != nil && (t.GetHoldTime() > 0 || t.GetKeepalive() > 0) {
		peer.Timers = &api.Timers{
			Config: &api.TimersConfig{
				HoldTime:          uint64(t.GetHoldTime()),
				KeepaliveInterval: uint64(t.GetKeepalive()),
			},
		}
	}

	if spec.GetRouteReflectorClient() {
		peer.RouteReflector = &api.RouteReflector{RouteReflectorClient: true}
	}

	if spec.GetPassive() {
		peer.Transport = &api.Transport{PassiveMode: true}
	}
	if spec.GetRemotePort() > 0 {
		if peer.Transport == nil {
			peer.Transport = &api.Transport{}
		}
		peer.Transport.RemotePort = uint32(spec.GetRemotePort())
	}

	if spec.EbgpMultihop != nil && *spec.EbgpMultihop > 0 {
		peer.EbgpMultihop = &api.EbgpMultihop{
			Enabled:     true,
			MultihopTtl: uint32(*spec.EbgpMultihop),
		}
	}

	if spec.TtlSecurity != nil && *spec.TtlSecurity > 0 {
		peer.TtlSecurity = &api.TtlSecurity{
			Enabled: true,
			TtlMin:  uint32(*spec.TtlSecurity),
		}
	}

	if spec.GetPassword() != "" {
		peer.Conf.AuthPassword = spec.GetPassword()
	}

	return peer
}

// familyFromSpec maps a cosmos AddressFamily to a GoBGP api.Family.
func familyFromSpec(af *providerv1alpha1.AddressFamily) *api.Family {
	f := &api.Family{}
	switch strings.ToLower(af.GetAfi()) {
	case "ipv4", "ip":
		f.Afi = api.Family_AFI_IP
	case "ipv6", "ip6":
		f.Afi = api.Family_AFI_IP6
	case "l2vpn":
		f.Afi = api.Family_AFI_L2VPN
	}
	switch strings.ToLower(af.GetSafi()) {
	case safiUnicast:
		f.Safi = api.Family_SAFI_UNICAST
	case "multicast":
		f.Safi = api.Family_SAFI_MULTICAST
	case "mpls-vpn", "vpn":
		f.Safi = api.Family_SAFI_MPLS_VPN
	case "evpn":
		f.Safi = api.Family_SAFI_EVPN
	}
	return f
}

// buildPath constructs an apiutil.Path for a CIDR prefix.
func buildPath(prefix netip.Prefix, withdrawal bool) (*apiutil.Path, error) {
	prefix = prefix.Masked()
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("create NLRI: %w", err)
	}

	family := bgp.RF_IPv4_UC
	if prefix.Addr().Is6() {
		family = bgp.RF_IPv6_UC
	}

	var attrs []bgp.PathAttributeInterface
	if !withdrawal {
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.0"))
		if err != nil {
			return nil, fmt.Errorf("create nexthop attr: %w", err)
		}
		attrs = []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			nh,
		}
	}

	return &apiutil.Path{
		Family:     family,
		Nlri:       nlri,
		Attrs:      attrs,
		Withdrawal: withdrawal,
		Age:        time.Now().Unix(),
	}, nil
}

// upsertPolicy creates or replaces a policy and its defined sets in GoBGP.
func upsertPolicy(ctx context.Context, b *gobgpserver.BgpServer, spec *providerv1alpha1.PolicySpec) error {
	allStmts := append(spec.GetImportStatements(), spec.GetExportStatements()...)

	// Collect and create unique prefix defined sets.
	prefixSetsSeen := map[string]bool{}
	for _, stmt := range allStmts {
		cond := stmt.GetConditions()
		if cond == nil {
			continue
		}
		for _, setName := range cond.GetPrefixSets() {
			if prefixSetsSeen[setName] {
				continue
			}
			prefixSetsSeen[setName] = true
			if err := b.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
				DefinedSet: &api.DefinedSet{
					DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
					Name:        setName,
				},
				Replace: true,
			}); err != nil {
				return fmt.Errorf("add prefix set %q: %w", setName, err)
			}
		}
		if cs := cond.GetCommunitySet(); cs != "" && !prefixSetsSeen["community:"+cs] {
			prefixSetsSeen["community:"+cs] = true
			if err := b.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
				DefinedSet: &api.DefinedSet{
					DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
					Name:        cs,
				},
				Replace: true,
			}); err != nil {
				return fmt.Errorf("add community set %q: %w", cs, err)
			}
		}
	}

	// Build GoBGP statements.
	importStmts := buildStatements(spec.GetImportStatements())
	exportStmts := buildStatements(spec.GetExportStatements())

	// Add/replace the policy with all statements.
	allGoBGPStmts := append(importStmts, exportStmts...)
	if err := b.AddPolicy(ctx, &api.AddPolicyRequest{
		Policy: &api.Policy{
			Name:       spec.GetName(),
			Statements: allGoBGPStmts,
		},
		ReferExistingStatements: false,
	}); err != nil {
		return fmt.Errorf("add policy: %w", err)
	}

	// Assign policy to global RIB for import and export.
	if len(importStmts) > 0 {
		if err := b.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{
				Name:          globalPolicyTable,
				Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
				Policies:      []*api.Policy{{Name: spec.GetName()}},
				DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
			},
		}); err != nil {
			return fmt.Errorf("assign import policy: %w", err)
		}
	}
	if len(exportStmts) > 0 {
		if err := b.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{
				Name:          globalPolicyTable,
				Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
				Policies:      []*api.Policy{{Name: spec.GetName()}},
				DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
			},
		}); err != nil {
			return fmt.Errorf("assign export policy: %w", err)
		}
	}

	return nil
}

// buildStatements converts cosmos PolicyStatements to GoBGP api.Statements.
func buildStatements(stmts []*providerv1alpha1.PolicyStatement) []*api.Statement {
	out := make([]*api.Statement, 0, len(stmts))
	for _, s := range stmts {
		gs := &api.Statement{Name: s.GetName()}

		if cond := s.GetConditions(); cond != nil {
			gs.Conditions = &api.Conditions{}
			if sets := cond.GetPrefixSets(); len(sets) > 0 {
				gs.Conditions.PrefixSet = &api.MatchSet{
					Type: api.MatchSet_TYPE_ANY,
					Name: sets[0],
				}
			}
			if cs := cond.GetCommunitySet(); cs != "" {
				gs.Conditions.CommunitySet = &api.MatchSet{
					Type: api.MatchSet_TYPE_ANY,
					Name: cs,
				}
			}
		}

		if act := s.GetActions(); act != nil {
			gs.Actions = &api.Actions{}
			switch strings.ToLower(act.GetRouteDisposition()) {
			case "accept":
				gs.Actions.RouteAction = api.RouteAction_ROUTE_ACTION_ACCEPT
			case "reject":
				gs.Actions.RouteAction = api.RouteAction_ROUTE_ACTION_REJECT
			}
			if sc := act.GetSetCommunity(); sc != nil && len(sc.GetCommunities()) > 0 {
				communityType := api.CommunityAction_TYPE_ADD
				switch strings.ToLower(sc.GetMethod()) {
				case "replace":
					communityType = api.CommunityAction_TYPE_REPLACE
				case "remove":
					communityType = api.CommunityAction_TYPE_REMOVE
				}
				gs.Actions.Community = &api.CommunityAction{
					Type:        communityType,
					Communities: sc.GetCommunities(),
				}
			}
			if act.SetLocalPreference != nil {
				gs.Actions.LocalPref = &api.LocalPrefAction{Value: uint32(*act.SetLocalPreference)}
			}
			if act.SetMed != nil {
				gs.Actions.Med = &api.MedAction{
					Type:  api.MedAction_TYPE_REPLACE,
					Value: int64(*act.SetMed),
				}
			}
			if nh := act.GetSetNextHop(); nh != "" {
				gs.Actions.Nexthop = &api.NexthopAction{Address: nh}
			}
		}

		out = append(out, gs)
	}
	return out
}
