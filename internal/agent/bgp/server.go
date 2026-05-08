// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bgp wraps github.com/osrg/gobgp/v3/pkg/server and exposes the
// narrow surface the agent reconciler needs: lifecycle, peer config,
// originate/withdraw, watch.
package bgp

import (
	"context"
	"fmt"
	"net"
	"sync"

	api "github.com/osrg/gobgp/v3/api"
	gobgp "github.com/osrg/gobgp/v3/pkg/server"
)

// Encoding selects how the SRv6 service SID is carried in BGP UPDATEs.
// See PLAN-bgp-cutover.md for the design rationale.
type Encoding string

const (
	// EncodingTunnelEncap carries the SID in a Tunnel Encapsulation
	// Attribute (RFC 9012) using SR Policy tunnel type with one Type-A
	// segment. Default; works with off-the-shelf GoBGP today.
	EncodingTunnelEncap Encoding = "tunnel-encap"

	// EncodingPrefixSID carries the SID in PA_PREFIX_SID's L3 Service
	// Sub-TLV (RFC 9252). Requires a GoBGP build that round-trips the
	// sub-TLV. Verified at startup.
	EncodingPrefixSID Encoding = "prefix-sid"
)

// Config holds startup parameters for the BGP server.
type Config struct {
	// LocalASN is the ASN this agent peers with the RR under. Must
	// match the operator's --asn.
	LocalASN uint32

	// RouterID is the BGP router-id (an IPv4-formatted 4-byte value).
	RouterID string

	// ListenPort is the local TCP port for incoming BGP connections.
	// 179 by default; set to a non-privileged port for tests.
	ListenPort int32

	// NodeLocator is the IPv6 address used as the BGP next-hop for
	// routes this agent originates. The underlay must route to this
	// address. Distinct from the cluster POP-locator (which is the
	// service-SID locator).
	NodeLocator net.IP

	// Peers is the set of route-reflector addresses to connect to.
	Peers []PeerConfig

	// Encoding selects the SID wire format. See Encoding.
	Encoding Encoding
}

// PeerConfig is one RR peer.
type PeerConfig struct {
	Address  string // IP or DNS name
	Password string // optional MD5/TCP-AO secret
}

// SessionState describes a peer's BGP FSM state.
type SessionState int

const (
	SessionStateIdle SessionState = iota
	SessionStateConnect
	SessionStateActive
	SessionStateOpenSent
	SessionStateOpenConfirm
	SessionStateEstablished
)

// SessionEvent is delivered on the channel returned by SessionEvents.
type SessionEvent struct {
	Peer  string
	State SessionState
}

// ReceivedRoute is an inbound VPN path normalized for the reconciler.
type ReceivedRoute struct {
	Prefix             *net.IPNet
	RouteDistinguisher string   // human-readable form, e.g. "65000:1234"
	RouteTargets       []string // human-readable form
	NextHop            net.IP
	ServiceSID         net.IP
	IsWithdraw         bool
}

// PathKey uniquely names an originated path so the reconciler can
// withdraw it later and so OnSessionEstablished can replay every
// active origination.
type PathKey struct {
	VPCHex    string
	AttachHex string
	Prefix    string // CIDR string form
}

// Server is the BGP wrapper. Construct with NewServer; lifecycle is
// Start / Stop. The Stop call sends BGP NOTIFICATION Cease on each peer
// before tearing the local goroutines down — without it, peers must
// time the session out via hold-timer, ~3 minutes of RR-side noise.
type Server struct {
	cfg Config

	bs *gobgp.BgpServer

	// active stores the originated path's UUID per key so we can
	// DeletePath later and so we can re-originate after session flap.
	mu     sync.Mutex
	active map[PathKey]activeEntry

	// peerStates is updated by the watch loop and read by health
	// checks and metrics. Keyed by neighbor address.
	peerStates map[string]SessionState

	sessionCh chan SessionEvent
	receiveCh chan ReceivedRoute
}

type activeEntry struct {
	uuid       []byte
	prefix     *net.IPNet
	rd         string
	rt         string
	nextHop    net.IP
	serviceSID net.IP
}

// NewServer constructs a Server but does not start it.
func NewServer(cfg Config) (*Server, error) {
	if cfg.LocalASN == 0 {
		return nil, fmt.Errorf("LocalASN required")
	}
	if cfg.RouterID == "" {
		return nil, fmt.Errorf("RouterID required")
	}
	if cfg.NodeLocator == nil {
		return nil, fmt.Errorf("NodeLocator required")
	}
	if cfg.Encoding == "" {
		cfg.Encoding = EncodingTunnelEncap
	}
	if cfg.Encoding != EncodingTunnelEncap && cfg.Encoding != EncodingPrefixSID {
		return nil, fmt.Errorf("unknown SRv6 encoding %q", cfg.Encoding)
	}
	if cfg.Encoding == EncodingPrefixSID {
		// Fail fast if the pinned GoBGP build doesn't round-trip the
		// L3 Service Sub-TLV. Better to refuse to start than to
		// originate paths the rest of the cluster can't decode.
		if err := VerifyPrefixSIDRoundTrip(); err != nil {
			return nil, fmt.Errorf("prefix-sid encoding selected but round-trip failed: %w", err)
		}
	}
	return &Server{
		cfg:        cfg,
		active:     map[PathKey]activeEntry{},
		peerStates: map[string]SessionState{},
		sessionCh:  make(chan SessionEvent, 16),
		receiveCh:  make(chan ReceivedRoute, 256),
	}, nil
}

// AnyEstablished reports whether at least one configured RR peer is in
// the Established state. Used by /healthz to gate readiness.
func (s *Server) AnyEstablished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.peerStates {
		if st == SessionStateEstablished {
			return true
		}
	}
	return false
}

// PeerStates returns a snapshot of every known peer's current state.
// Used by metrics to export per-peer gauges.
func (s *Server) PeerStates() map[string]SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]SessionState, len(s.peerStates))
	for k, v := range s.peerStates {
		out[k] = v
	}
	return out
}

// updatePeerState is called by watchPeers on every state change.
func (s *Server) updatePeerState(peer string, st SessionState) {
	s.mu.Lock()
	s.peerStates[peer] = st
	s.mu.Unlock()
}

// Start brings up the BGP speaker, configures peers, and starts the
// watch goroutines. Returns when the BGP server is initialized; peer
// sessions establish asynchronously.
func (s *Server) Start(ctx context.Context) error {
	s.bs = gobgp.NewBgpServer()
	go s.bs.Serve()

	if err := s.bs.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        s.cfg.LocalASN,
			RouterId:   s.cfg.RouterID,
			ListenPort: s.cfg.ListenPort,
		},
	}); err != nil {
		return fmt.Errorf("StartBgp: %w", err)
	}

	// Watch peer state changes and inbound routes. Both run for the
	// life of the server; the channels are drained by the reconciler.
	go s.watchPeers(ctx)
	go s.watchTable(ctx)

	for _, p := range s.cfg.Peers {
		if err := s.addPeer(ctx, p); err != nil {
			return fmt.Errorf("AddPeer %q: %w", p.Address, err)
		}
	}
	return nil
}

// Stop tears the BGP server down gracefully — sends NOTIFICATION Cease
// to each peer, waits briefly, then stops internal goroutines.
func (s *Server) Stop(ctx context.Context) {
	if s.bs == nil {
		return
	}
	_ = s.bs.StopBgp(ctx, &api.StopBgpRequest{})
	s.bs.Stop()
}

// SessionEvents returns the channel of peer state changes. The
// reconciler subscribes to this to drive OnSessionEstablished replays.
func (s *Server) SessionEvents() <-chan SessionEvent { return s.sessionCh }

// ReceivedRoutes returns the channel of inbound BGP UPDATEs decoded
// into the agent's normalized form.
func (s *Server) ReceivedRoutes() <-chan ReceivedRoute { return s.receiveCh }

// ActivePaths returns a snapshot of the currently-originated paths.
// Used by the reconciler's OnSessionEstablished handler to replay.
func (s *Server) ActivePaths() map[PathKey]activeEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[PathKey]activeEntry, len(s.active))
	for k, v := range s.active {
		out[k] = v
	}
	return out
}

func (s *Server) addPeer(ctx context.Context, p PeerConfig) error {
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: p.Address,
			PeerAsn:         s.cfg.LocalASN, // iBGP
			AuthPassword:    p.Password,
		},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Family:  &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_MPLS_VPN},
					Enabled: true,
				},
			},
			{
				Config: &api.AfiSafiConfig{
					Family:  &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_MPLS_VPN},
					Enabled: true,
				},
			},
		},
	}
	return s.bs.AddPeer(ctx, &api.AddPeerRequest{Peer: n})
}
