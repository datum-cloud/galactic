// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
)

const (
	// bmpSyncInterval is how often the keeper re-resolves each station's host
	// and re-reports session state. Resolution is repeated, not done once,
	// because a collector addressed by name can move.
	bmpSyncInterval = 30 * time.Second

	// bmpResolveTimeout bounds one station's name lookup, so an unresponsive
	// resolver delays only that station's registration.
	bmpResolveTimeout = 5 * time.Second
)

// BMP route monitoring policy names, as accepted by ParseBMPPolicy.
const (
	BMPPolicyPrePolicy  = "pre-policy"
	BMPPolicyPostPolicy = "post-policy"
	BMPPolicyLocalRIB   = "local-rib"
	BMPPolicyAll        = "all"
)

// bmpPolicies maps each accepted policy name to GoBGP's enum. GoBGP's "both"
// is left out because GoBGP itself logs it as obsolete; "all" covers it.
var bmpPolicies = map[string]api.AddBmpRequest_MonitoringPolicy{
	BMPPolicyPrePolicy:  api.AddBmpRequest_MONITORING_POLICY_PRE,
	BMPPolicyPostPolicy: api.AddBmpRequest_MONITORING_POLICY_POST,
	BMPPolicyLocalRIB:   api.AddBmpRequest_MONITORING_POLICY_LOCAL,
	BMPPolicyAll:        api.AddBmpRequest_MONITORING_POLICY_ALL,
}

// ParseBMPPolicy returns the GoBGP monitoring policy for name, one of
// BMPPolicyPrePolicy, BMPPolicyPostPolicy, BMPPolicyLocalRIB or BMPPolicyAll.
// It returns an error for any other name.
func ParseBMPPolicy(name string) (api.AddBmpRequest_MonitoringPolicy, error) {
	p, ok := bmpPolicies[name]
	if !ok {
		return 0, fmt.Errorf("unknown BMP monitoring policy %q", name)
	}
	return p, nil
}

// BMPStation is one BMP collector a router streams to. Host is an IP address
// or a DNS name.
type BMPStation struct {
	Host string
	Port uint16
}

// String returns the station as host:port, bracketing an IPv6 host.
func (s BMPStation) String() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(int(s.Port)))
}

// BMPStateObserver is notified of each BMP station's session state every time
// the keeper checks it. router is the BGPRouter key of the runtime streaming to
// station; up reports whether its TCP session to the collector is established.
type BMPStateObserver interface {
	BMPStationState(router, station string, up bool)
}

// BMPConfig configures BMP (RFC 7854) export from every runtime a factory
// creates. The zero value, with no stations, disables it.
type BMPConfig struct {
	Stations []BMPStation
	Policy   api.AddBmpRequest_MonitoringPolicy
	// StatisticsInterval is how often statistics reports are sent for each
	// established peer, in whole seconds. Zero disables them.
	StatisticsInterval time.Duration
	// SysName is the sysName sent in the BMP Initiation message, which
	// collectors use to name the router.
	SysName string
	// Observer, when non-nil, receives each station's session state.
	Observer BMPStateObserver
}

// bmpKeeper registers a runtime's BMP stations on its GoBGP server and keeps
// them registered across server replacement and collector address changes.
//
// It registers only on the server it was last attached to and never loads the
// runtime's current server itself. The runtime detaches it before stopping or
// replacing a server and attaches the new one only once BGP has started on it,
// so a sync that races a replacement can never register a station on a server
// about to be stopped. GoBGP does not stop a server's BMP clients when the
// server stops, so a station left registered there would keep its own
// collector session open, streaming nothing, for the life of the process.
type bmpKeeper struct {
	cfg     BMPConfig
	router  string
	resolve func(ctx context.Context, host string) (netip.Addr, error)
	kick    chan struct{}

	mu         sync.Mutex
	server     *gobgpserver.BgpServer
	registered map[BMPStation]netip.AddrPort
}

// newBMPKeeper returns a keeper for router's stations, or nil when cfg has
// none. Every keeper method accepts a nil receiver.
func newBMPKeeper(cfg BMPConfig, router string) *bmpKeeper {
	if len(cfg.Stations) == 0 {
		return nil
	}
	return &bmpKeeper{
		cfg:        cfg,
		router:     router,
		resolve:    resolveHost,
		kick:       make(chan struct{}, 1),
		registered: make(map[BMPStation]netip.AddrPort),
	}
}

// resolveHost returns host itself when it is an IP address, and otherwise the
// first address a DNS lookup returns for it.
func resolveHost(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	ctx, cancel := context.WithTimeout(ctx, bmpResolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses for %s", host)
	}
	return addrs[0].Unmap(), nil
}

// attach makes b the server stations are registered on and triggers a sync.
// b must already have BGP started, since GoBGP reads the router's ASN and ID
// when a station's session opens. Attaching the server already attached is a
// no-op.
func (k *bmpKeeper) attach(b *gobgpserver.BgpServer) {
	if k == nil {
		return
	}
	k.mu.Lock()
	changed := k.server != b
	if changed {
		k.server = b
		clear(k.registered)
	}
	k.mu.Unlock()
	if changed {
		select {
		case k.kick <- struct{}{}:
		default:
		}
	}
}

// detach removes every registered station from the attached server, closing
// its collector sessions with a BMP Termination, and leaves the keeper with no
// server until the next attach. Call it before the server stops.
func (k *bmpKeeper) detach(ctx context.Context) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.server == nil {
		return
	}
	for st, ap := range k.registered {
		if err := k.server.DeleteBmp(ctx, &api.DeleteBmpRequest{
			Address: ap.Addr().String(),
			Port:    uint32(ap.Port()),
		}); err != nil {
			slog.Warn("bmp: remove station", "router", k.router, "station", st.String(), "err", err)
		}
		k.observe(st, false)
	}
	clear(k.registered)
	k.server = nil
}

// run syncs the stations every bmpSyncInterval, and whenever attach is called,
// until ctx is done.
func (k *bmpKeeper) run(ctx context.Context) {
	if k == nil {
		return
	}
	ticker := time.NewTicker(bmpSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-k.kick:
		case <-ticker.C:
		}
		k.sync(ctx)
	}
}

// sync resolves every station and registers any that is not registered at its
// current address on the attached server, replacing a registration whose
// address has changed. It then reports each station's session state. A
// station whose host does not resolve is reported down and retried on the
// next sync. It does nothing while no server is attached.
func (k *bmpKeeper) sync(ctx context.Context) {
	if k == nil {
		return
	}
	// Resolved before taking the lock, so a slow lookup never holds up a
	// detach, and with it the runtime's Apply or Stop.
	resolved := make(map[BMPStation]netip.AddrPort, len(k.cfg.Stations))
	for _, st := range k.cfg.Stations {
		addr, err := k.resolve(ctx, st.Host)
		if err != nil {
			slog.Warn("bmp: resolve station", "router", k.router, "station", st.String(), "err", err)
			continue
		}
		resolved[st] = netip.AddrPortFrom(addr, st.Port)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.server == nil {
		return
	}
	for _, st := range k.cfg.Stations {
		ap, ok := resolved[st]
		if !ok {
			continue
		}
		prev, isRegistered := k.registered[st]
		if isRegistered && prev == ap {
			continue
		}
		if isRegistered {
			if err := k.server.DeleteBmp(ctx, &api.DeleteBmpRequest{
				Address: prev.Addr().String(),
				Port:    uint32(prev.Port()),
			}); err != nil {
				slog.Warn("bmp: remove moved station", "router", k.router, "station", st.String(), "err", err)
			}
			delete(k.registered, st)
		}
		if err := k.server.AddBmp(ctx, &api.AddBmpRequest{
			Address:           ap.Addr().String(),
			Port:              uint32(ap.Port()),
			Policy:            k.cfg.Policy,
			StatisticsTimeout: int32(k.cfg.StatisticsInterval / time.Second),
			SysName:           k.cfg.SysName,
		}); err != nil {
			slog.Warn("bmp: add station", "router", k.router, "station", st.String(), "addr", ap.String(), "err", err)
			continue
		}
		k.registered[st] = ap
		slog.Info("bmp: station registered", "router", k.router, "station", st.String(), "addr", ap.String())
	}
	k.report(ctx)
}

// report passes each configured station's session state to the observer. The
// caller must hold k.mu.
func (k *bmpKeeper) report(ctx context.Context) {
	if k.cfg.Observer == nil {
		return
	}
	up := make(map[netip.AddrPort]bool, len(k.registered))
	if err := k.server.ListBmp(ctx, &api.ListBmpRequest{}, func(s *api.ListBmpResponse_BmpStation) {
		addr, err := netip.ParseAddr(s.GetConf().GetAddress())
		if err != nil {
			return
		}
		up[netip.AddrPortFrom(addr.Unmap(), uint16(s.GetConf().GetPort()))] = bmpSessionUp(s.GetState())
	}); err != nil {
		slog.Warn("bmp: list stations", "router", k.router, "err", err)
	}
	for _, st := range k.cfg.Stations {
		ap, ok := k.registered[st]
		k.observe(st, ok && up[ap])
	}
}

// observe passes one station's state to the observer, if there is one.
func (k *bmpKeeper) observe(st BMPStation, up bool) {
	if k.cfg.Observer != nil {
		k.cfg.Observer.BMPStationState(k.router, st.String(), up)
	}
}

// bmpSessionUp reports whether a station's collector session is established.
// GoBGP records only the second the session last came up and the second it
// last went down, so the two are compared at one-second resolution: a session
// that dropped and reconnected within one second correctly reads as up, but so
// does one that came up and dropped again within the same second, until its
// next connection attempt moves either time.
func bmpSessionUp(st *api.ListBmpResponse_BmpStation_State) bool {
	if st.GetUptime() == nil {
		return false
	}
	if st.GetDowntime() == nil {
		return true
	}
	return !st.GetUptime().AsTime().Before(st.GetDowntime().AsTime())
}
