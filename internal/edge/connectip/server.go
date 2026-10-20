// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
)

const (
	// TemplatePath is the :path of every CONNECT-IP request the server
	// accepts.
	TemplatePath = "/.well-known/masque/ip/*/*/"
	// VPCHeader names the request header that selects the request's VPC.
	VPCHeader = "Galactic-VPC"

	// MinInnerMTU is the smallest inner packet every accepted request must be
	// able to carry toward the client.
	MinInnerMTU = 1280

	// DefaultInitialPacketSize is the QUIC packet size the server starts with
	// when Config.QUICConfig is nil. It leaves room for a MinInnerMTU packet
	// plus QUIC, HTTP Datagram and context ID overhead.
	DefaultInitialPacketSize = 1350

	connectIPProtocol = "connect-ip"

	// probeContextID is a proxy-allocated context ID that is never
	// registered, so a client drops a datagram carrying it.
	probeContextID = 1

	maxPacketSize = 65535
)

// Principal is an authenticated caller and the VPCs it may connect to.
type Principal struct {
	Name string
	VPCs []string
}

// VPC is a network clients can be admitted to.
type VPC struct {
	Name string
	// Pool is the IPv6 prefix client addresses are assigned from.
	Pool netip.Prefix
	// Routes are the prefixes advertised to every client of the VPC.
	Routes []netip.Prefix
}

// Config configures a Server.
type Config struct {
	// Authority is the host[:port] clients send as :authority.
	Authority string
	// TLSConfig holds the server certificate.
	TLSConfig *tls.Config
	// QUICConfig is optional; datagrams are always enabled. When nil, the
	// initial packet size is DefaultInitialPacketSize.
	QUICConfig *quic.Config
	// Credentials maps a bearer token to its principal.
	Credentials map[string]Principal
	VPCs        []VPC
	Backend     PacketBackend
	// Logger is optional and defaults to slog.Default().
	Logger *slog.Logger
}

type vpcState struct {
	pool   *addressPool
	routes []connectip.IPRoute
}

// Server terminates CONNECT-IP requests over HTTP/3.
type Server struct {
	template    *uritemplate.Template
	credentials map[[sha256.Size]byte]Principal
	vpcs        map[string]*vpcState
	backend     PacketBackend
	log         *slog.Logger
	h3          *http3.Server
	proxy       connectip.Proxy

	nextID atomic.Uint64

	mu       sync.Mutex
	closed   bool
	sessions sync.WaitGroup
}

type quicConnKey struct{}

// NewServer validates cfg and returns a Server. It returns an error when the
// authority, TLS config or backend is missing, or when a VPC is duplicated,
// has an invalid pool, or has invalid or overlapping routes.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Authority == "" {
		return nil, errors.New("authority is required")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("TLS config is required")
	}
	if cfg.Backend == nil {
		return nil, errors.New("backend is required")
	}
	template, err := uritemplate.New("https://" + cfg.Authority + TemplatePath)
	if err != nil {
		return nil, fmt.Errorf("could not parse URI template: %w", err)
	}

	vpcs := make(map[string]*vpcState, len(cfg.VPCs))
	for _, v := range cfg.VPCs {
		if v.Name == "" {
			return nil, errors.New("VPC name is required")
		}
		if _, dup := vpcs[v.Name]; dup {
			return nil, fmt.Errorf("VPC %q is defined twice", v.Name)
		}
		pool, err := newAddressPool(v.Pool)
		if err != nil {
			return nil, fmt.Errorf("VPC %q: %w", v.Name, err)
		}
		routes, err := routeRanges(v.Routes)
		if err != nil {
			return nil, fmt.Errorf("VPC %q: %w", v.Name, err)
		}
		vpcs[v.Name] = &vpcState{pool: pool, routes: routes}
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	quicConf := &quic.Config{InitialPacketSize: DefaultInitialPacketSize}
	if cfg.QUICConfig != nil {
		quicConf = cfg.QUICConfig.Clone()
	}
	quicConf.EnableDatagrams = true

	credentials := make(map[[sha256.Size]byte]Principal, len(cfg.Credentials))
	for token, p := range cfg.Credentials {
		credentials[sha256.Sum256([]byte(token))] = p
	}
	s := &Server{
		template:    template,
		credentials: credentials,
		vpcs:        vpcs,
		backend:     cfg.Backend,
		log:         log,
	}
	s.h3 = &http3.Server{
		Handler:         s,
		EnableDatagrams: true,
		TLSConfig:       http3.ConfigureTLSConfig(cfg.TLSConfig),
		QUICConfig:      quicConf,
		Logger:          log,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, quicConnKey{}, c)
		},
	}
	return s, nil
}

// Serve serves HTTP/3 on conn until the server is closed.
func (s *Server) Serve(conn net.PacketConn) error {
	return s.h3.Serve(conn)
}

// Close closes every listener and connection and waits for every session to
// end.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	err := s.h3.Close()
	s.sessions.Wait()
	return err
}

// ServeHTTP admits a CONNECT-IP request and, once admitted, proxies its
// packets until the request or its connection ends.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The connect-ip upgrade token implies the Capsule Protocol, so RFC 9484
	// does not require clients to send Capsule-Protocol, but the parser does.
	if _, ok := r.Header[http3.CapsuleProtocolHeader]; !ok && r.Proto == connectIPProtocol {
		r.Header.Set(http3.CapsuleProtocolHeader, "?1")
	}
	preq, err := connectip.ParseProxyRequest(r, s.template)
	if err != nil {
		status := http.StatusBadRequest
		if perr, ok := errors.AsType[*connectip.ProxyRequestParseError](err); ok {
			status = perr.HTTPStatus
		}
		s.reject(w, status, "invalid CONNECT-IP request", err)
		return
	}
	if r.URL.Path != TemplatePath {
		s.reject(w, http.StatusNotFound, "unknown path", nil)
		return
	}
	principal, ok := s.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.reject(w, http.StatusUnauthorized, "missing or unknown credential", nil)
		return
	}
	vpcName, ok := requestedVPC(r)
	if !ok {
		s.reject(w, http.StatusBadRequest, "request must name exactly one VPC", nil)
		return
	}
	vpc, ok := s.vpcs[vpcName]
	if !ok || !slices.Contains(principal.VPCs, vpcName) {
		s.reject(w, http.StatusForbidden, "VPC not granted", nil)
		return
	}
	if err := probeInnerMTU(r); err != nil {
		s.reject(w, http.StatusServiceUnavailable, "path cannot carry the minimum inner MTU", err)
		return
	}
	addr, err := vpc.pool.allocate()
	if err != nil {
		s.reject(w, http.StatusServiceUnavailable, "no client address available", err)
		return
	}
	defer vpc.pool.release(addr)

	if !s.startSession() {
		s.reject(w, http.StatusServiceUnavailable, "server is closing", nil)
		return
	}
	defer s.sessions.Done()

	info := SessionInfo{ID: s.nextID.Add(1), Principal: principal.Name, VPC: vpcName, Address: addr}
	log := s.log.With("session", info.ID, "principal", info.Principal, "vpc", info.VPC, "address", addr)
	sess, err := s.backend.Open(r.Context(), info)
	if err != nil {
		s.reject(w, http.StatusServiceUnavailable, "backend unavailable", err)
		return
	}
	defer func() {
		if err := sess.Close(); err != nil {
			log.Warn("could not close backend session", "error", err)
		}
	}()

	conn, err := s.proxy.Proxy(w, preq)
	if err != nil {
		log.Warn("could not accept request", "error", err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debug("could not close CONNECT-IP stream cleanly", "error", err)
		}
	}()
	assigned := netip.PrefixFrom(addr, addr.BitLen())
	if err := conn.AssignAddresses([]netip.Prefix{assigned}); err != nil {
		log.Warn("could not assign address", "error", err)
		return
	}
	if err := conn.AdvertiseRoute(vpc.routes); err != nil {
		log.Warn("could not advertise routes", "error", err)
		return
	}
	log.Info("CONNECT-IP request accepted")
	s.proxySession(r.Context(), log, conn, sess, assigned)
	log.Info("CONNECT-IP request ended")
}

// startSession registers a session with Close, or returns false once the
// server is closing.
func (s *Server) startSession() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.sessions.Add(1)
	return true
}

// proxySession forwards packets in both directions and answers address
// requests until any of them stops, which happens when the request stream or
// its connection ends.
func (s *Server) proxySession(
	ctx context.Context, log *slog.Logger, conn *connectip.Conn, sess BackendSession, assigned netip.Prefix,
) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer cancel()
		answerAddressRequests(ctx, log, conn, assigned)
	})
	wg.Go(func() {
		defer cancel()
		buf := make([]byte, maxPacketSize)
		for {
			n, err := conn.ReadPacket(buf)
			if err != nil {
				return
			}
			if err := sess.WritePacket(buf[:n]); err != nil {
				log.Warn("could not write packet to backend", "error", err)
				return
			}
		}
	})
	wg.Go(func() {
		defer cancel()
		buf := make([]byte, maxPacketSize)
		for {
			n, err := sess.ReadPacket(ctx, buf)
			if err != nil {
				return
			}
			icmp, err := conn.WritePacket(buf[:n])
			if err != nil {
				return
			}
			if icmp == nil {
				continue
			}
			if err := sess.WritePacket(icmp); err != nil {
				log.Warn("could not return ICMP error to backend", "error", err)
				return
			}
		}
	})
	<-ctx.Done()
	// ReadPacket only returns once the stream's receive side is closed.
	if err := conn.Close(); err != nil {
		log.Debug("could not close CONNECT-IP stream cleanly", "error", err)
	}
	wg.Wait()
}

// answerAddressRequests answers every ADDRESS_REQUEST with the request's one
// assigned address: the first IPv6 request receives it, every other request is
// rejected, and the address stays assigned either way. It returns when the
// stream closes or ctx is done.
func answerAddressRequests(ctx context.Context, log *slog.Logger, conn *connectip.Conn, assigned netip.Prefix) {
	for {
		req, err := conn.ReceiveAddressRequest(ctx)
		if err != nil {
			return
		}
		answers := make([]netip.Prefix, len(req.Prefixes))
		var given bool
		for i, p := range req.Prefixes {
			if !given && p.Addr().Is6() {
				answers[i] = assigned
				given = true
			}
		}
		var additional []netip.Prefix
		if !given {
			additional = []netip.Prefix{assigned}
		}
		if err := req.Respond(answers, additional); err != nil {
			log.Warn("could not answer address request", "error", err)
			return
		}
	}
}

func (s *Server) reject(w http.ResponseWriter, status int, reason string, err error) {
	s.log.Info("CONNECT-IP request rejected", "status", status, "reason", reason, "error", err)
	w.WriteHeader(status)
}

// authenticate returns the principal of the request's single bearer
// credential.
func (s *Server) authenticate(r *http.Request) (Principal, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return Principal{}, false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return Principal{}, false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return Principal{}, false
	}
	// Tokens are held by digest, so the lookup's timing depends on the
	// digest of what was presented, not on how much of a valid token it
	// shares.
	p, ok := s.credentials[sha256.Sum256([]byte(token))]
	return p, ok
}

// requestedVPC returns the single VPC named by the request.
func requestedVPC(r *http.Request) (string, bool) {
	values := r.Header.Values(VPCHeader)
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return "", false
	}
	name := strings.TrimSpace(values[0])
	return name, name != ""
}

// probeInnerMTU sends the client a datagram on the request's stream that is as
// large as a MinInnerMTU packet in context 0, but in an unregistered context
// so the client drops it. It returns an error when the QUIC connection cannot
// currently send a datagram of that size.
func probeInnerMTU(r *http.Request) error {
	conn, ok := r.Context().Value(quicConnKey{}).(*quic.Conn)
	if !ok {
		return errors.New("request has no QUIC connection")
	}
	body, ok := r.Body.(interface{ StreamID() quic.StreamID })
	if !ok {
		return errors.New("request has no stream ID")
	}
	probe := quicvarint.Append(nil, uint64(body.StreamID()/4))
	probe = quicvarint.Append(probe, probeContextID)
	probe = append(probe, make([]byte, MinInnerMTU)...)
	if err := conn.SendDatagram(probe); err != nil {
		if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			return fmt.Errorf("datagram of %d bytes exceeds the current maximum of %d bytes",
				len(probe), tooLarge.MaxDatagramPayloadSize)
		}
		return fmt.Errorf("could not send MTU probe: %w", err)
	}
	return nil
}

// routeRanges converts prefixes into a route advertisement sorted as RFC 9484
// requires. It returns an error for an invalid or overlapping prefix.
func routeRanges(prefixes []netip.Prefix) ([]connectip.IPRoute, error) {
	sorted := slices.Clone(prefixes)
	for i, p := range sorted {
		if !p.IsValid() {
			return nil, fmt.Errorf("route %d is invalid", i)
		}
		sorted[i] = p.Masked()
	}
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		return cmp.Or(cmp.Compare(a.Addr().BitLen(), b.Addr().BitLen()), a.Addr().Compare(b.Addr()))
	})
	routes := make([]connectip.IPRoute, 0, len(sorted))
	for i, p := range sorted {
		if i > 0 && sorted[i-1].Overlaps(p) {
			return nil, fmt.Errorf("routes %s and %s overlap", sorted[i-1], p)
		}
		routes = append(routes, connectip.IPRoute{StartIP: p.Addr(), EndIP: lastAddr(p)})
	}
	return routes, nil
}

// lastAddr returns the highest address in the masked prefix p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	offset := 0
	if p.Addr().Is4() {
		offset = 96
	}
	for bit := offset + p.Bits(); bit < 128; bit++ {
		b[bit/8] |= 0x80 >> (bit % 8)
	}
	if p.Addr().Is4() {
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return netip.AddrFrom16(b)
}
