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
	"time"

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

	// errExcessiveLoad is the HTTP/3 H3_EXCESSIVE_LOAD error code.
	errExcessiveLoad = 0x0107
)

// Default limits apply to each zero field of Limits. They are the initial
// per-pod targets in docs/designs/masque/contract.md; MaxSessions covers 32
// active connectors plus 32 replacements.
const (
	DefaultMaxConnections             = 128
	DefaultMaxConnectionsPerSource    = 8
	DefaultMaxStreamsPerConn          = 2
	DefaultMaxHeaderBytes             = 8 << 10
	DefaultHandshakeTimeout           = 5 * time.Second
	DefaultMaxAdmissions              = 16
	DefaultMaxAdmissionsPerCredential = 2
	DefaultMaxSessions                = 64
)

// Limits bound the work any client can make the server do before and after
// admission. A zero field takes its default.
type Limits struct {
	// MaxConnections caps open QUIC connections. The server closes a
	// connection over the cap with H3_EXCESSIVE_LOAD.
	MaxConnections int
	// MaxConnectionsPerSource caps the open QUIC connections from one
	// source IP address, closing the rest the same way. A connection counts
	// once its handshake completes. Clients behind one NAT share it.
	MaxConnectionsPerSource int
	// MaxStreamsPerConn caps the concurrent request streams of one
	// connection. It is QUIC's MaxIncomingStreams.
	MaxStreamsPerConn int
	// MaxHeaderBytes caps the size of a request's header section.
	MaxHeaderBytes int
	// HandshakeTimeout bounds a QUIC handshake from the client's first
	// packet. quic-go allows a handshake twice its HandshakeIdleTimeout, so
	// that is set to half of HandshakeTimeout.
	HandshakeTimeout time.Duration
	// MaxAdmissions caps the requests waiting on Admission.Admit at once.
	MaxAdmissions int
	// MaxAdmissionsPerCredential caps the requests waiting on
	// Admission.Admit at once with one bearer credential. It is checked
	// after MaxSessions and MaxAdmissions.
	MaxAdmissionsPerCredential int
	// MaxSessions caps the requests admitted at once.
	MaxSessions int
}

func (l Limits) withDefaults() Limits {
	return Limits{
		MaxConnections:             cmp.Or(l.MaxConnections, DefaultMaxConnections),
		MaxConnectionsPerSource:    cmp.Or(l.MaxConnectionsPerSource, DefaultMaxConnectionsPerSource),
		MaxStreamsPerConn:          cmp.Or(l.MaxStreamsPerConn, DefaultMaxStreamsPerConn),
		MaxHeaderBytes:             cmp.Or(l.MaxHeaderBytes, DefaultMaxHeaderBytes),
		HandshakeTimeout:           cmp.Or(l.HandshakeTimeout, DefaultHandshakeTimeout),
		MaxAdmissions:              cmp.Or(l.MaxAdmissions, DefaultMaxAdmissions),
		MaxAdmissionsPerCredential: cmp.Or(l.MaxAdmissionsPerCredential, DefaultMaxAdmissionsPerCredential),
		MaxSessions:                cmp.Or(l.MaxSessions, DefaultMaxSessions),
	}
}

// Config configures a Server.
type Config struct {
	// Authority is the host[:port] clients send as :authority.
	Authority string
	// TLSConfig holds the server certificate.
	TLSConfig *tls.Config
	// QUICConfig is optional; datagrams are always enabled, and
	// MaxIncomingStreams and HandshakeIdleTimeout come from Limits. When
	// nil, the initial packet size is DefaultInitialPacketSize.
	QUICConfig *quic.Config
	// Limits is optional; see Limits for the defaults.
	Limits Limits
	// Admission authenticates requests and supplies an authorized prefix lease.
	Admission Admission
	Backend   PacketBackend
	// Logger is optional and defaults to slog.Default().
	Logger *slog.Logger
}

// Server terminates CONNECT-IP requests over HTTP/3.
type Server struct {
	template  *uritemplate.Template
	admission Admission
	backend   PacketBackend
	log       *slog.Logger
	h3        *http3.Server
	proxy     connectip.Proxy

	// limits has every default applied. conns counts open QUIC
	// connections; admitting and active hold one token per request in Admit
	// and per admitted request.
	limits    Limits
	conns     atomic.Int64
	admitting chan struct{}
	active    chan struct{}

	// countMu guards the open connections of each source address and the
	// requests in Admit of each credential digest.
	countMu    sync.Mutex
	sources    map[netip.Addr]int
	credential map[[sha256.Size]byte]int

	mu       sync.Mutex
	closed   bool
	sessions sync.WaitGroup
}

type quicConnKey struct{}

// NewServer validates cfg and returns a Server. It returns an error when the
// authority, TLS config, admission authority or backend is missing.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Authority == "" {
		return nil, errors.New("authority is required")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("TLS config is required")
	}
	if cfg.Admission == nil {
		return nil, errors.New("admission is required")
	}
	if cfg.Backend == nil {
		return nil, errors.New("backend is required")
	}
	template, err := uritemplate.New("https://" + cfg.Authority + TemplatePath)
	if err != nil {
		return nil, fmt.Errorf("could not parse URI template: %w", err)
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	quicConf := &quic.Config{InitialPacketSize: DefaultInitialPacketSize}
	if cfg.QUICConfig != nil {
		quicConf = cfg.QUICConfig.Clone()
	}
	limits := cfg.Limits.withDefaults()
	quicConf.EnableDatagrams = true
	quicConf.MaxIncomingStreams = int64(limits.MaxStreamsPerConn)
	quicConf.HandshakeIdleTimeout = limits.HandshakeTimeout / 2

	s := &Server{
		template:   template,
		admission:  cfg.Admission,
		backend:    cfg.Backend,
		log:        log,
		limits:     limits,
		admitting:  make(chan struct{}, limits.MaxAdmissions),
		active:     make(chan struct{}, limits.MaxSessions),
		sources:    map[netip.Addr]int{},
		credential: map[[sha256.Size]byte]int{},
	}
	s.h3 = &http3.Server{
		Handler:         s,
		EnableDatagrams: true,
		MaxHeaderBytes:  limits.MaxHeaderBytes,
		TLSConfig:       http3.ConfigureTLSConfig(cfg.TLSConfig),
		QUICConfig:      quicConf,
		Logger:          log,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			s.countConn(c)
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
	token, ok := bearerToken(r)
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
	if !s.startSession() {
		s.reject(w, http.StatusServiceUnavailable, "server is closing", nil)
		return
	}
	defer s.sessions.Done()
	// Every cap is taken before Admit, so an unauthenticated client cannot
	// queue work behind them. The global caps come first, so a flood of
	// credentials spends no digest work.
	if !tryAcquire(s.active) {
		s.reject(w, http.StatusServiceUnavailable, "too many sessions", nil)
		return
	}
	defer release(s.active)
	if !tryAcquire(s.admitting) {
		s.reject(w, http.StatusServiceUnavailable, "too many admissions in progress", nil)
		return
	}
	lease, admitted, err := s.admit(r.Context(), token, vpcName)
	if !admitted {
		s.reject(w, http.StatusServiceUnavailable, "too many admissions in progress for one credential", nil)
		return
	}
	if err != nil {
		s.reject(w, admissionStatus(w, err), "admission rejected", err)
		return
	}
	if lease == nil {
		s.reject(w, http.StatusServiceUnavailable, "missing admission lease", nil)
		return
	}
	defer func() {
		if err := lease.Close(); err != nil {
			s.log.Warn("could not release admission lease", "error", err)
		}
	}()
	info := lease.Info()
	routes, err := routeRanges(lease.Routes())
	if err != nil || !validGrant(info, lease.Routes(), vpcName) || lease.Done() == nil {
		s.reject(w, http.StatusServiceUnavailable, "invalid admission grant", err)
		return
	}
	select {
	case <-lease.Done():
		s.reject(w, http.StatusServiceUnavailable, "admission expired", nil)
		return
	default:
	}
	// Only an admitted client may receive the probe datagram.
	if err := probeInnerMTU(r); err != nil {
		s.reject(w, http.StatusServiceUnavailable, "path cannot carry the minimum inner MTU", err)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-lease.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-watchDone }()
	log := s.log.With("session", info.ID, "principal", info.Principal, "vpc", info.VPC, "prefix", info.Prefix)
	sess, err := s.backend.Open(ctx, info)
	if err != nil {
		s.reject(w, http.StatusServiceUnavailable, "backend unavailable", err)
		return
	}
	defer func() {
		if err := sess.Close(); err != nil {
			log.Warn("could not close backend session", "error", err)
		}
	}()

	if err := ctx.Err(); err != nil {
		s.reject(w, http.StatusServiceUnavailable, "admission expired during setup", err)
		return
	}
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
	// Expiry must also unblock capsule writes before packet workers start.
	stopExpiry := context.AfterFunc(ctx, func() {
		if err := conn.Close(); err != nil {
			log.Debug("could not close expired tunnel", "error", err)
		}
	})
	defer stopExpiry()
	if err := conn.AssignAddresses([]netip.Prefix{info.Prefix}); err != nil {
		log.Warn("could not assign address", "error", err)
		return
	}
	if err := conn.AdvertiseRoute(routes); err != nil {
		log.Warn("could not advertise routes", "error", err)
		return
	}
	log.Info("CONNECT-IP request accepted")
	s.proxySession(ctx, log, conn, sess, newPacketPolicy(info.Prefix, lease.Routes()))
	log.Info("CONNECT-IP request ended")
}

// countConn counts c until it closes, and closes it at once when it would
// exceed the connection cap. Its source address counts only once the
// handshake completes, which proves the client receives at that address, so
// spoofed Initial packets cannot spend a victim's per-source slots.
func (s *Server) countConn(c *quic.Conn) {
	n := s.conns.Add(1)
	context.AfterFunc(c.Context(), func() { s.conns.Add(-1) })
	if n > int64(s.limits.MaxConnections) {
		s.closeConn(c, "too many connections")
		return
	}
	go func() {
		select {
		case <-c.HandshakeComplete():
		case <-c.Context().Done():
			return
		}
		src := sourceAddr(c.RemoteAddr())
		s.countMu.Lock()
		s.sources[src]++
		fromSrc := s.sources[src]
		s.countMu.Unlock()
		context.AfterFunc(c.Context(), func() {
			s.countMu.Lock()
			defer s.countMu.Unlock()
			if s.sources[src]--; s.sources[src] == 0 {
				delete(s.sources, src)
			}
		})
		if fromSrc > s.limits.MaxConnectionsPerSource {
			s.closeConn(c, "too many connections from one source")
		}
	}()
}

func (s *Server) closeConn(c *quic.Conn, reason string) {
	s.log.Info("QUIC connection rejected", "reason", reason, "remote", c.RemoteAddr())
	_ = c.CloseWithError(errExcessiveLoad, reason)
}

// admit calls Admission.Admit while holding one of the credential's
// admission slots, and releases it and the global admission slot the caller
// took, even if Admit panics. admitted is false when the credential has no
// slot free; Admit then did not run.
func (s *Server) admit(ctx context.Context, token, vpc string) (lease Lease, admitted bool, err error) {
	defer release(s.admitting)
	digest := sha256.Sum256([]byte(token))
	if !s.acquireCredential(digest) {
		return nil, false, nil
	}
	defer s.releaseCredential(digest)
	lease, err = s.admission.Admit(ctx, token, vpc)
	return lease, true, err
}

// sourceAddr returns the IP address a connection comes from, with an
// IPv4-mapped IPv6 address unmapped, so one client counts once.
func sourceAddr(a net.Addr) netip.Addr {
	if u, ok := a.(*net.UDPAddr); ok {
		return u.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// acquireCredential takes one of digest's admission slots without waiting.
func (s *Server) acquireCredential(digest [sha256.Size]byte) bool {
	s.countMu.Lock()
	defer s.countMu.Unlock()
	if s.credential[digest] >= s.limits.MaxAdmissionsPerCredential {
		return false
	}
	s.credential[digest]++
	return true
}

func (s *Server) releaseCredential(digest [sha256.Size]byte) {
	s.countMu.Lock()
	defer s.countMu.Unlock()
	if s.credential[digest]--; s.credential[digest] == 0 {
		delete(s.credential, digest)
	}
}

// tryAcquire takes a token from sem without waiting.
func tryAcquire(sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(sem chan struct{}) { <-sem }

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

// proxySession forwards the packets policy allows in both directions and
// answers address requests until any of them stops, which happens when the
// request stream or its connection ends. A refused packet is dropped and
// counted. connect-ip-go checks a packet's addresses as well, before this
// policy sees a client packet and after it passes a gVPC one; it drops
// what it refuses without counting it.
func (s *Server) proxySession(
	ctx context.Context, log *slog.Logger, conn *connectip.Conn, sess BackendSession, policy *packetPolicy,
) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer cancel()
		answerAddressRequests(ctx, log, conn, policy.prefix)
	})
	wg.Go(func() {
		defer cancel()
		buf := make([]byte, maxPacketSize)
		for {
			n, err := conn.ReadPacket(buf)
			if err != nil {
				return
			}
			if reason := policy.fromClient(buf[:n]); reason != "" {
				deny(toVPC, reason)
				continue
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
			if reason := policy.toClient(buf[:n]); reason != "" {
				deny(toClient, reason)
				continue
			}
			icmp, err := conn.WritePacket(buf[:n])
			if err != nil {
				return
			}
			if icmp == nil {
				continue
			}
			// The library's Packet Too Big comes from the client's address,
			// so it passes the same checks as the client's own packets.
			if reason := policy.fromClient(icmp); reason != "" {
				deny(toVPC, reason)
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
	if err := sess.Close(); err != nil {
		log.Warn("could not stop backend session", "error", err)
	}
	wg.Wait()
}

// answerAddressRequests answers every ADDRESS_REQUEST with the request's one
// assigned prefix: the first IPv6 request receives it, every other request is
// rejected, and the prefix stays assigned either way. It returns when the
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

// admissionStatus returns the HTTP status for an Admit error, and asks for a
// bearer credential when the error is ErrUnauthenticated.
func admissionStatus(w http.ResponseWriter, err error) int {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", "Bearer")
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	default:
		return http.StatusServiceUnavailable
	}
}

func (s *Server) reject(w http.ResponseWriter, status int, reason string, err error) {
	s.log.Info("CONNECT-IP request rejected", "status", status, "reason", reason, "error", err)
	w.WriteHeader(status)
}

// bearerToken extracts exactly one nonempty bearer credential.
func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// validGrant reports whether admission returned a complete grant for vpc.
// Only IPv6 is carried, so a grant that routes IPv4 is refused rather than
// advertised.
func validGrant(info SessionInfo, routes []netip.Prefix, vpc string) bool {
	p := info.Prefix
	if slices.ContainsFunc(routes, func(r netip.Prefix) bool { return !r.Addr().Is6() || r.Addr().Is4In6() }) {
		return false
	}
	return info.VPC == vpc && info.Principal != "" && info.Connector != "" && info.Attachment != "" &&
		info.Claim != "" && info.Epoch != 0 && p.IsValid() && p.Addr().Is6() && !p.Addr().Is4In6() &&
		p.Bits() == 96 && p == p.Masked()
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
