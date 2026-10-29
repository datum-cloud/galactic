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
	"github.com/quic-go/quic-go/qlogwriter"
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

	// DefaultInitialPacketSize is the QUIC packet size the server uses when
	// Config.QUICConfig is nil. It leaves room for a MinInnerMTU packet
	// plus QUIC, HTTP Datagram and context ID overhead. The server never
	// grows it; see pathwatch.go.
	DefaultInitialPacketSize = 1350

	connectIPProtocol = "connect-ip"

	// probeContextID is a proxy-allocated context ID that is never
	// registered, so a client drops a datagram carrying it.
	probeContextID = 1

	maxPacketSize = 65535

	// errExcessiveLoad is the HTTP/3 H3_EXCESSIVE_LOAD error code.
	errExcessiveLoad = 0x0107
)

// deliveryTimeout bounds one write toward a client, a packet or an HTTP/2
// capsule. A client that stops receiving for longer ends its own session.
// Tests shorten it.
var deliveryTimeout = 5 * time.Second

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
	// MaxConnections caps open QUIC and TCP connections together. The
	// server closes a QUIC connection over the cap with H3_EXCESSIVE_LOAD,
	// and a TCP connection as soon as it is accepted.
	MaxConnections int
	// MaxConnectionsPerSource caps the open QUIC and TCP connections from
	// one source IP address, closing the rest the same way. A QUIC
	// connection counts once its handshake completes, a TCP connection once
	// it is accepted. Clients behind one NAT share it.
	MaxConnectionsPerSource int
	// MaxStreamsPerConn caps the concurrent request streams of one
	// connection. It is QUIC's MaxIncomingStreams and HTTP/2's
	// SETTINGS_MAX_CONCURRENT_STREAMS.
	MaxStreamsPerConn int
	// MaxHeaderBytes caps the size of a request's header section.
	MaxHeaderBytes int
	// HandshakeTimeout bounds a QUIC handshake from the client's first
	// packet, and a TLS handshake on TCP. quic-go allows a handshake twice
	// its HandshakeIdleTimeout, so that is set to half of HandshakeTimeout.
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
	// QUICConfig is optional; datagrams are always enabled, path MTU
	// discovery is always disabled, and MaxIncomingStreams and
	// HandshakeIdleTimeout come from Limits. Its InitialPacketSize is the
	// fixed QUIC packet size, DefaultInitialPacketSize when nil. A Tracer
	// still receives every event.
	QUICConfig *quic.Config
	// Limits is optional; see Limits for the defaults.
	Limits Limits
	// Admission authenticates requests and supplies an authorized prefix lease.
	Admission Admission
	Backend   PacketBackend
	// Logger is optional and defaults to slog.Default().
	Logger *slog.Logger
}

// Server terminates CONNECT-IP requests over HTTP/3 and HTTP/2.
type Server struct {
	authority string
	template  *uritemplate.Template
	admission Admission
	backend   PacketBackend
	log       *slog.Logger
	h3        *http3.Server
	h2        *http.Server
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

// pathWatchKey is the request context key of its connection's pathWatch.
type pathWatchKey struct{}

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
	// quic-go never shrinks a size it discovered, so a path that shrank
	// would drop packets the Packet Too Big check let through.
	quicConf.DisablePathMTUDiscovery = true
	innerTracer := quicConf.Tracer
	quicConf.Tracer = func(ctx context.Context, isClient bool, id quic.ConnectionID) qlogwriter.Trace {
		var inner qlogwriter.Trace
		if innerTracer != nil {
			inner = innerTracer(ctx, isClient, id)
		}
		return newPathWatch(inner, log)
	}
	quicConf.MaxIncomingStreams = int64(limits.MaxStreamsPerConn)
	quicConf.HandshakeIdleTimeout = limits.HandshakeTimeout / 2

	s := &Server{
		authority:  cfg.Authority,
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
			if w, ok := c.QlogTrace().(*pathWatch); ok {
				w.attach(c)
				ctx = context.WithValue(ctx, pathWatchKey{}, w)
			}
			return context.WithValue(ctx, quicConnKey{}, c)
		},
	}
	var h2Only http.Protocols
	h2Only.SetHTTP2(true)
	h2TLS := cfg.TLSConfig.Clone()
	h2TLS.NextProtos = []string{"h2"}
	s.h2 = &http.Server{
		Handler:   s,
		TLSConfig: h2TLS,
		Protocols: &h2Only,
		// net/http bounds the TLS handshake by ReadHeaderTimeout. HTTP/2
		// streams then run without a read or write deadline.
		ReadHeaderTimeout: limits.HandshakeTimeout,
		IdleTimeout:       h2IdleTimeout,
		MaxHeaderBytes:    limits.MaxHeaderBytes,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: limits.MaxStreamsPerConn,
			SendPingTimeout:      h2PingTimeout,
			PingTimeout:          h2PingTimeout,
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	return s, nil
}

// Serve serves CONNECT-IP over HTTP/3 on conn until the server is closed.
func (s *Server) Serve(conn net.PacketConn) error {
	return s.h3.Serve(conn)
}

// Close closes every listener and connection and waits for every session to
// end.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	err := errors.Join(s.h3.Close(), s.h2.Close())
	s.sessions.Wait()
	return err
}

// ServeHTTP admits a CONNECT-IP request over HTTP/3 or HTTP/2 and, once
// admitted, proxies its packets until the request or its connection ends.
// Both transports share every step after parsing: limits, admission, grant
// checks, the backend session and the packet policy.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.ProtoMajor {
	case 3:
		s.serveH3(w, r)
	case 2:
		s.serveH2(w, r)
	default:
		s.reject(w, r, http.StatusHTTPVersionNotSupported, outcomeBadRequest, "CONNECT-IP needs HTTP/3 or HTTP/2", nil)
	}
}

func (s *Server) serveH3(w http.ResponseWriter, r *http.Request) {
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
		s.reject(w, r, status, outcomeBadRequest, "invalid CONNECT-IP request", err)
		return
	}
	if r.URL.Path != TemplatePath {
		s.reject(w, r, http.StatusNotFound, outcomeBadRequest, "unknown path", nil)
		return
	}
	s.serve(w, r, &h3Request{r: r, preq: preq, proxy: &s.proxy})
}

// transport is what one request's HTTP version supplies to serve.
type transport interface {
	// probe checks, after admission, that the path can carry a
	// MinInnerMTU packet toward the client.
	probe(ctx context.Context) error
	// accept answers the request with 2xx and returns its tunnel.
	accept(w http.ResponseWriter) (tunnel, error)
}

// tunnel is an accepted CONNECT-IP request. ReadPacket returns client
// packets and WritePacket sends packets to the client, returning an ICMP
// error for the backend when the packet cannot be sent. Close must be
// idempotent and unblock every other method.
type tunnel interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) (icmp []byte, err error)
	AssignAddresses(prefixes []netip.Prefix) error
	AdvertiseRoute(routes []connectip.IPRoute) error
	receiveAddressRequest(ctx context.Context) (addressRequest, error)
	// pathLost returns a channel closed once the path toward the client
	// stops carrying MinInnerMTU packets, or nil when the transport cannot
	// lose them silently.
	pathLost() <-chan struct{}
	Close() error
	// abort closes whatever must close to unblock a WritePacket that the
	// client has stopped draining.
	abort()
}

// addressRequest is one ADDRESS_REQUEST. respond takes one assignment per
// requested prefix, where the zero Prefix rejects it, and any unsolicited
// assignments.
type addressRequest struct {
	prefixes []netip.Prefix
	respond  func(assigned, additional []netip.Prefix) error
}

// serve runs the transport-neutral part of a parsed request.
func (s *Server) serve(w http.ResponseWriter, r *http.Request, t transport) {
	token, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.reject(w, r, http.StatusUnauthorized, outcomeUnauthenticated, "missing or unknown credential", nil)
		return
	}
	vpcName, ok := requestedVPC(r)
	if !ok {
		s.reject(w, r, http.StatusBadRequest, outcomeBadRequest, "request must name exactly one VPC", nil)
		return
	}
	if !s.startSession() {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeUnavailable, "server is closing", nil)
		return
	}
	defer s.sessions.Done()
	// Every cap is taken before Admit, so an unauthenticated client cannot
	// queue work behind them. The global caps come first, so a flood of
	// credentials spends no digest work.
	if !tryAcquire(s.active) {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeLimited, "too many sessions", nil)
		return
	}
	defer release(s.active)
	if !tryAcquire(s.admitting) {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeLimited, "too many admissions in progress", nil)
		return
	}
	transport := transportOf(r)
	lease, admitted, err := s.admit(r.Context(), transport, token, vpcName)
	if !admitted {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeLimited,
			"too many admissions in progress for one credential", nil)
		return
	}
	if err != nil {
		status, outcome := admissionStatus(w, err)
		s.reject(w, r, status, outcome, "admission rejected", err)
		return
	}
	if lease == nil {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeInvalidGrant, "missing admission lease", nil)
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
		s.reject(w, r, http.StatusServiceUnavailable, outcomeInvalidGrant, "invalid admission grant", err)
		return
	}
	select {
	case <-lease.Done():
		s.reject(w, r, http.StatusServiceUnavailable, outcomeExpired, "admission expired", nil)
		return
	default:
	}
	// Only an admitted client may receive the probe datagram.
	if err := t.probe(r.Context()); err != nil {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeMTU, "path cannot carry the minimum inner MTU", err)
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
	log := s.log.With("transport", transport, "session", info.ID, "connector", info.Connector,
		"principal", info.Principal, "vpc", info.VPC, "prefix", info.Prefix, "attachment", info.Attachment,
		"claim", info.Claim, "epoch", info.Epoch)
	sess, err := s.backend.Open(ctx, info)
	if err != nil {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeBackendUnavailable, "backend unavailable", err)
		return
	}
	defer func() {
		if err := sess.Close(); err != nil {
			log.Warn("could not close backend session", "error", err)
		}
	}()

	if err := ctx.Err(); err != nil {
		s.reject(w, r, http.StatusServiceUnavailable, outcomeExpired, "admission expired during setup", err)
		return
	}
	conn, err := t.accept(w)
	if err != nil {
		requestsTotal.WithLabelValues(transport, outcomeAcceptFailed).Inc()
		log.Warn("could not accept request", "outcome", outcomeAcceptFailed, "error", err)
		return
	}
	requestsTotal.WithLabelValues(transport, outcomeAccepted).Inc()
	tunnels := openTunnels.WithLabelValues(transport)
	tunnels.Inc()
	defer tunnels.Dec()
	accepted := time.Now()
	cause := causeSetupFailed
	defer func() {
		cause = s.endCause(lease, cause)
		tunnelEnds.WithLabelValues(transport, cause).Inc()
		log.Info("CONNECT-IP request ended", "cause", cause, "duration", time.Since(accepted))
	}()
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
	cause = s.proxySession(ctx, log, conn, sess, newPacketPolicy(info.Prefix, lease.Routes()),
		newForwardCounters(transport))
}

// endCause returns why an accepted request ended: the lease ending or the
// server closing, which also break the tunnel, take precedence over cause,
// what the tunnel itself saw.
func (s *Server) endCause(lease Lease, cause string) string {
	select {
	case <-lease.Done():
		return causeLeaseEnded
	default:
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return causeServerClosed
	}
	return cause
}

// countConn counts c until it closes, and closes it at once when it would
// exceed the connection cap. Its source address counts only once the
// handshake completes, which proves the client receives at that address, so
// spoofed Initial packets cannot spend a victim's per-source slots.
func (s *Server) countConn(c *quic.Conn) {
	n := s.conns.Add(1)
	open := openConnections.WithLabelValues(transportH3)
	open.Inc()
	context.AfterFunc(c.Context(), func() {
		s.conns.Add(-1)
		open.Dec()
	})
	if n > int64(s.limits.MaxConnections) {
		s.closeConn(c, connReasonTotal)
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
			s.closeConn(c, connReasonPerSource)
		}
	}()
}

func (s *Server) closeConn(c *quic.Conn, reason string) {
	connsRejected.WithLabelValues(transportH3, reason).Inc()
	s.log.Info("QUIC connection rejected", "reason", reason, "remote", c.RemoteAddr())
	_ = c.CloseWithError(errExcessiveLoad, reason)
}

// admit calls Admission.Admit while holding one of the credential's
// admission slots, and releases it and the global admission slot the caller
// took, even if Admit panics. admitted is false when the credential has no
// slot free; Admit then did not run.
func (s *Server) admit(ctx context.Context, transport, token, vpc string) (lease Lease, admitted bool, err error) {
	defer release(s.admitting)
	digest := sha256.Sum256([]byte(token))
	if !s.acquireCredential(digest) {
		return nil, false, nil
	}
	defer s.releaseCredential(digest)
	inProgress := admissionsInProgress.WithLabelValues(transport)
	inProgress.Inc()
	defer inProgress.Dec()
	start := time.Now()
	defer func() { admissionSeconds.WithLabelValues(transport).Observe(time.Since(start).Seconds()) }()
	lease, err = s.admission.Admit(ctx, token, vpc)
	return lease, true, err
}

// sourceAddr returns the IP address a connection comes from, with an
// IPv4-mapped IPv6 address unmapped, so one client counts once.
func sourceAddr(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.UDPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
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
// what it refuses without counting it. It returns the cause of the first
// direction to stop: causeLeaseEnded, causePathMTU, causeSlowClient,
// causeBackendError or causeClientClosed.
func (s *Server) proxySession(
	ctx context.Context, log *slog.Logger, conn tunnel, sess BackendSession, policy *packetPolicy,
	fwd forwardCounters,
) string {
	ctx, cancel := context.WithCancel(ctx)
	var causeOnce sync.Once
	cause := causeClientClosed
	stop := func(c string) {
		causeOnce.Do(func() { cause = c })
		cancel()
	}
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
				stop(causeClientClosed)
				return
			}
			if reason := policy.fromClient(buf[:n]); reason != "" {
				deny(toVPC, reason)
				continue
			}
			if err := sess.WritePacket(buf[:n]); err != nil {
				stop(backendCause(log, "could not write packet to backend", err))
				return
			}
			fwd.toVPC(n)
		}
	})
	if lost := conn.pathLost(); lost != nil {
		wg.Go(func() {
			select {
			case <-ctx.Done():
			case <-lost:
				// The path drops MinInnerMTU packets without an error, so
				// the dropped packet is counted here, as one.
				deny(toClient, reasonPathMTU)
				log.Warn("ending CONNECT-IP session: path stopped carrying the minimum inner MTU",
					"minimum", MinInnerMTU)
				stop(causePathMTU)
			}
		})
	}
	clock := &deliveryClock{base: time.Now()}
	wg.Go(func() {
		defer cancel()
		watchDelivery(ctx, log, conn, clock, stop)
	})
	wg.Go(func() {
		defer cancel()
		buf := make([]byte, maxPacketSize)
		for {
			n, err := sess.ReadPacket(ctx, buf)
			if err != nil {
				// A cancelled context is another direction's stop, which
				// set the cause, or the request or lease ending, which
				// serve tells apart.
				if ctx.Err() != nil {
					stop(causeClientClosed)
				} else {
					stop(backendCause(log, "could not read packet from backend", err))
				}
				return
			}
			if reason := policy.toClient(buf[:n]); reason != "" {
				deny(toClient, reason)
				continue
			}
			clock.start()
			icmp, err := conn.WritePacket(buf[:n])
			clock.done()
			if err != nil {
				stop(causeClientClosed)
				return
			}
			if icmp == nil {
				fwd.toClient(n)
				continue
			}
			// A packet no larger than MinInnerMTU that does not fit means the
			// path can no longer carry the IPv6 minimum. Its sender cannot
			// go smaller, so a Packet Too Big would only black-hole it: RFC
			// 9484 section 10.1 ends the tunnel instead.
			if n <= MinInnerMTU {
				deny(toClient, reasonPathMTU)
				log.Warn("ending CONNECT-IP session: path cannot carry the minimum inner MTU",
					"packet", n, "minimum", MinInnerMTU)
				stop(causePathMTU)
				return
			}
			// The library's Packet Too Big comes from the client's address,
			// so it passes the same checks as the client's own packets.
			if reason := policy.fromClient(icmp); reason != "" {
				deny(toVPC, reason)
				continue
			}
			if err := sess.WritePacket(icmp); err != nil {
				stop(backendCause(log, "could not return ICMP error to backend", err))
				return
			}
			fwd.toVPC(len(icmp))
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
	return cause
}

// backendCause returns the end cause of a backend read or write that failed
// with err. A backend that stopped because the request's lease ended
// reports ErrLeaseEnded, which is the lease's end and not a device fault.
func backendCause(log *slog.Logger, msg string, err error) string {
	if errors.Is(err, ErrLeaseEnded) {
		log.Debug(msg, "error", err)
		return causeLeaseEnded
	}
	log.Warn(msg, "error", err)
	return causeBackendError
}

// deliveryClock times the writes toward one client for watchDelivery.
// Times are durations since base plus one, so 0 means unset.
//
// A stall is timed from the first write that waited, not from the first
// slow one. A slow write takes at least a quarter of deliveryTimeout, and a
// waiting write at least 1/256 of it. A QUIC connection to a client that
// stopped reading still drains a datagram per probe timeout, and those
// timeouts double from below the slow threshold, so a stall's first writes
// wait without being slow. Since they double, the writes before the first
// slow one span less than half of deliveryTimeout, which bounds how far back
// a stall is timed from.
type deliveryClock struct {
	base time.Time
	// writing is when the write in progress began.
	writing atomic.Int64
	// waiting is when the first waiting write of the current run began. The
	// run ends after promptStreak writes in a row that are not slow, after
	// quickStreak writes in a row that do not wait, or when the writer waits
	// a quarter of deliveryTimeout for a packet. Each QUIC probe timeout
	// frees two datagram slots, so a stalled client's waiting writes
	// alternate with ones that do not wait.
	waiting atomic.Int64
	// slowSince is when the run's stall began, once the run has a slow write.
	slowSince atomic.Int64
	// lastEnd is when the last write returned, prompt counts the writes in a
	// row since the run's last slow write that were not slow, and quick
	// counts the writes in a row that did not wait. Only the writer uses
	// them.
	lastEnd int64
	prompt  int
	quick   int
}

const (
	// promptStreak is how many prompt writes in a row end a run of slow ones.
	promptStreak = 16
	// quickStreak is how many writes in a row that do not wait end a run. A
	// stalled QUIC connection never returns two in a row.
	quickStreak = 3
)

func (c *deliveryClock) now() int64 { return int64(time.Since(c.base)) + 1 }

func (c *deliveryClock) start() {
	now := c.now()
	if c.lastEnd != 0 && time.Duration(now-c.lastEnd) >= deliveryTimeout/4 {
		c.endRun()
	}
	c.writing.Store(now)
}

func (c *deliveryClock) done() {
	now, began := c.now(), c.writing.Swap(0)
	c.lastEnd = now
	took := time.Duration(now - began)
	if took < deliveryTimeout/256 {
		if c.quick++; c.quick >= quickStreak {
			c.endRun()
			return
		}
	} else {
		c.quick = 0
		c.waiting.CompareAndSwap(0, began)
	}
	if took < deliveryTimeout/4 {
		if c.waiting.Load() != 0 {
			if c.prompt++; c.prompt >= promptStreak {
				c.endRun()
			}
		}
		return
	}
	c.prompt = 0
	c.slowSince.CompareAndSwap(0, c.stallStart(began))
}

func (c *deliveryClock) endRun() {
	c.waiting.Store(0)
	c.slowSince.Store(0)
	c.prompt = 0
	c.quick = 0
}

// stallStart returns when the stall around a slow write that began at began
// started: at the run's first waiting write, or at began when the run has
// none yet, and at most half of deliveryTimeout before began.
func (c *deliveryClock) stallStart(began int64) int64 {
	w := c.waiting.Load()
	if w == 0 {
		w = began
	}
	return max(w, began-int64(deliveryTimeout/2))
}

// blocked returns how long delivery has been stuck while a write is in
// progress: since the current stall began once the run or the write in
// progress is slow, or else since the write began.
func (c *deliveryClock) blocked() time.Duration {
	began := c.writing.Load()
	if began == 0 {
		return 0
	}
	now := c.now()
	if slow := c.slowSince.Load(); slow != 0 {
		return time.Duration(now - slow)
	}
	if time.Duration(now-began) >= deliveryTimeout/4 {
		return time.Duration(now - c.stallStart(began))
	}
	return time.Duration(now - began)
}

// watchDelivery ends a session whose delivery toward the client has been
// stuck for deliveryTimeout, checked every quarter of it, and counts it as
// denied with reason slow_client. Stuck means one write blocked that long,
// or back-to-back waiting writes, at least one of them slow, for that long:
// a QUIC connection to a client that stopped reading still drains one
// datagram per probe timeout, and those timeouts double from a fraction of a
// second; see deliveryClock.
// Over HTTP/3 ending the session closes the client's QUIC connection, since
// a blocked datagram waits on the connection's send queue; the
// connection's other request is stalled by the same client. It returns when
// ctx is done or the session is aborted.
func watchDelivery(
	ctx context.Context, log *slog.Logger, conn tunnel, clock *deliveryClock, stop func(cause string),
) {
	t := time.NewTicker(deliveryTimeout / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if clock.blocked() < deliveryTimeout {
			continue
		}
		deny(toClient, reasonSlowClient)
		log.Warn("ending CONNECT-IP session: the client stopped receiving", "blocked", deliveryTimeout)
		stop(causeSlowClient)
		conn.abort()
		return
	}
}

// answerAddressRequests answers every ADDRESS_REQUEST with the request's one
// assigned prefix: the first IPv6 request receives it, every other request is
// rejected, and the prefix stays assigned either way. It returns when the
// stream closes or ctx is done.
func answerAddressRequests(ctx context.Context, log *slog.Logger, conn tunnel, assigned netip.Prefix) {
	for {
		req, err := conn.receiveAddressRequest(ctx)
		if err != nil {
			return
		}
		answers := make([]netip.Prefix, len(req.prefixes))
		var given bool
		for i, p := range req.prefixes {
			if !given && p.Addr().Is6() {
				answers[i] = assigned
				given = true
			}
		}
		var additional []netip.Prefix
		if !given {
			additional = []netip.Prefix{assigned}
		}
		if err := req.respond(answers, additional); err != nil {
			log.Warn("could not answer address request", "error", err)
			return
		}
	}
}

// admissionStatus returns the HTTP status and outcome for an Admit error,
// and asks for a bearer credential when the error is ErrUnauthenticated.
func admissionStatus(w http.ResponseWriter, err error) (int, string) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", "Bearer")
		return http.StatusUnauthorized, outcomeUnauthenticated
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden, outcomeForbidden
	default:
		return http.StatusServiceUnavailable, outcomeUnavailable
	}
}

// reject answers r with status and counts it under outcome. reason is the
// log's free text; err may carry identities and stays out of every metric.
func (s *Server) reject(w http.ResponseWriter, r *http.Request, status int, outcome, reason string, err error) {
	transport := transportOf(r)
	requestsTotal.WithLabelValues(transport, outcome).Inc()
	s.log.Info("CONNECT-IP request rejected", "transport", transport, "status", status, "outcome", outcome,
		"reason", reason, "error", err)
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

// h3Request is a CONNECT-IP request over HTTP/3, served by connect-ip-go.
type h3Request struct {
	r     *http.Request
	preq  *connectip.ProxyRequest
	proxy *connectip.Proxy
}

// probe sends the client MinInnerMTU probes on the request's stream and
// waits until the path acknowledges one; see pathWatch.confirm.
func (h *h3Request) probe(ctx context.Context) error {
	w, ok := h.r.Context().Value(pathWatchKey{}).(*pathWatch)
	if !ok {
		return errors.New("request has no QUIC path watch")
	}
	id, err := requestStreamID(h.r)
	if err != nil {
		return err
	}
	return w.confirm(ctx, id)
}

func (h *h3Request) accept(w http.ResponseWriter) (tunnel, error) {
	conn, err := h.proxy.Proxy(w, h.preq)
	if err != nil {
		return nil, err
	}
	t := h3Tunnel{Conn: conn}
	t.qconn, _ = h.r.Context().Value(quicConnKey{}).(*quic.Conn)
	if watch, ok := h.r.Context().Value(pathWatchKey{}).(*pathWatch); ok {
		if id, err := requestStreamID(h.r); err == nil {
			watch.useStream(id)
		}
		t.lost = watch.pathLost()
	}
	return t, nil
}

type h3Tunnel struct {
	*connectip.Conn
	qconn *quic.Conn
	lost  <-chan struct{}
}

func (t h3Tunnel) pathLost() <-chan struct{} { return t.lost }

func (t h3Tunnel) abort() {
	_ = t.Close()
	if t.qconn != nil {
		_ = t.qconn.CloseWithError(errExcessiveLoad, "client stopped receiving")
	}
}

func (t h3Tunnel) receiveAddressRequest(ctx context.Context) (addressRequest, error) {
	req, err := t.ReceiveAddressRequest(ctx)
	if err != nil {
		return addressRequest{}, err
	}
	return addressRequest{prefixes: req.Prefixes, respond: req.Respond}, nil
}

// requestStreamID returns the QUIC stream ID of an HTTP/3 request.
func requestStreamID(r *http.Request) (quic.StreamID, error) {
	body, ok := r.Body.(interface{ StreamID() quic.StreamID })
	if !ok {
		return 0, errors.New("request has no stream ID")
	}
	return body.StreamID(), nil
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
