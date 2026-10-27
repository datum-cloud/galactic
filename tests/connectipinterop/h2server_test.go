// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectipinterop

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/quicvarint"

	"go.datum.net/galactic/internal/edge/connectip"
)

// maxPacketSize is the largest IP packet either server forwards.
const maxPacketSize = 1500

// protocolConnectIP is the Extended CONNECT protocol of RFC 9484.
const protocolConnectIP = "connect-ip"

// h2WriteTimeout bounds one blocked capsule write, so a client that stops
// reading ends its own request instead of holding its session.
const h2WriteTimeout = 5 * time.Second

// h2Server is the HTTP/2 CONNECT-IP prototype: Extended CONNECT from net/http
// and the capsule codec in capsule_test.go, over the same Admission and
// PacketBackend interfaces as connectip.Server. It applies the packet checks
// connect-ip-go applies on HTTP/3: a packet from the client must carry a source
// in its /96 and a destination in an advertised route; a packet toward the
// client must carry a destination in its /96 and a hop limit above one, which
// is decremented on encapsulation only (RFC 9484, Section 7.2). It accepts IPv6
// only and drops every other datagram.
type h2Server struct {
	// authority is the only :authority the server accepts.
	authority string
	admission connectip.Admission
	backend   connectip.PacketBackend
	log       *slog.Logger
	observe   func(proto string)
}

func (s *h2Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// net/http's HTTP/2 server exposes Extended CONNECT's :protocol
	// pseudo-header as a request header of that name.
	if r.Method != http.MethodConnect || r.Header.Get(":protocol") != protocolConnectIP {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Host != s.authority {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.URL.Path != connectip.TemplatePath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if v, ok := r.Header["Capsule-Protocol"]; ok && (len(v) != 1 || v[0] != "?1") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	vpc := r.Header.Values(connectip.VPCHeader)
	if len(vpc) != 1 || vpc[0] == "" || strings.Contains(vpc[0], ",") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	lease, err := s.admission.Admit(r.Context(), token, vpc[0])
	switch {
	case errors.Is(err, connectip.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	case errors.Is(err, connectip.ErrForbidden):
		w.WriteHeader(http.StatusForbidden)
		return
	case err != nil || lease == nil:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = lease.Close() }()
	info := lease.Info()
	routes := lease.Routes()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		select {
		case <-lease.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	sess, err := s.backend.Open(ctx, info)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = sess.Close() }()

	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	tw := &tunnelWriter{w: w, rc: http.NewResponseController(w)}
	var setup []byte
	setup = appendAddressAssign(setup, []assignment{{prefix: info.Prefix}})
	setup = appendRouteAdvertisement(setup, routes)
	if err := tw.write(setup); err != nil {
		return
	}
	if s.observe != nil {
		s.observe(r.Proto)
	}
	log := s.log.With("transport", r.Proto, "session", info.ID, "prefix", info.Prefix)
	log.Info("CONNECT-IP request accepted")

	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Go(func() { errc <- s.fromClient(ctx, r.Body, tw, sess, info.Prefix, routes) })
	wg.Go(func() { errc <- s.toClient(ctx, tw, sess, info.Prefix) })
	select {
	case err = <-errc:
	case <-ctx.Done():
		err = ctx.Err()
	}
	cancel()
	_ = sess.Close()
	_ = r.Body.Close()
	tw.close()
	wg.Wait()
	log.Info("CONNECT-IP request ended", "reason", err)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		// Reset the stream rather than ending it cleanly, so the client
		// sees the malformed request fail.
		panic(http.ErrAbortHandler)
	}
}

// fromClient reads capsules until the stream ends or a capsule is malformed.
func (s *h2Server) fromClient(
	ctx context.Context, body io.Reader, tw *tunnelWriter, sess connectip.BackendSession,
	prefix netip.Prefix, routes []netip.Prefix,
) error {
	cr := newCapsuleReader(body)
	for ctx.Err() == nil {
		c, err := cr.next()
		if err != nil {
			return err
		}
		switch c.typ {
		case capsuleDatagram:
			id, n, err := quicvarint.Parse(c.value)
			if err != nil {
				return errors.New("DATAGRAM capsule without a context ID")
			}
			// Context 0 is the only registered context.
			if id != 0 {
				continue
			}
			pkt := c.value[n:]
			if !allowedFromClient(pkt, prefix, routes) {
				continue
			}
			if err := sess.WritePacket(pkt); err != nil {
				return err
			}
		case capsuleAddressRequest:
			reqs, err := parseAddressEntries(c.value)
			if err != nil {
				return err
			}
			if err := tw.write(appendAddressAssign(nil, answerAddressRequest(reqs, prefix))); err != nil {
				return err
			}
		default:
			// The client's own ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT do
			// not change what it may send; unknown capsules are skipped.
		}
	}
	return ctx.Err()
}

func (s *h2Server) toClient(
	ctx context.Context, tw *tunnelWriter, sess connectip.BackendSession, prefix netip.Prefix,
) error {
	buf := make([]byte, maxPacketSize)
	var out []byte
	for {
		n, err := sess.ReadPacket(ctx, buf)
		if err != nil {
			return err
		}
		pkt := buf[:n]
		if !isIPv6(pkt) || !prefix.Contains(netip.AddrFrom16([16]byte(pkt[24:40]))) || pkt[7] <= 1 {
			continue
		}
		pkt[7]--
		out = appendDatagram(out[:0], pkt)
		if err := tw.write(out); err != nil {
			return err
		}
	}
}

// answerAddressRequest gives the first IPv6 request the session's prefix and
// rejects every other request, as connectip.Server does.
func answerAddressRequest(reqs []assignment, prefix netip.Prefix) []assignment {
	out := make([]assignment, 0, len(reqs)+1)
	given := false
	for _, req := range reqs {
		switch {
		case !given && req.prefix.Addr().Is6():
			out = append(out, assignment{requestID: req.requestID, prefix: prefix})
			given = true
		case req.prefix.Addr().Is4():
			out = append(out, assignment{requestID: req.requestID, prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 32)})
		default:
			out = append(out, assignment{requestID: req.requestID, prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 128)})
		}
	}
	if !given {
		out = append(out, assignment{prefix: prefix})
	}
	return out
}

func isIPv6(pkt []byte) bool {
	return len(pkt) >= 40 && pkt[0]>>4 == 6 && int(pkt[4])<<8|int(pkt[5]) == len(pkt)-40
}

func allowedFromClient(pkt []byte, prefix netip.Prefix, routes []netip.Prefix) bool {
	if !isIPv6(pkt) {
		return false
	}
	src := netip.AddrFrom16([16]byte(pkt[8:24]))
	dst := netip.AddrFrom16([16]byte(pkt[24:40]))
	return prefix.Contains(src) && slices.ContainsFunc(routes, func(r netip.Prefix) bool { return r.Contains(dst) })
}

func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	token = strings.TrimSpace(token)
	return token, found && strings.EqualFold(scheme, "Bearer") && token != ""
}

// tunnelWriter serializes capsule writes on one response stream and bounds
// each by h2WriteTimeout.
type tunnelWriter struct {
	mu     sync.Mutex
	w      io.Writer
	rc     *http.ResponseController
	closed bool
}

func (t *tunnelWriter) write(b []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errTunnelClosed
	}
	_ = t.rc.SetWriteDeadline(time.Now().Add(h2WriteTimeout))
	if _, err := t.w.Write(b); err != nil {
		return err
	}
	return t.rc.Flush()
}

// close stops further writes; the handler's return ends the stream.
func (t *tunnelWriter) close() {
	_ = t.rc.SetWriteDeadline(time.Now())
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}

var errTunnelClosed = errors.New("tunnel closed")
