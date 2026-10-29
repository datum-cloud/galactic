// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/sys/unix"
)

// reflectBackend is the load harness's gVPC. It returns every client packet
// to the session that sent it, with source and destination swapped, through
// a queue with the TUN backend's limits.
type reflectBackend struct {
	mu       sync.Mutex
	sessions map[sessionKey]*reflectSession
	open     atomic.Int64
	drops    atomic.Int64
	// peak is the most packets one session's queue has held.
	peak atomic.Int64
}

func newReflectBackend() *reflectBackend {
	return &reflectBackend{sessions: map[sessionKey]*reflectSession{}}
}

func (b *reflectBackend) Open(_ context.Context, info SessionInfo) (BackendSession, error) {
	s := &reflectSession{b: b, key: sessionKey{info.VPC, info.ID}, q: make(chan []byte, tunQueueLen),
		closed: make(chan struct{})}
	b.mu.Lock()
	b.sessions[s.key] = s
	b.mu.Unlock()
	b.open.Add(1)
	return s, nil
}

// session returns the open session of prefix in vpc.
func (b *reflectBackend) session(vpc string, prefix netip.Prefix) *reflectSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, s := range b.sessions {
		if k.vpc == vpc && s.prefix.Load() != nil && *s.prefix.Load() == prefix {
			return s
		}
	}
	return nil
}

type reflectSession struct {
	b      *reflectBackend
	key    sessionKey
	prefix atomic.Pointer[netip.Prefix]
	q      chan []byte
	queued atomic.Int64
	once   sync.Once
	closed chan struct{}
}

func (s *reflectSession) WritePacket(pkt []byte) error {
	if len(pkt) < ipv6HeaderLen {
		return nil
	}
	if s.prefix.Load() == nil {
		p := netip.PrefixFrom(netip.AddrFrom16([16]byte(pkt[8:24])), 96).Masked()
		s.prefix.Store(&p)
	}
	out := bytes.Clone(pkt)
	copy(out[8:24], pkt[24:40])
	copy(out[24:40], pkt[8:24])
	out[7] = 64
	n := int64(len(out))
	if s.queued.Add(n) > tunQueueBytes {
		s.queued.Add(-n)
		s.b.drops.Add(1)
		return nil
	}
	select {
	case s.q <- out:
		for depth := int64(len(s.q)); ; {
			old := s.b.peak.Load()
			if depth <= old || s.b.peak.CompareAndSwap(old, depth) {
				break
			}
		}
	default:
		s.queued.Add(-n)
		s.b.drops.Add(1)
	}
	return nil
}

func (s *reflectSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case pkt := <-s.q:
		s.queued.Add(-int64(len(pkt)))
		return copy(buf, pkt), nil
	case <-s.closed:
		return 0, errors.New("session closed")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (s *reflectSession) Close() error {
	s.once.Do(func() {
		close(s.closed)
		s.b.mu.Lock()
		delete(s.b.sessions, s.key)
		s.b.mu.Unlock()
		s.b.open.Add(-1)
	})
	return nil
}

func (s *reflectSession) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// loadConn is one client's accepted CONNECT-IP request.
type loadConn interface {
	writePacket(b []byte) error
	readPacket(b []byte) (int, error)
	close()
}

type h3LoadConn struct {
	conn  *connectip.Conn
	qconn *quic.Conn
	tr    *quic.Transport
	udp   net.PacketConn
	imp   *impairedConn
}

func (c *h3LoadConn) writePacket(b []byte) error {
	_, err := c.conn.WritePacket(b)
	return err
}

func (c *h3LoadConn) readPacket(b []byte) (int, error) { return c.conn.ReadPacket(b) }

func (c *h3LoadConn) close() {
	if c.imp != nil {
		c.imp.closing.Store(true)
		c.imp.stalled.Store(false)
		c.imp.pending.Wait()
	}
	_ = c.conn.Close()
	_ = c.qconn.CloseWithError(0, "")
	_ = c.tr.Close()
	_ = c.udp.Close()
}

type h2LoadConn struct {
	s   *h2Stream
	out []byte
}

func (c *h2LoadConn) writePacket(b []byte) error {
	c.out = appendDatagram(c.out[:0], b)
	return c.s.send(c.out, 16384)
}

func (c *h2LoadConn) readPacket(b []byte) (int, error) {
	for {
		cp, err := c.s.cr.next()
		if err != nil {
			return 0, err
		}
		if cp.typ != capsuleDatagram || cp.skipped {
			continue
		}
		id, n, err := quicvarint.Parse(cp.value)
		if err != nil || id != 0 {
			continue
		}
		return copy(b, cp.value[n:]), nil
	}
}

func (c *h2LoadConn) close() {
	c.s.cancel()
	_ = c.s.c.conn.Close()
}

// impairment drops a fraction of a client's UDP datagrams in each direction
// and delays the ones it sends.
type impairment struct {
	loss  float64
	delay time.Duration
}

// impairedConn applies an impairment to a client UDP socket. While stalled
// it discards everything it receives, as a client that stopped reading.
type impairedConn struct {
	net.PacketConn
	imp     impairment
	stalled atomic.Bool
	// closing stops the impairment, so the CONNECTION_CLOSE leaves at once.
	closing atomic.Bool
	pending sync.WaitGroup
}

func (c *impairedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if c.stalled.Load() || (c.imp.loss > 0 && rand.Float64() < c.imp.loss) {
			continue
		}
		return n, addr, nil
	}
}

func (c *impairedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.closing.Load() {
		return c.PacketConn.WriteTo(b, addr)
	}
	if c.imp.loss > 0 && rand.Float64() < c.imp.loss {
		return len(b), nil
	}
	if c.imp.delay > 0 {
		pkt := bytes.Clone(b)
		c.pending.Add(1)
		time.AfterFunc(c.imp.delay, func() {
			defer c.pending.Done()
			_, _ = c.PacketConn.WriteTo(pkt, addr)
		})
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

// nextSource hands out loopback source addresses, so every client counts as
// its own source against MaxConnectionsPerSource.
var nextSource atomic.Uint32

func loadSource() netip.Addr {
	n := nextSource.Add(1)
	return netip.AddrFrom4([4]byte{127, 1 + byte(n>>16), byte(n >> 8), byte(n)})
}

// statusError is a request the server answered with a status other than 200.
type statusError int

func (e statusError) Error() string { return "status " + strconv.Itoa(int(e)) }

// dialLoad opens one connection from src over transport and one request on
// it with token and vpc. It returns the request and its delegated /96.
func (e *testEnv) dialLoad(
	ctx context.Context, transport, src, token, vpc string, imp *impairedConn,
) (loadConn, netip.Prefix, error) {
	if transport == "h2" {
		return e.dialLoadH2(ctx, src, token, vpc)
	}
	return e.dialLoadH3(ctx, src, token, vpc, imp)
}

func (e *testEnv) dialLoadH3(
	ctx context.Context, src, token, vpc string, imp *impairedConn,
) (loadConn, netip.Prefix, error) {
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(src), 0)))
	if err != nil {
		return nil, netip.Prefix{}, err
	}
	tr := &quic.Transport{Conn: udp}
	if imp != nil {
		imp.PacketConn = udp
		tr = &quic.Transport{Conn: imp}
	}
	var qconn *quic.Conn
	fail := func(err error) (loadConn, netip.Prefix, error) {
		if qconn != nil {
			_ = qconn.CloseWithError(0, "")
		}
		_ = tr.Close()
		_ = udp.Close()
		return nil, netip.Prefix{}, err
	}
	raddr, err := net.ResolveUDPAddr("udp4", e.addr)
	if err != nil {
		return fail(err)
	}
	qconn, err = tr.Dial(ctx, raddr, e.clientTLS(),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
	if err != nil {
		return fail(fmt.Errorf("dial: %w", err))
	}
	cc, err := (&connectip.Transport{}).NewClientConn(qconn)
	if err != nil {
		return fail(fmt.Errorf("client conn: %w", err))
	}
	req, err := connectip.NewRequest(ctx, e.template)
	if err != nil {
		return fail(err)
	}
	for k, vs := range authHeaders(token, vpc) {
		for _, v := range vs {
			req.Header().Add(k, v)
		}
	}
	conn, rsp, err := cc.Dial(req)
	if err != nil {
		return fail(fmt.Errorf("request: %w", err))
	}
	if rsp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return fail(statusError(rsp.StatusCode))
	}
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil || len(assigned) != 1 {
		_ = conn.Close()
		return fail(fmt.Errorf("address assignment: %v %w", assigned, err))
	}
	return &h3LoadConn{conn: conn, qconn: qconn, tr: tr, udp: udp, imp: imp}, assigned[0].IPPrefix, nil
}

func (e *testEnv) dialLoadH2(ctx context.Context, src, token, vpc string) (loadConn, netip.Prefix, error) {
	c, err := e.dialH2From(ctx, net.ParseIP(src))
	if err != nil {
		return nil, netip.Prefix{}, err
	}
	s, status, err := c.tryRequest(ctx, e.addr, authHeaders(token, vpc))
	if err != nil {
		_ = c.conn.Close()
		return nil, netip.Prefix{}, err
	}
	if status != http.StatusOK {
		_ = c.conn.Close()
		return nil, netip.Prefix{}, statusError(status)
	}
	assign, err := s.tryNextCapsule(testTimeout)
	if err != nil || assign.typ != capsuleAddressAssign {
		_ = c.conn.Close()
		return nil, netip.Prefix{}, fmt.Errorf("no ADDRESS_ASSIGN: %w", err)
	}
	got, err := parseAssignmentsErr(assign.value)
	if err != nil || len(got) != 1 {
		_ = c.conn.Close()
		return nil, netip.Prefix{}, fmt.Errorf("address assignment: %v %w", got, err)
	}
	if _, err := s.tryNextCapsule(testTimeout); err != nil {
		_ = c.conn.Close()
		return nil, netip.Prefix{}, fmt.Errorf("no ROUTE_ADVERTISEMENT: %w", err)
	}
	return &h2LoadConn{s: s}, got[0].prefix, nil
}

// outcome names why a dialLoad failed, for the overload report.
func outcome(err error) string {
	var appErr *quic.ApplicationError
	var trErr *quic.TransportError
	var idle *quic.IdleTimeoutError
	var hs *quic.HandshakeTimeoutError
	switch {
	case err == nil:
		return "accepted"
	case errors.As(err, new(statusError)):
		s, _ := errors.AsType[statusError](err)
		return "status_" + strconv.Itoa(int(s))
	case strings.Contains(err.Error(), "server responded with "):
		// connect-ip-go reports a non-2xx response as an error.
		_, code, _ := strings.Cut(err.Error(), "server responded with ")
		return "status_" + code
	case errors.As(err, &appErr):
		if appErr.ErrorCode == errExcessiveLoad {
			return "closed_excessive_load"
		}
		return "closed_application_error"
	case errors.As(err, &trErr):
		return "closed_transport_error"
	case errors.As(err, &idle), errors.As(err, &hs), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case strings.Contains(err.Error(), "dial TLS"):
		return "tcp_refused"
	default:
		return "closed_other"
	}
}

// Load packets are IPv6/UDP. The payload starts with a sequence number,
// whose top 24 bits name the connector, and the send time.
const (
	loadHeaderLen  = ipv6HeaderLen + 8
	minLoadPacket  = loadHeaderLen + 16
	loadWindow     = 32
	loadStallReset = 200 * time.Millisecond
)

func putLoadPacket(pkt []byte, src, dst netip.Addr, seq uint64, sent time.Duration) {
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt)-ipv6HeaderLen))
	pkt[6] = 17
	pkt[7] = 64
	s16, d16 := src.As16(), dst.As16()
	copy(pkt[8:24], s16[:])
	copy(pkt[24:40], d16[:])
	binary.BigEndian.PutUint16(pkt[40:], 40000)
	binary.BigEndian.PutUint16(pkt[42:], 40000)
	binary.BigEndian.PutUint16(pkt[44:], uint16(len(pkt)-ipv6HeaderLen))
	binary.BigEndian.PutUint64(pkt[loadHeaderLen:], seq)
	binary.BigEndian.PutUint64(pkt[loadHeaderLen+8:], uint64(sent))
}

// loadCounters are one run's totals across its connectors.
type loadCounters struct {
	sent, recv, recvBytes, misdelivered atomic.Uint64
}

type counterSnapshot struct{ sent, recv, recvBytes uint64 }

func (c *loadCounters) snapshot() counterSnapshot {
	return counterSnapshot{c.sent.Load(), c.recv.Load(), c.recvBytes.Load()}
}

// rttHist is a log-linear histogram of round-trip times in microseconds,
// with 8 buckets per power of two.
type rttHist struct{ b [512]atomic.Uint64 }

func rttBucket(us uint64) int {
	if us < 16 {
		return int(us)
	}
	e := bits.Len64(us) - 4
	return min(16+(e-1)*8+int(us>>e)-8, 511)
}

func rttBucketValue(i int) float64 {
	if i < 16 {
		return float64(i)
	}
	e := (i-16)/8 + 1
	m := uint64((i-16)%8 + 8)
	return float64(m<<e+(m+1)<<e) / 2
}

func (h *rttHist) record(d time.Duration) { h.b[rttBucket(uint64(d.Microseconds()))].Add(1) }

// quantile returns the q quantile in milliseconds, or 0 with no samples.
func (h *rttHist) quantile(q float64) float64 {
	var total uint64
	for i := range h.b {
		total += h.b[i].Load()
	}
	if total == 0 {
		return 0
	}
	want := uint64(q * float64(total))
	var seen uint64
	for i := range h.b {
		seen += h.b[i].Load()
		if seen > want {
			return rttBucketValue(i) / 1000
		}
	}
	return rttBucketValue(len(h.b)-1) / 1000
}

// connector is one load client with its request and addresses.
type connector struct {
	idx    uint64
	vpc    string
	prefix netip.Prefix
	conn   loadConn
	imp    *impairedConn
	recv   atomic.Uint64
}

// run sends size-byte packets to testTarget with at most loadWindow
// unanswered, until ctx ends. A window unanswered for loadStallReset is
// written off as lost. Replies update counters and hist.
func (c *connector) run(ctx context.Context, epoch time.Time, size int, ctrs *loadCounters,
	hist *atomic.Pointer[rttHist]) {
	var inflight atomic.Int64
	answered := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, maxPacketSize)
		for {
			n, err := c.conn.readPacket(buf)
			if err != nil {
				return
			}
			if n < minLoadPacket {
				continue
			}
			seq := binary.BigEndian.Uint64(buf[loadHeaderLen:])
			if seq>>40 != c.idx {
				ctrs.misdelivered.Add(1)
				continue
			}
			sent := time.Duration(binary.BigEndian.Uint64(buf[loadHeaderLen+8:]))
			hist.Load().record(time.Since(epoch) - sent)
			ctrs.recv.Add(1)
			ctrs.recvBytes.Add(uint64(n))
			c.recv.Add(1)
			if inflight.Add(-1) < 0 {
				inflight.Store(0)
			}
			select {
			case answered <- struct{}{}:
			default:
			}
		}
	})
	src, pkt := c.prefix.Addr().Next(), make([]byte, size)
	for seq := c.idx << 40; ctx.Err() == nil; {
		if inflight.Load() >= loadWindow {
			select {
			case <-answered:
			case <-time.After(loadStallReset):
				inflight.Store(0)
			case <-ctx.Done():
			}
			continue
		}
		seq++
		putLoadPacket(pkt, src, testTarget, seq, time.Since(epoch))
		if err := c.conn.writePacket(pkt); err != nil {
			break
		}
		inflight.Add(1)
		ctrs.sent.Add(1)
	}
	// Leave the reader running until the connector closes, so replies in
	// flight are counted.
	go wg.Wait()
}

// usage is the process's CPU time and resident memory at one moment.
type usage struct {
	at  time.Time
	cpu time.Duration
}

func readUsage() usage {
	var ru unix.Rusage
	_ = unix.Getrusage(unix.RUSAGE_SELF, &ru)
	return usage{at: time.Now(), cpu: time.Duration(ru.Utime.Nano() + ru.Stime.Nano())}
}

// rssBytes returns the process's resident set size.
func rssBytes() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, _ := strconv.ParseInt(f[1], 10, 64)
	return pages * int64(os.Getpagesize())
}
