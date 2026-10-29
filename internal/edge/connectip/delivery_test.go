// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

// stallConn is a client UDP socket that discards everything it receives
// once stalled, as a client that stopped reading would.
type stallConn struct {
	net.PacketConn
	stalled atomic.Bool
}

func (c *stallConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.stalled.Load() {
			return n, addr, err
		}
	}
}

func shortenDeliveryTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := deliveryTimeout
	deliveryTimeout = d
	t.Cleanup(func() { deliveryTimeout = old })
}

func slowClientEnds() float64 {
	return testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonSlowClient))
}

// TestH3StalledClientEndsOnlyItsSession stops one HTTP/3 client reading
// while packets keep arriving for it. Its datagram send queue fills, and
// the session ends after deliveryTimeout rather than the 30 s QUIC idle
// timeout. A session on another connection keeps forwarding.
func TestH3StalledClientEndsOnlyItsSession(t *testing.T) {
	shortenDeliveryTimeout(t, 300*time.Millisecond)
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = adm })

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sc := &stallConn{PacketConn: udp}
	tr := &quic.Transport{Conn: sc}
	t.Cleanup(func() { _ = tr.Close() })
	raddr, err := net.ResolveUDPAddr("udp4", env.addr)
	if err != nil {
		t.Fatal(err)
	}
	qconn, err := tr.Dial(t.Context(), raddr, env.clientTLS(),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
	if err != nil {
		t.Fatalf("dial QUIC: %v", err)
	}
	slow := open(t, newClientConn(t, qconn), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	slowSess := env.backend.nextOpened(t)
	fast := open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
	fastSess := env.backend.nextOpened(t)

	before, endsBefore := slowClientEnds(), ends(transportH3, causeSlowClient)
	sc.stalled.Store(true)
	start := time.Now()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case slowSess.toClient <- echoRequest(t, testTarget, slow.address, i%60000, 1200):
			case <-stop:
				return
			case <-slowSess.closed:
				return
			}
		}
	})
	defer func() { close(stop); wg.Wait() }()
	slowSess.waitClosed(t)
	if took := time.Since(start); took > 10*deliveryTimeout {
		t.Fatalf("stalled session ended after %v, want about %v", took, deliveryTimeout)
	}
	adm.waitReleased(t, slowSess.info)
	if got := slowClientEnds() - before; got != 1 {
		t.Fatalf("slow_client count rose by %v, want 1", got)
	}
	eventually(t, "a slow_client tunnel end", func() bool {
		return ends(transportH3, causeSlowClient)-endsBefore == 1
	})

	if _, err := fast.conn.WritePacket(echoRequest(t, fast.address, testTarget, 70, 200)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if id := echoID(t, parseICMPv6(t, readPacket(t, fast.conn))); id != 70 {
		t.Fatalf("reply id %d, want 70", id)
	}
	if fastSess.isClosed() {
		t.Fatal("the other connection's session closed")
	}
}

// TestTUNQueueFullDropIsCounted fills one session's queue toward the client
// from the device and counts each packet past the cap as queue_full. A
// SOCK_SEQPACKET socket stands in for the TUN descriptor.
func TestTUNQueueFullDropIsCounted(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	peer := os.NewFile(uintptr(fds[1]), "peer")
	t.Cleanup(func() { _ = peer.Close() })
	b, err := NewTUNBackend(os.NewFile(uintptr(fds[0]), "dev"), vpcBlue)
	if err != nil {
		t.Fatalf("NewTUNBackend: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	info := SessionInfo{ID: 1, VPC: vpcBlue, Prefix: firstPrefix}
	if _, err := b.Open(t.Context(), info); err != nil {
		t.Fatalf("Open: %v", err)
	}
	queueFull := func() float64 {
		return testutil.ToFloat64(packetsDenied.WithLabelValues(toClient, reasonQueueFull))
	}
	before := queueFull()
	const extra = 5
	pkt := echoRequest(t, testTarget, firstClient, 1, 200)
	for range tunQueueLen + extra {
		if _, err := unix.Write(fds[1], pkt); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	pollUntil(t, "queue_full drops", func() bool { return queueFull()-before == extra })
}

// slowTunnel is a tunnel whose writes toward the client take per, as a QUIC
// connection to a stalled client drains its datagram queue once per probe
// timeout. After each slow write, the next prompt writes return at once, as
// the second datagram a probe timeout frees does.
type slowTunnel struct {
	*narrowTunnel
	per    time.Duration
	prompt int64
	writes atomic.Int64
}

func (t *slowTunnel) WritePacket([]byte) ([]byte, error) {
	if (t.writes.Add(1)-1)%(t.prompt+1) != 0 {
		return nil, nil
	}
	select {
	case <-time.After(t.per):
		return nil, nil
	case <-t.closed:
		return nil, net.ErrClosed
	}
}

// TestBackToBackSlowWritesEndSession keeps one tunnel's writes slow without
// any single write reaching deliveryTimeout, with a prompt write after each
// slow one. The session still ends, once slow writes have run back to back
// for deliveryTimeout.
func TestBackToBackSlowWritesEndSession(t *testing.T) {
	shortenDeliveryTimeout(t, 400*time.Millisecond)
	before := slowClientEnds()
	tun := &slowTunnel{narrowTunnel: newNarrowTunnel(maxPacketSize), per: 150 * time.Millisecond, prompt: 1}
	sess, done := runProxySession(t, tun)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for i := 0; ; i++ {
			select {
			case sess.toClient <- echoRequest(t, policyTarget, firstClient, i, 200):
			case <-stop:
				return
			case <-sess.closed:
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("session with back-to-back slow writes stayed open")
	}
	if got := slowClientEnds() - before; got != 1 {
		t.Fatalf("slow_client count rose by %v, want 1", got)
	}
}

// TestPromptStreakResetsRun answers promptStreak writes at once after each
// slow one, as a congested but healthy client drains its queue between
// stalls. Each streak ends the run of slow writes, so the session stays open.
func TestPromptStreakResetsRun(t *testing.T) {
	shortenDeliveryTimeout(t, 400*time.Millisecond)
	tun := &slowTunnel{narrowTunnel: newNarrowTunnel(maxPacketSize), per: 150 * time.Millisecond,
		prompt: promptStreak}
	sess, done := runProxySession(t, tun)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for i := 0; ; i++ {
			select {
			case sess.toClient <- echoRequest(t, policyTarget, firstClient, i, 200):
			case <-stop:
				return
			case <-sess.closed:
				return
			}
		}
	}()
	select {
	case <-done:
		t.Fatal("session ended although every slow write was followed by a prompt streak")
	case <-time.After(2 * time.Second):
	}
}

// TestSpacedSlowWritesKeepSession sends packets far enough apart that the
// writer waits for each one. Slow writes with idle time between them are a
// slow link, not a stalled client, so the session stays open.
func TestSpacedSlowWritesKeepSession(t *testing.T) {
	shortenDeliveryTimeout(t, 400*time.Millisecond)
	tun := &slowTunnel{narrowTunnel: newNarrowTunnel(maxPacketSize), per: 150 * time.Millisecond}
	sess, done := runProxySession(t, tun)
	for i := range 8 {
		sess.inject(echoRequest(t, policyTarget, firstClient, i, 200))
		time.Sleep(300 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("session with spaced slow writes ended")
	default:
	}
}

// scriptTunnel is a tunnel whose writes toward the client take the waits in
// turn, starting over after the last one. It records when the first write
// that waits began.
type scriptTunnel struct {
	*narrowTunnel
	waits  []time.Duration
	writes atomic.Int64
	once   sync.Once
	first  time.Time
}

func (t *scriptTunnel) WritePacket([]byte) ([]byte, error) {
	wait := t.waits[(t.writes.Add(1)-1)%int64(len(t.waits))]
	if wait == 0 {
		return nil, nil
	}
	t.once.Do(func() { t.first = time.Now() })
	select {
	case <-time.After(wait):
		return nil, nil
	case <-t.closed:
		return nil, net.ErrClosed
	}
}

// feed offers the session packets toward the client until stop closes or
// the session ends.
func feed(t *testing.T, sess *memorySession, stop <-chan struct{}) {
	t.Helper()
	go func() {
		for i := 0; ; i++ {
			select {
			case sess.toClient <- echoRequest(t, policyTarget, firstClient, i, 200):
			case <-stop:
				return
			case <-sess.closed:
				return
			}
		}
	}()
}

// checkInterval is how often watchDelivery checks, so a stall of
// deliveryTimeout ends within deliveryTimeout plus checkInterval.
func checkInterval() time.Duration { return deliveryTimeout / 4 }

// endSlack covers scheduling between the watchdog's check and the backend
// session closing.
const endSlack = 50 * time.Millisecond

// TestDoublingWritesEndWithinCheckInterval drains one write per wait, with
// a prompt write after each and each wait twice the last, as a QUIC
// connection to a stalled client sends datagrams on probe timeouts that
// start well below the slow threshold. The stall is timed from its first
// waiting write, so the session ends within one check interval of
// deliveryTimeout after it, and not before deliveryTimeout.
func TestDoublingWritesEndWithinCheckInterval(t *testing.T) {
	shortenDeliveryTimeout(t, 800*time.Millisecond)
	var waits []time.Duration
	for d := deliveryTimeout / 100; d < 4*deliveryTimeout; d *= 2 {
		waits = append(waits, d, 0)
	}
	tun := &scriptTunnel{narrowTunnel: newNarrowTunnel(maxPacketSize), waits: waits}
	sess, done := runProxySession(t, tun)
	stop := make(chan struct{})
	defer close(stop)
	feed(t, sess, stop)
	select {
	case cause := <-done:
		if cause != causeSlowClient {
			t.Fatalf("cause = %q, want %q", cause, causeSlowClient)
		}
	case <-time.After(testTimeout):
		t.Fatal("session with doubling waits stayed open")
	}
	took := time.Since(tun.first)
	if took < deliveryTimeout || took > deliveryTimeout+checkInterval()+endSlack {
		t.Fatalf("stalled session ended %v after its first waiting write, want %v to %v",
			took, deliveryTimeout, deliveryTimeout+checkInterval())
	}
}

// TestSteadyWaitsBeforeSlowWriteKeepSession keeps a client's writes waiting
// an eighth of deliveryTimeout each, as a congested client that keeps
// accepting packets, with an occasional slow write followed by a prompt
// streak. Delivery keeps making progress, so the session stays open.
func TestSteadyWaitsBeforeSlowWriteKeepSession(t *testing.T) {
	shortenDeliveryTimeout(t, 400*time.Millisecond)
	// One write short of two streaks of waiting writes, so the slow write
	// lands at the end of a run.
	waits := make([]time.Duration, 0, 3*promptStreak)
	for range 2*promptStreak - 1 {
		waits = append(waits, deliveryTimeout/8)
	}
	waits = append(waits, deliveryTimeout/3)
	for range promptStreak {
		waits = append(waits, 0)
	}
	tun := &scriptTunnel{narrowTunnel: newNarrowTunnel(maxPacketSize), waits: waits}
	sess, done := runProxySession(t, tun)
	stop := make(chan struct{})
	defer close(stop)
	feed(t, sess, stop)
	select {
	case <-done:
		t.Fatal("session with steady waits and an occasional slow write ended")
	case <-time.After(6 * deliveryTimeout):
	}
}

// dialStallable opens a QUIC connection to env whose client stops reading
// once its stallConn is stalled.
func dialStallable(t *testing.T, env *testEnv) (*stallConn, *quic.Conn) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sc := &stallConn{PacketConn: udp}
	tr := &quic.Transport{Conn: sc}
	t.Cleanup(func() { _ = tr.Close() })
	raddr, err := net.ResolveUDPAddr("udp4", env.addr)
	if err != nil {
		t.Fatal(err)
	}
	qconn, err := tr.Dial(t.Context(), raddr, env.clientTLS(),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
	if err != nil {
		t.Fatalf("dial QUIC: %v", err)
	}
	return sc, qconn
}

// TestStalledClientEndsWithinCheckInterval stops one client reading over
// each transport while the gVPC side keeps sending to it. Its session ends
// within one check interval of deliveryTimeout after the client stopped.
func TestStalledClientEndsWithinCheckInterval(t *testing.T) {
	run := func(t *testing.T, sess *memorySession, client netip.Addr, stall func()) {
		stall()
		start := time.Now()
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case sess.toClient <- echoRequest(t, testTarget, client, i%60000, MinInnerMTU):
				case <-stop:
					return
				case <-sess.closed:
					return
				}
			}
		})
		defer func() { close(stop); wg.Wait() }()
		sess.waitClosed(t)
		if took := time.Since(start); took > deliveryTimeout+checkInterval()+endSlack {
			t.Fatalf("stalled session ended after %v, want at most %v",
				took, deliveryTimeout+checkInterval())
		}
	}
	t.Run("HTTP/3", func(t *testing.T) {
		shortenDeliveryTimeout(t, time.Second)
		env := startServer(t, nil)
		sc, qconn := dialStallable(t, env)
		s := open(t, newClientConn(t, qconn), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
		sess := env.backend.nextOpened(t)
		run(t, sess, s.address, func() { sc.stalled.Store(true) })
	})
	t.Run("HTTP/2", func(t *testing.T) {
		shortenDeliveryTimeout(t, time.Second)
		env := startServer(t, nil)
		s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
		sess := env.backend.nextOpened(t)
		run(t, sess, sess.info.Prefix.Addr().Next(), s.pause)
	})
}

// TestSlowWriteAfterQuickWritesKeepSession waits briefly once, answers the
// next writes at once with packets spaced just under the idle gap, then
// blocks one write for three quarters of deliveryTimeout. The writes that
// did not wait end the run, so the slow write is timed on its own and the
// session stays open.
func TestSlowWriteAfterQuickWritesKeepSession(t *testing.T) {
	shortenDeliveryTimeout(t, 400*time.Millisecond)
	waits := make([]time.Duration, quickStreak+2)
	waits[0], waits[len(waits)-1] = deliveryTimeout/100, deliveryTimeout*3/4
	tun := &scriptTunnel{narrowTunnel: newNarrowTunnel(maxPacketSize), waits: waits}
	sess, done := runProxySession(t, tun)
	for i := range waits {
		select {
		case sess.toClient <- echoRequest(t, policyTarget, firstClient, i, 200):
		case <-done:
			t.Fatal("session with one slow write after quick ones ended")
		}
		time.Sleep(deliveryTimeout / 5)
	}
	select {
	case <-done:
		t.Fatal("session with one slow write after quick ones ended")
	case <-time.After(2 * deliveryTimeout):
	}
}
