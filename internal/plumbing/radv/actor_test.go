// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package radv

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// recordingWriter is a raWriter that records when each advertisement was
// sent and where to.
type recordingWriter struct {
	mu    sync.Mutex
	sends []recordedSend
}

type recordedSend struct {
	at  time.Time
	dst netip.Addr
}

func (w *recordingWriter) WriteTo(m ndp.Message, _ *ipv6.ControlMessage, dst netip.Addr) error {
	if _, ok := m.(*ndp.RouterAdvertisement); !ok {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sends = append(w.sends, recordedSend{at: time.Now(), dst: dst})
	return nil
}

func (w *recordingWriter) snapshot() []recordedSend {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]recordedSend(nil), w.sends...)
}

// shrinkRadvTimers scales the protocol delays down so a test of the actor
// loop runs in milliseconds, keeping the regular interval far out of reach.
func shrinkRadvTimers(t *testing.T, minDelay time.Duration) {
	t.Helper()
	origMin, origMax := MinRtrAdvInterval, MaxRtrAdvInterval
	origDelay, origRADelay := MinDelayBetweenRAs, MaxRADelayTime
	MinRtrAdvInterval, MaxRtrAdvInterval = time.Hour, 2*time.Hour
	MinDelayBetweenRAs, MaxRADelayTime = minDelay, time.Millisecond
	t.Cleanup(func() {
		MinRtrAdvInterval, MaxRtrAdvInterval = origMin, origMax
		MinDelayBetweenRAs, MaxRADelayTime = origDelay, origRADelay
	})
}

// runLoopFor runs runActorLoop against w for d and returns once it has exited.
func runLoopFor(t *testing.T, w raWriter, rsCh <-chan netip.Addr, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	hwAddr := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	runActorLoop(ctx, w, "tap-test", 1500, hwAddr, rsCh)
}

// TestRunActorLoop_InitialBurst covers #828: an actor advertises the moment it
// starts, without waiting for a solicitation, then sends the rest of the
// RFC 4861 initial burst no closer together than MinDelayBetweenRAs, then
// falls back to the regular interval.
func TestRunActorLoop_InitialBurst(t *testing.T) {
	const minDelay = 100 * time.Millisecond
	shrinkRadvTimers(t, minDelay)

	w := &recordingWriter{}
	start := time.Now()
	runLoopFor(t, w, make(chan netip.Addr), MaxInitialRtrAdvertisements*minDelay+minDelay)

	sends := w.snapshot()
	if len(sends) != MaxInitialRtrAdvertisements {
		t.Fatalf("sent %d advertisements, want %d (the initial burst, then the regular interval)",
			len(sends), MaxInitialRtrAdvertisements)
	}
	if first := sends[0].at.Sub(start); first >= 2*minDelay {
		t.Errorf("first advertisement sent %v after start, want it immediately", first)
	}
	for i, s := range sends {
		if s.dst != allNodesMulticast {
			t.Errorf("advertisement %d sent to %v, want %v", i, s.dst, allNodesMulticast)
		}
		if i == 0 {
			continue
		}
		if gap := s.at.Sub(sends[i-1].at); gap < minDelay {
			t.Errorf("advertisement %d sent %v after the previous one, want at least %v", i, gap, minDelay)
		}
	}
}

// TestRunActorLoop_UnicastSolicitationDuringBurstRepliesPromptly checks that
// multicast spacing does not delay a unicast solicited reply.
func TestRunActorLoop_UnicastSolicitationDuringBurstRepliesPromptly(t *testing.T) {
	const minDelay = 200 * time.Millisecond
	shrinkRadvTimers(t, minDelay)

	w := &recordingWriter{}
	rsCh := make(chan netip.Addr, 1)
	rsCh <- netip.MustParseAddr("fe80::2")
	runLoopFor(t, w, rsCh, minDelay/2)

	sends := w.snapshot()
	if len(sends) < 1 || len(sends) > 2 {
		t.Fatalf(
			"sent %d advertisements within %v of start, want prompt unicast reply and optional initial multicast",
			len(sends), minDelay/2,
		)
	}
	want := netip.MustParseAddr("fe80::2")
	found := false
	for _, send := range sends {
		found = found || send.dst == want
	}
	if !found {
		t.Fatalf("advertisements sent to %v, want a solicited reply to %v", sends, want)
	}
}

// TestRunActorLoop_MulticastSolicitationDuringBurstIsDeferred checks a reply
// to an unspecified source is delayed rather than dropped when the initial
// multicast advertisement was just sent.
func TestRunActorLoop_MulticastSolicitationDuringBurstIsDeferred(t *testing.T) {
	const minDelay = 100 * time.Millisecond
	shrinkRadvTimers(t, minDelay)

	w := &recordingWriter{}
	rsCh := make(chan netip.Addr, 1)
	rsCh <- netip.IPv6Unspecified()
	runLoopFor(t, w, rsCh, minDelay+minDelay/2)

	sends := w.snapshot()
	if len(sends) != 2 {
		t.Fatalf("sent %d advertisements, want initial multicast and deferred reply", len(sends))
	}
	if gap := sends[1].at.Sub(sends[0].at); gap < minDelay {
		t.Fatalf("multicast reply sent after %v, want at least %v", gap, minDelay)
	}
}

func TestNextUnsolicitedDelay(t *testing.T) {
	for sent := 1; sent < MaxInitialRtrAdvertisements; sent++ {
		if got := nextUnsolicitedDelay(sent); got != MinDelayBetweenRAs {
			t.Errorf("nextUnsolicitedDelay(%d) = %v, want %v", sent, got, MinDelayBetweenRAs)
		}
	}
	for _, sent := range []int{MaxInitialRtrAdvertisements, MaxInitialRtrAdvertisements + 5} {
		got := nextUnsolicitedDelay(sent)
		if got < MinRtrAdvInterval || got >= MaxRtrAdvInterval {
			t.Errorf("nextUnsolicitedDelay(%d) = %v, want in [%v, %v)", sent, got, MinRtrAdvInterval, MaxRtrAdvInterval)
		}
	}
}

func TestHasLinkLocal(t *testing.T) {
	ipnet := func(s string) net.Addr {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = net.ParseIP(s[:len(s)-len("/64")])
		return n
	}

	tests := []struct {
		name  string
		addrs []net.Addr
		want  bool
	}{
		{"None", nil, false},
		{"GlobalOnly", []net.Addr{ipnet("2001:db8::1/64")}, false},
		{"IPv4LinkLocalOnly", []net.Addr{&net.IPNet{IP: net.IPv4(169, 254, 0, 1).To4(), Mask: net.CIDRMask(16, 32)}}, false},
		{"LinkLocal", []net.Addr{ipnet("2001:db8::1/64"), ipnet("fe80::1/64")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasLinkLocal(tt.addrs); got != tt.want {
				t.Errorf("hasLinkLocal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMulticastDelay(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		lastSent time.Time
		now      time.Time
		dst      netip.Addr
		want     time.Duration
	}{
		{"NeverSent", time.Time{}, base, allNodesMulticast, 0},
		{"Unicast", base, base.Add(time.Second), netip.MustParseAddr("fe80::2"), 0},
		{"MulticastJustSent", base, base.Add(time.Second), allNodesMulticast, MinDelayBetweenRAs - time.Second},
		{"ExactlyAtBoundary", base, base.Add(MinDelayBetweenRAs), allNodesMulticast, 0},
		{"WellPastBoundary", base, base.Add(MinDelayBetweenRAs + time.Second), allNodesMulticast, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := multicastDelay(tt.lastSent, tt.now, tt.dst); got != tt.want {
				t.Errorf("multicastDelay(%v, %v, %v) = %v, want %v", tt.lastSent, tt.now, tt.dst, got, tt.want)
			}
		})
	}
}

func TestResponseDestination(t *testing.T) {
	guestAddr := netip.MustParseAddr("fe80::1")

	tests := []struct {
		name string
		src  netip.Addr
		want netip.Addr
	}{
		{"UnspecifiedSourceFallsBackToMulticast", netip.IPv6Unspecified(), allNodesMulticast},
		{"UnicastSourceIsUsedDirectly", guestAddr, guestAddr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responseDestination(tt.src); got != tt.want {
				t.Errorf("responseDestination(%v) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// TestAddrNotReady checks EADDRNOTAVAIL and ENODEV are recognised through the
// wrapping the net package puts around a failed bind.
func TestAddrNotReady(t *testing.T) {
	tests := []struct {
		errno        syscall.Errno
		wantNotReady bool
	}{
		{syscall.EADDRNOTAVAIL, true},
		// A tap recreated under the same name after it was looked up (#1293).
		{syscall.ENODEV, true},
		{syscall.EACCES, false},
	}
	for _, tt := range tests {
		bind := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", tt.errno)}
		got := addrNotReady(bind)
		if errors.Is(got, ErrAddrNotReady) != tt.wantNotReady || !errors.Is(got, tt.errno) {
			t.Errorf("addrNotReady(%v) = %v, want wrapping ErrAddrNotReady %v and still %v",
				bind, got, tt.wantNotReady, tt.errno)
		}
	}
}
