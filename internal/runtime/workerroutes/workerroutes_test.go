// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package workerroutes

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
)

// fakeStream records requests and answers each with its sequence unless
// held.
type fakeStream struct {
	sent  chan *workerv1alpha1.RoutesSyncRequest
	resps chan *workerv1alpha1.RoutesSyncResponse
	fail  chan error

	mu   sync.Mutex
	hold bool
}

func newFakeStream() *fakeStream {
	return &fakeStream{
		sent:  make(chan *workerv1alpha1.RoutesSyncRequest, 64),
		resps: make(chan *workerv1alpha1.RoutesSyncResponse, 64),
		fail:  make(chan error, 1),
	}
}

func (s *fakeStream) Send(req *workerv1alpha1.RoutesSyncRequest) error {
	s.sent <- req
	s.mu.Lock()
	hold := s.hold
	s.mu.Unlock()
	if !hold {
		s.resps <- &workerv1alpha1.RoutesSyncResponse{Sequence: req.GetSequence()}
	}
	return nil
}

func (s *fakeStream) Recv() (*workerv1alpha1.RoutesSyncResponse, error) {
	select {
	case r := <-s.resps:
		return r, nil
	case err := <-s.fail:
		return nil, err
	}
}

func (s *fakeStream) CloseSend() error { return nil }

// collect reads requests until it has seen one upsert and withdrawals
// withdrawals, or fails after a deadline.
func collect(t *testing.T, s *fakeStream, withdrawals int) ([]string, []string) {
	const upserts = 1
	t.Helper()
	var ups, wds []string
	deadline := time.After(5 * time.Second)
	for len(ups) < upserts || len(wds) < withdrawals {
		select {
		case req := <-s.sent:
			for _, u := range req.GetUpserts() {
				ups = append(ups, u.GetVpc()+" "+u.GetPrefix()+" "+u.GetSid())
			}
			for _, w := range req.GetWithdrawals() {
				wds = append(wds, w.GetVpc()+" "+w.GetPrefix())
			}
		case <-deadline:
			t.Fatalf("got upserts %v and withdrawals %v, want %d and %d", ups, wds, upserts, withdrawals)
		}
	}
	sort.Strings(ups)
	sort.Strings(wds)
	return ups, wds
}

var (
	pA  = netip.MustParsePrefix("2001:db8:a::1/128")
	pB  = netip.MustParsePrefix("2001:db8:a::2/128")
	sid = net.ParseIP("2001:db8:0:2:e000:1::")
)

// acked counts the withdrawals Worker acknowledged and the ones it has not.
func (h *Handoff) acked() (acked, pending int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, w := range h.withdrawn {
		if w.acked.IsZero() {
			pending++
		} else {
			acked++
		}
	}
	return acked, pending
}

func TestHandoffSendsEverythingThenChanges(t *testing.T) {
	stream := newFakeStream()
	h := NewWithConnect(func(context.Context) (Stream, func(), error) { return stream, func() {}, nil })
	h.Upsert("vpcA", 100, pA, sid)
	h.Upsert("vpcA", 100, pB, sid)
	h.Withdraw("vpcA", pB)
	h.Withdraw("vpcB", pA)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	ups, wds := collect(t, stream, 2)
	if len(ups) != 1 || ups[0] != "vpcA 2001:db8:a::1/128 2001:db8:0:2:e000:1::" {
		t.Errorf("upserts = %v", ups)
	}
	if len(wds) != 2 {
		t.Errorf("withdrawals = %v", wds)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a, p := h.acked(); a == 2 && p == 0 {
			break
		}
		if time.Now().After(deadline) {
			a, p := h.acked()
			t.Fatalf("withdrawals acknowledged %d, pending %d; want 2 and 0", a, p)
		}
		time.Sleep(time.Millisecond)
	}

	h.Upsert("vpcC", 300, pA, sid)
	if ups, _ := collect(t, stream, 0); ups[0] != "vpcC 2001:db8:a::1/128 2001:db8:0:2:e000:1::" {
		t.Errorf("change = %v", ups)
	}
}

func TestHandoffResendsAfterReconnecting(t *testing.T) {
	first, second := newFakeStream(), newFakeStream()
	first.hold = true // nothing is acknowledged on the first stream
	streams := make(chan *fakeStream, 2)
	streams <- first
	streams <- second
	h := NewWithConnect(func(ctx context.Context) (Stream, func(), error) {
		select {
		case s := <-streams:
			return s, func() {}, nil
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	})
	h.Upsert("vpcA", 100, pA, sid)
	h.Withdraw("vpcA", pB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	collect(t, first, 1)
	first.fail <- errors.New("worker restarted")
	// The route and the withdrawal are both sent again.
	ups, wds := collect(t, second, 1)
	if len(ups) != 1 || len(wds) != 1 || wds[0] != "vpcA 2001:db8:a::2/128" {
		t.Fatalf("after reconnecting: upserts %v, withdrawals %v", ups, wds)
	}
}

func TestHandoffIgnoresRoutesWithoutAVPC(t *testing.T) {
	h := NewWithConnect(nil)
	h.Upsert("", 100, pA, sid)
	h.Withdraw("", pA)
	if h.next() != nil {
		t.Fatal("a route without a VPC was queued")
	}
}

func TestHandoffResendsAcknowledgedWithdrawalsUntilTheyExpire(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := NewWithConnect(nil)
	h.now = func() time.Time { return now }
	h.Upsert("vpcA", 100, pA, sid)
	h.Withdraw("vpcA", pA)
	req := h.next()
	h.ack(&workerv1alpha1.RoutesSyncResponse{Sequence: req.GetSequence()})
	if a, _ := h.acked(); a != 1 {
		t.Fatal("acknowledged withdrawal not kept")
	}

	// A new stream sends it again: Worker may have restarted before removing
	// the entry.
	h.mu.Lock()
	for k := range h.withdrawn {
		h.dirty[k] = struct{}{}
	}
	h.mu.Unlock()
	if req := h.next(); len(req.GetWithdrawals()) != 1 {
		t.Fatalf("resent request = %v, want the withdrawal", req)
	}

	now = now.Add(withdrawalRetention + time.Second)
	h.ack(&workerv1alpha1.RoutesSyncResponse{Sequence: 99})
	if a, p := h.acked(); a != 0 || p != 0 {
		t.Fatalf("expired withdrawal kept: acknowledged %d, pending %d", a, p)
	}
}

func TestHandoffForgetTableWithdrawsOnlyThatTable(t *testing.T) {
	h := NewWithConnect(nil)
	h.Upsert("vpcA", 100, pA, sid)
	h.Upsert("vpcA", 100, pB, sid)
	h.Upsert("vpcB", 100, pA, sid)
	h.Upsert("vpcA", 200, netip.MustParsePrefix("2001:db8:a::3/128"), sid)
	h.ForgetTable("vpcA", 100)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.routes) != 2 || len(h.withdrawn) != 2 {
		t.Fatalf("routes %v, withdrawn %v; want vpcA's table 100 routes withdrawn only", h.routes, h.withdrawn)
	}
}
