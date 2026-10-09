// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/radv"
)

// linkUpdate builds a netlink link update for interface index carrying link,
// with the given message type and lower-up flag.
func linkUpdate(msgType uint16, index int32, link netlink.Link, lowerUp bool) netlink.LinkUpdate {
	if link != nil {
		attrs := link.Attrs()
		attrs.Index = int(index)
		if lowerUp {
			attrs.RawFlags |= unix.IFF_LOWER_UP
		}
	}
	return netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Index: index}},
		Header:    unix.NlMsghdr{Type: msgType},
		Link:      link,
	}
}

func newTap() netlink.Link {
	return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "tap0"}, Mode: netlink.TUNTAP_MODE_TAP}
}

func newVeth() netlink.Link {
	return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0"}}
}

func TestTapGainedCarrier(t *testing.T) {
	type step struct {
		update netlink.LinkUpdate
		want   bool
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "TapGainingCarrierCounts",
			steps: []step{
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), false), false},
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), true},
			},
		},
		{
			name: "FirstSightingWithCarrierCounts",
			steps: []step{
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), true},
			},
		},
		{
			// Every attribute change repeats the link, carrier included.
			name: "RepeatedUpdateWhileUpDoesNotCount",
			steps: []step{
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), true},
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), false},
			},
		},
		{
			// A guest restarting closes and reopens its tap.
			name: "RegainingCarrierCountsAgain",
			steps: []step{
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), true},
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), false), false},
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), true},
			},
		},
		{
			name: "DeletedAndRecreatedTapCountsAgain",
			steps: []step{
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), true},
				{linkUpdate(unix.RTM_DELLINK, 7, newTap(), true), false},
				{linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true), true},
			},
		},
		{
			name: "VethIsIgnored",
			steps: []step{
				{linkUpdate(unix.RTM_NEWLINK, 8, newVeth(), true), false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			carrier := map[int32]bool{}
			for i, s := range tt.steps {
				if got := tapGainedCarrier(carrier, s.update); got != s.want {
					t.Errorf("step %d: tapGainedCarrier() = %v, want %v", i, got, s.want)
				}
			}
		})
	}
}

// TestWatchTapCarrier checks that a tap gaining carrier triggers a reconcile
// at once, without waiting for the reconcile ticker (#828), and that a failed
// subscription is retried.
func TestWatchTapCarrier(t *testing.T) {
	origSubscribe, origDelay := tapCarrierLinkSubscribe, tapCarrierResubscribeDelay
	t.Cleanup(func() { tapCarrierLinkSubscribe, tapCarrierResubscribeDelay = origSubscribe, origDelay })
	tapCarrierResubscribeDelay = time.Millisecond

	subscribed := make(chan chan<- netlink.LinkUpdate, 1)
	calls := 0
	tapCarrierLinkSubscribe = func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		calls++
		if calls == 1 {
			return errors.New("subscribe failed")
		}
		subscribed <- ch
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	trigger := make(chan struct{}, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		watchTapCarrier(ctx, trigger)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	var updates chan<- netlink.LinkUpdate
	select {
	case updates = <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("watchTapCarrier did not resubscribe after a failed subscription")
	}

	updates <- linkUpdate(unix.RTM_NEWLINK, 7, newTap(), false)
	updates <- linkUpdate(unix.RTM_NEWLINK, 8, newVeth(), true)
	select {
	case <-trigger:
		t.Fatal("triggered without any tap gaining carrier")
	case <-time.After(50 * time.Millisecond):
	}

	updates <- linkUpdate(unix.RTM_NEWLINK, 7, newTap(), true)
	select {
	case <-trigger:
	case <-time.After(2 * time.Second):
		t.Fatal("tap gaining carrier did not trigger a reconcile")
	}
}

// TestRunRadvActor_RetriesAddrNotReady checks that an actor whose tap address
// is still being assigned is retried locally rather than reported as a failed
// start (#828).
func TestRunRadvActor_RetriesAddrNotReady(t *testing.T) {
	origRun, origDelay, origRetries := radvRunActor, radvAddrNotReadyRetryDelay, radvAddrNotReadyRetries
	t.Cleanup(func() {
		radvRunActor, radvAddrNotReadyRetryDelay, radvAddrNotReadyRetries = origRun, origDelay, origRetries
	})
	radvAddrNotReadyRetryDelay = time.Millisecond
	radvAddrNotReadyRetries = 5

	notReady := fmt.Errorf("open NDP connection: %w", radv.ErrAddrNotReady)
	other := errors.New("permission denied")

	tests := []struct {
		name      string
		results   []error
		wantErr   error
		wantCalls int
	}{
		{"ReadyAfterTwoAttempts", []error{notReady, notReady, nil}, nil, 3},
		{"OtherErrorIsNotRetried", []error{other}, other, 1},
		{
			"GivesUpAfterRetries",
			[]error{notReady, notReady, notReady, notReady, notReady, notReady, notReady},
			radv.ErrAddrNotReady, 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			radvRunActor = func(context.Context, string, int) error {
				err := tt.results[calls]
				calls++
				return err
			}

			err := runRadvActor(context.Background(), radvTestIface, 1500)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Errorf("runRadvActor() = %v, want %v", err, tt.wantErr)
			}
			if calls != tt.wantCalls {
				t.Errorf("radvRunActor called %d times, want %d", calls, tt.wantCalls)
			}
		})
	}
}

// TestRadvActorFailed_AddrNotReadyDoesNotBackOff checks that a start that
// failed only because the tap's address was not ready yet is retried on the
// next reconcile and does not grow the backoff (#828).
func TestRadvActorFailed_AddrNotReadyDoesNotBackOff(t *testing.T) {
	env := newRadvTestEnv(t)
	recordRadvAttachment(t)
	env.links[radvTestIface] = radvTestLink{carrier: true}

	ctx, cancel := context.WithCancel(context.Background())
	actors := &radvActorSet{}
	t.Cleanup(func() {
		cancel()
		actors.wg.Wait()
	})

	reconcileRadvActors(ctx, actors)
	radvActorFailed(actors, awaitRadvFailure(t, actors))
	if got := actors.pending[radvTestIface].failures; got != 1 {
		t.Fatalf("failures after an ordinary failed start = %d, want 1", got)
	}

	// Started again once the backoff elapses, this time failing on an
	// address that is not ready yet.
	env.now = actors.pending[radvTestIface].retryAt
	reconcileRadvActors(ctx, actors)
	awaitRadvFailure(t, actors)
	radvActorFailed(actors, radvActorFailure{
		iface: radvTestIface,
		err:   fmt.Errorf("open NDP connection: %w", radv.ErrAddrNotReady),
	})

	p := actors.pending[radvTestIface]
	if p.failures != 1 {
		t.Errorf("failures after an address-not-ready start = %d, want it unchanged at 1", p.failures)
	}
	reconcileRadvActors(ctx, actors)
	if _, running := actors.cancel[radvTestIface]; !running {
		t.Errorf("actor on %q not retried on the next reconcile after an address-not-ready start", radvTestIface)
	}
}
