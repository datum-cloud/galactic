// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package radv

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
)

// RunActor owns one tap attachment's entire Router Advertisement lifecycle
// for as long as ctx is not canceled: it sends unsolicited RAs on the
// jittered schedule NextInterval describes, and it replies to Router
// Solicitations (RFC 4861 §6.2.6) so a freshly-booted or reconnected guest
// doesn't have to wait out a full resend cycle to converge. Both jobs share
// one Conn and one "when did we last send" clock, so a solicited reply also
// reschedules the next unsolicited send — see the RFC 4861 §6.2.6 combining
// behavior this mirrors — rather than the guest receiving a redundant
// unsolicited RA moments after a solicited one.
//
// Callers (internal/installer's reconciler) run one RunActor per currently
// recorded attachment (state.go), start it when a new attachment appears,
// and cancel ctx when the attachment disappears or the daemon shuts down.
// RunActor returns nil on a clean ctx cancellation; a non-nil error means it
// never got the Conn open in the first place (nothing to clean up, and the
// reconciler is expected to retry on its next tick since the attachment
// record is still there).
func RunActor(ctx context.Context, iface string, mtu int) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("look up interface %q: %w", iface, err)
	}

	conn, _, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("open NDP connection on %q: %w", iface, err)
	}

	// Without joining this group, the kernel never delivers multicast
	// traffic addressed to ff02::2 to this socket at all — a guest's
	// Router Solicitation is sent there (RFC 4861 §4.1), not to this
	// interface's own unicast address.
	if err := conn.JoinGroup(allRoutersMulticast); err != nil {
		_ = conn.Close()
		return fmt.Errorf("join all-routers multicast group on %q: %w", iface, err)
	}

	rsCh := make(chan netip.Addr)
	var wg sync.WaitGroup
	wg.Add(1)
	go readSolicitations(&wg, conn, rsCh)

	runActorLoop(ctx, conn, iface, mtu, ifi.HardwareAddr, rsCh)

	_ = conn.Close()
	wg.Wait()
	return nil
}

// readSolicitations is RunActor's blocking read loop, run on its own
// goroutine since ndp.Conn.ReadFrom blocks and so can't share a select
// statement with the resend timer in runActorLoop below. It exits as soon
// as ReadFrom errors -- which is exactly what happens once runActorLoop
// closes conn on shutdown, so no separate cancellation signal is needed
// here.
func readSolicitations(wg *sync.WaitGroup, conn *ndp.Conn, rsCh chan<- netip.Addr) {
	defer wg.Done()

	for {
		msg, _, src, err := conn.ReadFrom()
		if err != nil {
			// conn.Close() (runActorLoop shutting down) or a fatal socket
			// error either way -- this actor is done reading either way.
			return
		}
		if _, ok := msg.(*ndp.RouterSolicitation); !ok {
			continue
		}

		select {
		case rsCh <- src:
		case <-time.After(time.Second):
			// The main loop only fails to receive here if it has already
			// returned (about to close conn) -- drop rather than leak this
			// goroutine waiting forever on a send nothing will ever read.
		}
	}
}

// runActorLoop is RunActor's own select loop, split out solely so RunActor
// itself stays a short, readable setup/teardown wrapper. See RunActor's doc
// comment for the combined resend/solicit behavior this implements.
func runActorLoop(
	ctx context.Context, conn *ndp.Conn, iface string, mtu int, hwAddr net.HardwareAddr, rsCh <-chan netip.Addr,
) {
	resendTimer := time.NewTimer(NextInterval())
	defer resendTimer.Stop()

	var lastSent time.Time
	send := func(dst netip.Addr) {
		ra := buildAdvertisement(mtu, hwAddr)
		if err := conn.WriteTo(ra, nil, dst); err != nil {
			slog.Warn("Failed to send router advertisement", "err", err, "hostInterface", iface, "dst", dst)
		}
		lastSent = time.Now()
		resendTimer.Reset(NextInterval())
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-resendTimer.C:
			send(allNodesMulticast)

		case src := <-rsCh:
			select {
			case <-time.After(nextResponseDelay()):
			case <-ctx.Done():
				return
			}

			if rateLimited(lastSent, time.Now()) {
				continue
			}
			send(responseDestination(src))
		}
	}
}

// rateLimited reports whether now is too soon after lastSent to send another
// advertisement, per RFC 4861 §6.2.6/§10 (MinDelayBetweenRAs): a router must
// never send more than one advertisement -- solicited or not -- within that
// window of the last one. A zero lastSent (no advertisement sent yet this
// actor's lifetime) is never rate-limited.
func rateLimited(lastSent, now time.Time) bool {
	if lastSent.IsZero() {
		return false
	}
	return now.Sub(lastSent) < MinDelayBetweenRAs
}

// responseDestination returns the address a solicited reply should be sent
// to for a Router Solicitation whose source address was src. RFC 4861
// §6.1.1: a solicitation with the unspecified source address (::) means the
// guest hasn't self-configured any address yet, so there is nothing to
// unicast a reply to -- fall back to the same all-nodes multicast address
// unsolicited RAs use. Otherwise, unicast directly back to the soliciting
// guest: cheaper than multicast, and correct here since there is exactly
// one guest per tap link, not a shared segment with other listeners to also
// serve.
func responseDestination(src netip.Addr) netip.Addr {
	if src.IsUnspecified() {
		return allNodesMulticast
	}
	return src
}
