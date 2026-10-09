// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package radv

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// ErrAddrNotReady is wrapped by RunActor's error when the interface has no
// usable link-local address yet: the kernel has not assigned one, or duplicate
// address detection still holds it tentative and the kernel refuses to bind
// it. Both clear on their own within moments of the interface gaining carrier,
// so a caller should retry soon rather than count it as a failure.
var ErrAddrNotReady = errors.New("link-local address not ready")

// raWriter is the part of *ndp.Conn runActorLoop sends through, so a test can
// record what the loop sends and when.
type raWriter interface {
	WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error
}

// RunActor owns one tap attachment's whole Router Advertisement lifecycle for
// as long as ctx lives: it sends unsolicited advertisements on the jittered
// schedule, and replies to solicitations so a freshly booted or reconnected
// guest need not wait out a full resend cycle.
//
// It sends the first advertisement as soon as the connection is open, then
// MaxInitialRtrAdvertisements-1 more MinDelayBetweenRAs apart, so a guest gets
// its default route without having to solicit one. Both jobs share one
// connection and one last-sent clock, so a solicited reply also reschedules the
// next unsolicited send rather than the guest receiving a redundant
// advertisement moments later.
//
// Callers run one per recorded attachment, starting it when the attachment
// appears and cancelling when it disappears or the daemon shuts down. It
// returns nil on a clean cancellation; a non-nil error means it never got the
// connection open, leaving nothing to clean up and the caller free to retry on
// its next tick. An error wrapping ErrAddrNotReady means the interface's
// link-local address is not usable yet.
func RunActor(ctx context.Context, iface string, mtu int) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("look up interface %q: %w", iface, err)
	}

	conn, err := listen(ifi)
	if err != nil {
		return fmt.Errorf("open NDP connection on %q: %w", iface, err)
	}

	// Without joining this group the kernel never delivers multicast
	// traffic addressed to it to this socket at all, and a guest's Router
	// Solicitation goes there rather than to this interface's unicast
	// address.
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

// listen opens the NDP connection on ifi's link-local address. ndp.Listen
// reports a missing address only as an untyped error, so the address is looked
// for here first to tell that case apart.
func listen(ifi *net.Interface) (*ndp.Conn, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	if !hasLinkLocal(addrs) {
		return nil, fmt.Errorf("no IPv6 link-local address assigned: %w", ErrAddrNotReady)
	}

	conn, _, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		// The kernel refuses to bind an address that duplicate address
		// detection still holds tentative.
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			return nil, fmt.Errorf("%w: %w", ErrAddrNotReady, err)
		}
		return nil, err
	}
	return conn, nil
}

// hasLinkLocal reports whether addrs holds an IPv6 link-local unicast address.
func hasLinkLocal(addrs []net.Addr) bool {
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipn.IP.To4() == nil && ipn.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// readSolicitations is the blocking read loop, on its own goroutine since the
// read blocks and so cannot share a select with the resend timer. It exits as
// soon as the read errors, which is what happens once the main loop closes the
// connection on shutdown, so it needs no separate cancellation signal.
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
			// The main loop only fails to receive here when it has already
			// returned and is about to close the connection. Drop rather
			// than leak this goroutine on a send nothing will read.
		}
	}
}

// runActorLoop is RunActor's select loop, split out so RunActor stays a short
// setup and teardown wrapper. See RunActor for the combined behavior it
// implements.
func runActorLoop(
	ctx context.Context, conn raWriter, iface string, mtu int, hwAddr net.HardwareAddr, rsCh <-chan netip.Addr,
) {
	// Fires at once: the first advertisement goes out as soon as the
	// connection is open.
	resendTimer := time.NewTimer(0)
	defer resendTimer.Stop()

	var lastSent time.Time
	sent := 0
	send := func(dst netip.Addr) {
		ra := buildAdvertisement(mtu, hwAddr)
		if err := conn.WriteTo(ra, nil, dst); err != nil {
			slog.Warn("Failed to send router advertisement", "err", err, "hostInterface", iface, "dst", dst)
		}
		lastSent = time.Now()
		sent++
		resendTimer.Reset(nextUnsolicitedDelay(sent))
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
// advertisement: a router must never send more than one, solicited or not,
// within the minimum delay. A zero lastSent, meaning none sent yet this
// actor's lifetime, is never rate-limited.
func rateLimited(lastSent, now time.Time) bool {
	if lastSent.IsZero() {
		return false
	}
	return now.Sub(lastSent) < MinDelayBetweenRAs
}

// responseDestination returns where a solicited reply should go for a
// solicitation from src.
//
// An unspecified source means the guest has not self-configured any address, so
// there is nothing to unicast to and the reply goes to the same all-nodes
// address unsolicited advertisements use. Otherwise it goes straight back to
// the guest: cheaper than multicast, and correct here since there is exactly
// one guest per tap link rather than a shared segment.
func responseDestination(src netip.Addr) netip.Addr {
	if src.IsUnspecified() {
		return allNodesMulticast
	}
	return src
}
