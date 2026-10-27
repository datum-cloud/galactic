// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package healthprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// ErrUnavailable is wrapped by Dial when the probe cannot be sent at all: the
// host-side interface is missing, or has no link-local address. It says
// nothing about the backend.
var ErrUnavailable = errors.New("probe cannot run")

// Dial opens a TCP connection to addr:port over the host-side interface iface,
// from iface's link-local address, and closes it as soon as the handshake
// completes, sending no data. It returns nil when the handshake completes
// within timeout, retrying connection refusals at most twice 250 ms apart.
// It returns an error wrapping ErrUnavailable when iface or its
// link-local address is missing, and the dial error otherwise.
//
// The link-local source keeps the backend's reply out of the VIP rewrite the
// backend's node applies to everything the backend sends from its bound port:
// the uSID datapath hands a packet for a link-local destination to the kernel
// unchanged. Binding to the address also binds the socket to iface, so the
// route lookup uses the VRF iface is enslaved to.
func Dial(ctx context.Context, iface string, addr netip.Addr, port uint16, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	local, err := linkLocalAddr(iface)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: local.AsSlice(), Zone: iface},
	}
	return retryRefused(ctx, func() error {
		conn, err := dialer.DialContext(ctx, "tcp6", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
		if err != nil {
			return err
		}
		// Reset so probes leave no TIME_WAIT sockets on the node.
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		return conn.Close()
	})
}

// retryRefused retries connection refusals at most twice, 250 ms apart, within
// ctx's deadline. Other errors and cancellation stop the probe immediately.
func retryRefused(ctx context.Context, attempt func() error) error {
	for i := 0; ; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := attempt()
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || i == 2 {
			return err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// linkLocalAddr returns iface's IPv6 link-local address.
func linkLocalAddr(iface string) (netip.Addr, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: interface %s: %w", ErrUnavailable, iface, err)
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: addresses of %s: %w", ErrUnavailable, iface, err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if ok && ip.Is6() && !ip.Is4In6() && ip.IsLinkLocalUnicast() {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: interface %s has no IPv6 link-local address", ErrUnavailable, iface)
}
