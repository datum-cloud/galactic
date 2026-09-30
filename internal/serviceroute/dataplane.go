//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// RouteProgrammer applies the local bidirectional service path for a route
// intent. Implementations must make repeated Apply calls safe.
type RouteProgrammer interface {
	Apply(RouteIntent) error
	Remove(RouteIntent) error
}

// LinuxRouteProgrammer programs plain VRF routes and local pass-through
// entries. It deliberately does not install a default route or NAT64 route;
// those remain owned by Galactic's egress-shard programming.
type LinuxRouteProgrammer struct {
	PinDir string
}

func (p LinuxRouteProgrammer) Apply(intent RouteIntent) error {
	consumerTable, serviceTable, err := p.tables(intent)
	if err != nil {
		return err
	}
	if err := p.route(consumerTable, intent.Service, intent.ServiceDevice, true); err != nil {
		return fmt.Errorf("install consumer-to-service route: %w", err)
	}
	if err := p.route(serviceTable, intent.Consumer, intent.ConsumerDevice, true); err != nil {
		_ = p.route(consumerTable, intent.Service, intent.ServiceDevice, false)
		return fmt.Errorf("install service-to-consumer route: %w", err)
	}
	if err := p.passThrough(consumerTable, intent.Service, true); err != nil {
		return fmt.Errorf("install consumer pass-through: %w", err)
	}
	if err := p.passThrough(serviceTable, intent.Consumer, true); err != nil {
		_ = p.passThrough(consumerTable, intent.Service, false)
		return fmt.Errorf("install service pass-through: %w", err)
	}
	return nil
}

func (p LinuxRouteProgrammer) Remove(intent RouteIntent) error {
	consumerTable, serviceTable, err := p.tables(intent)
	if err != nil {
		return err
	}
	var first error
	for _, op := range []func() error{
		func() error { return p.passThrough(consumerTable, intent.Service, false) },
		func() error { return p.passThrough(serviceTable, intent.Consumer, false) },
		func() error { return p.route(consumerTable, intent.Service, intent.ServiceDevice, false) },
		func() error { return p.route(serviceTable, intent.Consumer, intent.ConsumerDevice, false) },
	} {
		if err := op(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (p LinuxRouteProgrammer) tables(intent RouteIntent) (uint32, uint32, error) {
	consumer, err := vrf.TableID(intent.ConsumerVPC)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve consumer VRF %q: %w", intent.ConsumerVPC, err)
	}
	service, err := vrf.TableID(intent.ServiceVPC)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve service VRF %q: %w", intent.ServiceVPC, err)
	}
	return consumer, service, nil
}

func (p LinuxRouteProgrammer) route(table uint32, prefix *net.IPNet, device string, add bool) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return err
	}
	route := &netlink.Route{Dst: prefix, Table: int(table), LinkIndex: link.Attrs().Index}
	if add {
		return netlink.RouteReplace(route)
	}
	return netlink.RouteDel(route)
}

func (p LinuxRouteProgrammer) passThrough(table uint32, prefix *net.IPNet, add bool) error {
	t, closer, err := egressroutemap.OpenPinnedEgressRouteTable(p.PinDirOrDefault())
	if err != nil {
		return err
	}
	defer closer.Close() // best effort
	if add {
		return t.RegisterPassThrough(table, prefix)
	}
	return t.Unregister(table, prefix)
}

func (p LinuxRouteProgrammer) PinDirOrDefault() string {
	if p.PinDir != "" {
		return p.PinDir
	}
	return attach.PinDir
}
