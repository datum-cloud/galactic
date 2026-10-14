// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// shardGroupReader is what installing a VRF's egress routes needs from the
// egress shard groups. *egressroutemap.ShardGroupTable implements it.
type shardGroupReader interface {
	AnyOpen() (bool, error)
	FindClass(class egressroutemap.TranslationClass) (uint32, egressroutemap.GroupStatus, bool, error)
}

// openShardGroupsFn opens the shard groups pinned under pinDir. A datapath
// older than the shard group map has no such pin, which reads as nil: ordered
// mode, as before. A variable so tests can state the groups without a pinned
// map.
var openShardGroupsFn = func(pinDir string) (shardGroupReader, io.Closer, error) {
	groups, closer, err := egressroutemap.OpenPinnedShardGroupTable(pinDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, io.NopCloser(nil), nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open pinned egress shard groups: %w", err)
	}
	return groups, closer, nil
}

// egressGroupRouteAddFn is a variable so tests can observe group route
// installs without a pinned map.
var egressGroupRouteAddFn = func(
	table *egressroutemap.EgressRouteTable, vrfTableID uint32, prefix *net.IPNet, groupID uint32, argument uint16,
) error {
	return table.RegisterGroup(vrfTableID, prefix, groupID, argument)
}

// egressPrefixes returns the routes a VRF's egress needs: ::/0, then one per
// NAT64 prefix in nat64Raw.
func egressPrefixes(nat64Raw string) ([]*net.IPNet, error) {
	prefixes, err := config.ParseNAT64Prefixes(nat64Raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", config.EnvCNINAT64Prefix, err)
	}
	return append([]*net.IPNet{egressroutemap.DefaultPrefix}, prefixes...), nil
}

// installVRFEgress installs vrfTableID's egress routes, in hashed mode when
// any shard group is open and in ordered mode otherwise. exists, when not nil,
// skips routes already present.
//
// In hashed mode each route names the group serving its translation class:
// NAT66 for ::/0, the matching NAT64 prefix for the others. NAT66 with no
// group, or no eligible shard, gets no route, as an empty static list gives
// none. A NAT64 prefix with no eligible shard names its empty group instead,
// so ::/0 cannot catch it. A class whose shards are all unreachable or
// draining fails the ADD, as an ordered list with no resolvable shard does.
//
// Once the routes are written the groups are read again. galactic-cni marks
// every group closing before it moves the cluster back to ordered mode, and
// moves routes off a group only after that; a route written by an ADD that
// read the groups before they closed, and is written after galactic-cni's last
// scan, would otherwise outlive the group. If the groups closed meanwhile,
// this ADD rewrites its routes in ordered mode itself.
func installVRFEgress(
	groups shardGroupReader, table *egressroutemap.EgressRouteTable, vrfTableID uint32, argument uint16,
	cfg EgressConfig, exists routeExistsFn,
) (int, error) {
	open := false
	if groups != nil {
		var err error
		if open, err = groups.AnyOpen(); err != nil {
			return 0, fmt.Errorf("read egress shard groups: %w", err)
		}
	}
	if !open {
		return installOrderedEgress(table, vrfTableID, argument, cfg, exists)
	}

	n, err := installGroupRoutesIn(groups, table, vrfTableID, argument, cfg.NAT64Prefix, exists)
	if err != nil && !errors.Is(err, errClassGroupNotOpen) {
		return n, err
	}
	stillOpen, rerr := groups.AnyOpen()
	if rerr != nil {
		return n, fmt.Errorf("re-read egress shard groups: %w", rerr)
	}
	if stillOpen {
		return n, err
	}
	slog.Info("egress shard groups closed while installing this VRF's routes; installing them in ordered mode",
		"vrfTable", vrfTableID)
	m, err := installOrderedEgress(table, vrfTableID, argument, cfg, nil)
	if err != nil {
		return n, fmt.Errorf("egress shard groups closed during install, and ordered install failed: %w", err)
	}
	return m, nil
}

// installOrderedEgress installs vrfTableID's routes toward the first
// resolvable shard of cfg's static list. An empty list installs nothing.
func installOrderedEgress(
	table *egressroutemap.EgressRouteTable, vrfTableID uint32, argument uint16, cfg EgressConfig,
	exists routeExistsFn,
) (int, error) {
	tenantSIDs, err := tenantShardSIDs(cfg, argument)
	if err != nil || len(tenantSIDs) == 0 {
		return 0, err
	}
	return installEgressRoutesIn(table, vrfTableID, tenantSIDs, cfg.NAT64Prefix, exists)
}

// errClassGroupNotOpen reports a configured NAT64 prefix whose class has no
// open group while hashed mode is in force.
var errClassGroupNotOpen = errors.New("no open egress shard group for this NAT64 prefix's class")

// groupRoute is one sentinel installGroupRoutesIn will write.
type groupRoute struct {
	prefix  *net.IPNet
	class   egressroutemap.TranslationClass
	groupID uint32
}

// installGroupRoutesIn writes, for each of the VRF's egress prefixes, a
// sentinel naming the open group that serves the prefix's class, carrying
// argument. Nothing is resolved here: the group's shards carry their own next
// hops.
//
// A NAT64 prefix is never left to ::/0. One whose group has no candidate gets
// a sentinel naming that empty group, which drops its packets, and one with no
// open group fails the install. Every route is checked before any is written,
// and NAT64 routes are written before ::/0.
func installGroupRoutesIn(
	groups shardGroupReader, table *egressroutemap.EgressRouteTable, vrfTableID uint32, argument uint16,
	nat64Raw string, exists routeExistsFn,
) (int, error) {
	prefixes, err := egressPrefixes(nat64Raw)
	if err != nil {
		return 0, err
	}
	var nat64, nat66 []groupRoute
	for _, prefix := range prefixes {
		if exists != nil {
			found, err := exists(prefix)
			if err != nil {
				return 0, err
			}
			if found {
				continue
			}
		}
		class, ok := egressroutemap.ClassForRoute(prefix)
		if !ok {
			continue
		}
		groupID, status, found, err := groups.FindClass(class)
		if err != nil {
			return 0, fmt.Errorf("find the %s egress shard group: %w", class, err)
		}
		switch {
		case (!found || !status.Open()) && class.NAT64:
			return 0, fmt.Errorf("%w: %s", errClassGroupNotOpen, prefix)
		case !found || !status.Open() || (status.Candidates == 0 && !class.NAT64):
			slog.Warn("no egress shard in the cluster translates this route's class; installing no route for it",
				"vrfTable", vrfTableID, "prefix", prefix, "class", class.String())
			continue
		case status.Candidates == 0:
			slog.Warn("no egress shard in the cluster translates this NAT64 prefix; its route drops",
				"vrfTable", vrfTableID, "prefix", prefix, "class", class.String(), "group", groupID)
		case status.Active == 0:
			return 0, fmt.Errorf("%w yet for %s: the %s egress shard group has %d candidates and none is "+
				"reachable and accepting", srv6.ErrNoShardResolvable, prefix, class, status.Candidates)
		}
		route := groupRoute{prefix: prefix, class: class, groupID: groupID}
		if class.NAT64 {
			nat64 = append(nat64, route)
		} else {
			nat66 = append(nat66, route)
		}
	}
	written := 0
	for _, r := range append(nat64, nat66...) {
		if err := egressGroupRouteAddFn(table, vrfTableID, r.prefix, r.groupID, argument); err != nil {
			return written, fmt.Errorf("install %s group route for %s: %w", r.class, r.prefix, err)
		}
		written++
	}
	return written, nil
}
