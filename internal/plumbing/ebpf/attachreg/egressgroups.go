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
// NAT66 for ::/0, the matching NAT64 prefix for the others. A class no group
// serves, or whose group has no eligible shard, gets no route, as an empty
// static list gives none. A class whose shards are all unreachable or
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
	if err != nil {
		return n, err
	}
	stillOpen, err := groups.AnyOpen()
	if err != nil {
		return n, fmt.Errorf("re-read egress shard groups: %w", err)
	}
	if stillOpen {
		return n, nil
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

// installGroupRoutesIn writes, for each of the VRF's egress prefixes, a
// sentinel naming the open group that serves the prefix's class, carrying
// argument. Nothing is resolved here: the group's shards carry their own next
// hops.
func installGroupRoutesIn(
	groups shardGroupReader, table *egressroutemap.EgressRouteTable, vrfTableID uint32, argument uint16,
	nat64Raw string, exists routeExistsFn,
) (int, error) {
	prefixes, err := egressPrefixes(nat64Raw)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, prefix := range prefixes {
		if exists != nil {
			found, err := exists(prefix)
			if err != nil {
				return written, err
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
			return written, fmt.Errorf("find the %s egress shard group: %w", class, err)
		}
		if !found || !status.Open() || status.Candidates == 0 {
			slog.Warn("no egress shard in the cluster translates this route's class; installing no route for it",
				"vrfTable", vrfTableID, "prefix", prefix, "class", class.String())
			continue
		}
		if status.Active == 0 {
			return written, fmt.Errorf("%w yet for %s: the %s egress shard group has %d candidates and none is "+
				"reachable and accepting", srv6.ErrNoShardResolvable, prefix, class, status.Candidates)
		}
		if err := egressGroupRouteAddFn(table, vrfTableID, prefix, groupID, argument); err != nil {
			return written, fmt.Errorf("install %s group route for %s: %w", class, prefix, err)
		}
		written++
	}
	return written, nil
}
