// Package routesync streams BGP RIB events from GoBGP and programs netlink routes.
package routesync

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	bgpnetlink "go.miloapis.com/bgp/internal/netlink"
	bgpcontroller "go.miloapis.com/bgp/internal/controller"
)

const routeWatchRetryInterval = 2 * time.Second

// RunRouteWatcher streams BGP path events from GoBGP and programs/removes
// netlink routes (proto 196) for received prefixes. It automatically reconnects
// the event stream on error.
//
// srv6Net is this node's own prefix (e.g. a /48); routes matching it are skipped
// so the node does not install a route to itself. Pass an empty string to disable
// the self-route filter.
//
// This function blocks until ctx is cancelled.
func RunRouteWatcher(ctx context.Context, gobgp *bgpcontroller.GoBGPClient, srv6Net string) {
	var ownPrefix *net.IPNet
	if srv6Net != "" {
		_, ownPrefix, _ = net.ParseCIDR(srv6Net)
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c := gobgp.Client()
		if c == nil {
			log.Printf("bgp/route: GoBGP not connected, retrying in %s", routeWatchRetryInterval)
			select {
			case <-ctx.Done():
				return
			case <-time.After(routeWatchRetryInterval):
			}
			continue
		}

		if err := watchAndProgram(ctx, c, ownPrefix); err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("bgp/route: stream error: %v — restarting in %s", err, routeWatchRetryInterval)
				select {
				case <-ctx.Done():
					return
				case <-time.After(routeWatchRetryInterval):
				}
			}
		}
	}
}

// watchAndProgram opens a WatchEvent stream on GoBGP and programs netlink routes
// until the stream ends or ctx is cancelled.
func watchAndProgram(ctx context.Context, client gobgpapi.GobgpApiClient, ownPrefix *net.IPNet) error {
	knownPrefixes := make(map[string]net.IP)

	stream, err := client.WatchEvent(ctx, &gobgpapi.WatchEventRequest{
		Table: &gobgpapi.WatchEventRequest_Table{
			Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
				{
					Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
					Init: true,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("WatchEvent: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("stream recv: %w", err)
			}
		}

		table := resp.GetTable()
		if table == nil {
			continue
		}

		for _, path := range table.Paths {
			if path.Family == nil ||
				path.Family.Afi != gobgpapi.Family_AFI_IP6 ||
				path.Family.Safi != gobgpapi.Family_SAFI_UNICAST {
				continue
			}

			prefix, nextHop, err := extractPrefixAndNextHop(path)
			if err != nil {
				log.Printf("bgp/route: skip path: %v", err)
				continue
			}

			// Skip our own prefix to avoid self-routing.
			if ownPrefix != nil && prefix.String() == ownPrefix.String() {
				continue
			}

			if path.IsWithdraw {
				log.Printf("bgp/route: DEL route %s", prefix)
				if err := bgpnetlink.DelRoute(prefix); err != nil {
					log.Printf("bgp/route: del route %s: %v", prefix, err)
				}
				delete(knownPrefixes, prefix.String())
			} else {
				log.Printf("bgp/route: ADD route %s via %s", prefix, nextHop)
				if err := bgpnetlink.AddRoute(prefix, nextHop); err != nil {
					log.Printf("bgp/route: add route %s via %s: %v", prefix, nextHop, err)
				}
				knownPrefixes[prefix.String()] = nextHop
			}
		}
	}
}

// extractPrefixAndNextHop parses the NLRI and next-hop from a GoBGP Path.
func extractPrefixAndNextHop(path *gobgpapi.Path) (*net.IPNet, net.IP, error) {
	nlri, err := apiutil.GetNativeNlri(path)
	if err != nil {
		return nil, nil, fmt.Errorf("get native NLRI: %w", err)
	}

	_, ipNet, err := net.ParseCIDR(nlri.String())
	if err != nil {
		return nil, nil, fmt.Errorf("parse prefix %s: %w", nlri.String(), err)
	}

	attrs, err := apiutil.GetNativePathAttributes(path)
	if err != nil {
		return nil, nil, fmt.Errorf("get native path attrs: %w", err)
	}

	var nextHop net.IP
	for _, attr := range attrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			nextHop = a.Value
		case *bgp.PathAttributeMpReachNLRI:
			if len(a.Nexthop) > 0 {
				nextHop = a.Nexthop
			}
		}
	}
	if nextHop == nil {
		return nil, nil, fmt.Errorf("no next-hop in path attributes")
	}

	return ipNet, nextHop, nil
}
