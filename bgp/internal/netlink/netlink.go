// Package netlink manages IPv6 routes tagged with the BGP operator's protocol ID.
package netlink

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProtocolBGPOperator is the Linux routing protocol ID used to tag all underlay
// routes managed by this operator. Range 192–255 is user-defined; 196 is the
// same value used historically by galactic-agent so existing routes remain valid.
const ProtocolBGPOperator = 196

// AddRoute installs or replaces an IPv6 route for dst via gw, tagged with
// ProtocolBGPOperator so routes can be identified for garbage collection.
func AddRoute(dst *net.IPNet, gw net.IP) error {
	route := &netlink.Route{
		Dst:      dst,
		Gw:       gw,
		Protocol: ProtocolBGPOperator,
		Family:   unix.AF_INET6,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route replace %s via %s: %w", dst, gw, err)
	}
	return nil
}

// DelRoute removes the route for dst that was installed by this operator.
func DelRoute(dst *net.IPNet) error {
	route := &netlink.Route{
		Dst:      dst,
		Protocol: ProtocolBGPOperator,
		Family:   unix.AF_INET6,
	}
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("route del %s: %w", dst, err)
	}
	return nil
}

// ListManagedRoutes returns all IPv6 routes tagged with ProtocolBGPOperator.
func ListManagedRoutes() ([]netlink.Route, error) {
	filter := &netlink.Route{
		Protocol: ProtocolBGPOperator,
	}
	routes, err := netlink.RouteListFiltered(unix.AF_INET6, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return nil, fmt.Errorf("list managed routes: %w", err)
	}
	return routes, nil
}
