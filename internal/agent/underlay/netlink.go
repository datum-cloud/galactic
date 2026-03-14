package underlay

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProtocolGalacticBGP is the Linux routing protocol ID used to tag all
// underlay routes managed by this controller. Range 192-255 is user-defined.
const ProtocolGalacticBGP = 196

// AddRoute installs or replaces an IPv6 route for dst via gw, tagged with
// protocol 196 so we can identify our routes for garbage collection.
func AddRoute(dst *net.IPNet, gw net.IP) error {
	route := &netlink.Route{
		Dst:      dst,
		Gw:       gw,
		Protocol: ProtocolGalacticBGP,
		Family:   unix.AF_INET6,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route replace %s via %s: %w", dst, gw, err)
	}
	return nil
}

// DelRoute removes the route for dst that was installed by this controller.
func DelRoute(dst *net.IPNet) error {
	route := &netlink.Route{
		Dst:      dst,
		Protocol: ProtocolGalacticBGP,
		Family:   unix.AF_INET6,
	}
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("route del %s: %w", dst, err)
	}
	return nil
}

// ListManagedRoutes returns all IPv6 routes tagged with ProtocolGalacticBGP.
func ListManagedRoutes() ([]netlink.Route, error) {
	filter := &netlink.Route{
		Protocol: ProtocolGalacticBGP,
	}
	routes, err := netlink.RouteListFiltered(unix.AF_INET6, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return nil, fmt.Errorf("list managed routes: %w", err)
	}
	return routes, nil
}
