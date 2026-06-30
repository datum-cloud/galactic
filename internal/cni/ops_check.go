// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdCheck validates that the container's network state matches what was
// established during cmdAdd. Per the CNI spec, CHECK is called by the runtime
// to probe the status of an existing container and should return an error if
// managed resources are missing or in an invalid state.
func cmdCheck(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	var errs []error

	// Check VRF interface exists.
	if err := vrf.Exists(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		errs = append(errs, fmt.Errorf("vrf %s-%s: %w", pluginConf.VPC, pluginConf.VPCAttachment, err))
	}

	// Check the host-side interface exists.
	hostName := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	if _, err := netlink.LinkByName(hostName); err != nil {
		errs = append(errs, fmt.Errorf("host interface %q: %w", hostName, err))
	}

	// For veth mode, verify the guest interface is in the container netns.
	if pluginConf.InterfaceType == interfaceTypeVeth {
		guestName := intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
		if err := checkGuestInterface(args.Netns, guestName); err != nil {
			errs = append(errs, fmt.Errorf("guest interface %q: %w", guestName, err))
		}

		// Verify termination routes exist in the VRF table.
		if err := checkTerminationRoutes(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.Terminations); err != nil {
			errs = append(errs, fmt.Errorf("termination routes: %w", err))
		}
	}

	// Validate kernel state against prevResult (CNI spec §4.3).
	if pluginConf.RawPrevResult != nil {
		if err := checkPrevResult(pluginConf.RawPrevResult, hostName, args.Netns); err != nil {
			errs = append(errs, fmt.Errorf("prevResult validation: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("CHECK failed: %w", errors.Join(errs...))
	}
	return nil
}

// cmdStatus implements the CNI spec STATUS operation. It is called by the
// runtime to determine whether the plugin is ready to service ADD requests.
// Unlike cmdCheck, no container is attached so there is no Netns to inspect.
// STATUS validates the plugin's own readiness: config is parseable, managed
// kernel resources (VRF, host interface) exist, and the API server is
// reachable for BGPAdvertisement CRD operations.
func cmdStatus(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	var errs []error

	// Check VRF interface exists.
	if err := vrf.Exists(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		errs = append(errs, fmt.Errorf("vrf %s-%s: %w", pluginConf.VPC, pluginConf.VPCAttachment, err))
	}

	// Check the host-side interface exists.
	hostName := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	if _, err := netlink.LinkByName(hostName); err != nil {
		errs = append(errs, fmt.Errorf("host interface %q: %w", hostName, err))
	}

	// Check API server reachability with a lightweight GET.
	if err := probeAPIServer(); err != nil {
		errs = append(errs, fmt.Errorf("api server: %w", err))
	}

	if len(errs) > 0 {
		// Code 50 = plugin not available. Per CNI spec v1.1.0 §4.4, STATUS
		// errors must use a typed error code so runtimes can distinguish
		// plugin unavailability (retry/reschedule) from generic failures.
		return types.NewError(50, "STATUS failed", errors.Join(errs...).Error())
	}
	return nil
}

// probeAPIServer performs a lightweight GET against the in-cluster API server
// to verify reachability. Returns nil when the server responds (any HTTP
// status code) or when running outside a cluster with no kubeconfig.
func probeAPIServer() error {
	kubeconfig, err := ctrl.GetConfig()
	if err != nil {
		// No kubeconfig (running outside a cluster); skip API check.
		return nil
	}
	kubeconfig.Timeout = 2 * time.Second
	httpClient, err := rest.HTTPClientFor(kubeconfig)
	if err != nil {
		return fmt.Errorf("build http client: %w", err)
	}
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		kubeconfig.Host+"/healthz",
		nil,
	)
	if err != nil {
		return fmt.Errorf("build healthz request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthz request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort probe
	return nil
}

// checkGuestInterface verifies that the named interface exists inside the
// given network namespace. Returns nil when the interface is present.
func checkGuestInterface(netnsPath, ifName string) error {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		if _, err := handle.LinkByName(ifName); err != nil {
			return fmt.Errorf("find interface %q: %w", ifName, err)
		}
		return nil
	})
}

// checkTerminationRoutes verifies that all termination routes exist in the
// VRF table for the given VPC/VPCAttachment pair.
func checkTerminationRoutes(vpc, vpcAttachment string, terminations []Termination) error {
	tableID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return fmt.Errorf("get VRF table ID: %w", err)
	}

	handle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("create netlink handle: %w", err)
	}
	defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

	routes, err := handle.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	dev := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	for _, term := range terminations {
		viaIP := net.ParseIP(term.Via)
		if viaIP == nil {
			return fmt.Errorf("invalid termination gateway %q", term.Via)
		}
		found := false
		for _, r := range routes {
			if r.Table == int(tableID) &&
				r.Dst != nil &&
				r.Dst.String() == term.Network &&
				r.Gw != nil &&
				r.Gw.Equal(viaIP) &&
				r.LinkIndex > 0 {
				// Verify the link name matches (defers to the veth/tap device).
				if link, linkErr := handle.LinkByIndex(r.LinkIndex); linkErr == nil && link.Attrs().Name == dev {
					found = true
					break
				}
			}
		}
		if !found {
			return fmt.Errorf("missing route %s via %s in VRF table %d", term.Network, term.Via, tableID)
		}
	}
	return nil
}

// checkPrevResult validates that kernel state matches the interfaces and IPs
// recorded in the prevResult returned by the most recent ADD. Per the CNI spec
// §4.3, CHECK must verify that managed resources have not drifted.
func checkPrevResult(rawPrevResult map[string]interface{}, _ string, netns string) error {
	// RawPrevResult is map[string]interface{} — marshal back to JSON, then
	// parse as a versioned CNI result.
	jsonBytes, err := json.Marshal(rawPrevResult)
	if err != nil {
		return fmt.Errorf("marshal prevResult: %w", err)
	}
	res, err := type100.NewResult(jsonBytes)
	if err != nil {
		return fmt.Errorf("parse prevResult: %w", err)
	}
	result, err := type100.GetResult(res)
	if err != nil {
		return fmt.Errorf("get prevResult: %w", err)
	}

	// Validate each interface declared in prevResult against the kernel.
	for _, iface := range result.Interfaces {
		if iface.Name == "" {
			continue
		}

		// Host-side interface: validate MAC and MTU from the host namespace.
		if iface.Sandbox == "" {
			if err := validateHostInterface(iface.Name, iface.Mac, iface.Mtu); err != nil {
				return fmt.Errorf("interface %q (host): %w", iface.Name, err)
			}
			continue
		}

		// Guest-side interface: validate MAC and MTU from inside the container netns.
		if err := validateGuestInterface(iface.Name, iface.Mac, iface.Mtu, netns); err != nil {
			return fmt.Errorf("interface %q (guest): %w", iface.Name, err)
		}
	}

	// Validate each IP assignment against the kernel.
	for _, ipConfig := range result.IPs {
		if ipConfig.Interface == nil {
			continue
		}
		idx := *ipConfig.Interface
		if idx < 0 || idx >= len(result.Interfaces) {
			return fmt.Errorf("ipConfig interface index %d out of range [0, %d)", idx, len(result.Interfaces))
		}
		targetIface := result.Interfaces[idx]
		if targetIface.Sandbox == "" {
			// Host-side IP — not expected in our plugin, but skip gracefully.
			continue
		}
		if err := validateIPOnInterface(ipConfig.Address.IP, targetIface.Name, netns); err != nil {
			return fmt.Errorf("ip %s on %q (guest): %w", ipConfig.Address.String(), targetIface.Name, err)
		}
	}

	return nil
}

// validateHostInterface checks that a host-side interface's MAC and MTU match
// the values recorded in prevResult.
func validateHostInterface(name, wantMac string, wantMtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find link: %w", err)
	}
	if wantMac != "" && link.Attrs().HardwareAddr.String() != wantMac {
		return fmt.Errorf("MAC mismatch: expected %q, got %q", wantMac, link.Attrs().HardwareAddr.String())
	}
	if wantMtu > 0 && link.Attrs().MTU != wantMtu {
		return fmt.Errorf("MTU mismatch: expected %d, got %d", wantMtu, link.Attrs().MTU)
	}
	return nil
}

// validateGuestInterface checks that a guest-side interface's MAC and MTU match
// the values recorded in prevResult, reading from inside the container netns.
func validateGuestInterface(name, wantMac string, wantMtu int, netns string) error {
	containerNS, err := ns.GetNS(netns)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netns, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(name)
		if err != nil {
			return fmt.Errorf("find link: %w", err)
		}
		if wantMac != "" && link.Attrs().HardwareAddr.String() != wantMac {
			return fmt.Errorf("MAC mismatch: expected %q, got %q", wantMac, link.Attrs().HardwareAddr.String())
		}
		if wantMtu > 0 && link.Attrs().MTU != wantMtu {
			return fmt.Errorf("MTU mismatch: expected %d, got %d", wantMtu, link.Attrs().MTU)
		}
		return nil
	})
}

// validateIPOnInterface verifies that the given IP address is assigned to the
// named interface inside the container netns.
func validateIPOnInterface(ip net.IP, name, netns string) error {
	containerNS, err := ns.GetNS(netns)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netns, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(name)
		if err != nil {
			return fmt.Errorf("find link: %w", err)
		}

		addrs, err := handle.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("list addresses: %w", err)
		}

		for _, addr := range addrs {
			if addr.IP.Equal(ip) {
				return nil
			}
		}
		return fmt.Errorf("ip %s not assigned to %q", ip, name)
	})
}
