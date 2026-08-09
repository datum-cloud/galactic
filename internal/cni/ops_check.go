// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/plumbing/intf"
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
	slog.Info("CHECK: starting", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)

	var errs []error

	// Check node-level state (VRF + host interface).
	hostName, nodeErrs := cnimaster.CheckNodeLevelState(pluginConf.VPC, pluginConf.VPCAttachment)
	errs = append(errs, nodeErrs...)

	// Verify the guest interface is in the container netns.
	guestName := intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
	if err := checkGuestInterface(args.Netns, guestName); err != nil {
		errs = append(errs, fmt.Errorf("guest interface %q: %w", guestName, err))
	}

	// Termination routes are galactic-route's own CHECK now (see
	// internal/cniroute's checkTerminationRoutes) — this plugin's CHECK no
	// longer verifies them.

	// Validate kernel state against prevResult (CNI spec §4.3).
	if pluginConf.RawPrevResult != nil {
		if err := checkPrevResult(pluginConf.RawPrevResult, hostName, args.Netns); err != nil {
			errs = append(errs, fmt.Errorf("prevResult validation: %w", err))
		}
	}

	// Delegate CHECK to the IPAM plugin so a lost or corrupted allocation
	// marker file is caught here too, not just at ADD/DEL time.
	if pluginConf.IPAM != nil {
		if err := ipam.ExecCheck(pluginConf.IPAM.Type, args.StdinData); err != nil {
			errs = append(errs, fmt.Errorf("IPAM CHECK: %w", err))
		}
	}

	if len(errs) > 0 {
		err := fmt.Errorf("CHECK failed: %w", errors.Join(errs...))
		slog.Error("CHECK: failed", "err", err, "containerID", args.ContainerID,
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		return err
	}
	slog.Info("CHECK: passed", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
	return nil
}

// cmdStatus implements the CNI spec STATUS operation — see
// internal/cnimaster.RunStatus for the full reasoning, shared verbatim with
// galactic-tap-cni.
func cmdStatus(args *skel.CmdArgs) error {
	return cnimaster.RunStatus(args.StdinData, cniConfig, ConfFile)
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
			if err := cnimaster.ValidateHostInterface(iface.Name, iface.Mac, iface.Mtu); err != nil {
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
