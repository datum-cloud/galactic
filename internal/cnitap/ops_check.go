// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdCheck validates that the node's tap-side networking state matches what
// was established during cmdAdd. Unlike internal/cni's own cmdCheck, there
// is no guest interface to verify — tap mode never enters a container
// netns.
func cmdCheck(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}
	slog.Info("CHECK: starting", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)

	var errs []error

	hostName, nodeErrs := checkNodeLevelState(pluginConf.VPC, pluginConf.VPCAttachment)
	errs = append(errs, nodeErrs...)

	if err := checkTerminationRoutes(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.Terminations); err != nil {
		errs = append(errs, fmt.Errorf("termination routes: %w", err))
	}

	if pluginConf.RawPrevResult != nil {
		if err := checkPrevResult(pluginConf.RawPrevResult, hostName); err != nil {
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

// cmdStatus implements the CNI spec STATUS operation — see internal/cni's
// own cmdStatus for the full reasoning; identical here.
func cmdStatus(args *skel.CmdArgs) error {
	if err := parseStatusConf(args.StdinData); err != nil {
		return err
	}

	hostConf, err := loadHostConf(ConfFile)
	if err != nil {
		return &types.Error{Code: 7, Msg: fmt.Sprintf("load host CNI config: %v", err)}
	}

	cniConfig.Resolve(&config.ConflistValues{
		Kubeconfig: hostConf.Kubeconfig,
		Namespace:  hostConf.Namespace,
		LogFile:    hostConf.LogFile,
		LogLevel:   hostConf.LogLevel,
	})

	_ = os.Setenv("KUBECONFIG", cniConfig.Kubeconfig)

	setupLogging(cniConfig.LogFile, cniConfig.LogLevel)
	slog.Debug("CNI config received", "stdin", string(args.StdinData))

	slog.Info("STATUS: probing API server reachability")
	if err := probeAPIServer(); err != nil {
		slog.Error("STATUS: API server probe failed", "err", err)
		return &types.Error{Code: 50, Msg: fmt.Sprintf("API server health check failed: %v", err)}
	}
	slog.Info("STATUS: ready")
	return nil
}

// probeAPIServerFn is a variable so tests can override it.
var probeAPIServerFn = func() error {
	kubeconfig, err := ctrl.GetConfig()
	if err != nil {
		if errors.Is(err, rest.ErrNotInCluster) {
			return nil
		}
		return fmt.Errorf("load kubeconfig: %w", err)
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

var probeAPIServer = probeAPIServerFn

// checkNodeLevelState verifies that node-level networking resources exist:
// the VRF interface and the host-side tap interface.
func checkNodeLevelState(vpc, vpcAttachment string) (string, []error) {
	var errs []error

	if err := vrf.Exists(vpc, vpcAttachment); err != nil {
		errs = append(errs, fmt.Errorf("vrf %s-%s: %w", vpc, vpcAttachment, err))
	}

	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	if _, err := netlink.LinkByName(hostName); err != nil {
		errs = append(errs, fmt.Errorf("host interface %q: %w", hostName, err))
	}

	return hostName, errs
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

	routes, err := handle.RouteListFiltered(
		netlink.FAMILY_V6,
		&netlink.Route{Table: int(tableID)},
		netlink.RT_FILTER_TABLE,
	)
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
			if r.Dst != nil &&
				r.Dst.String() == term.Network &&
				r.Gw != nil &&
				r.Gw.Equal(viaIP) &&
				r.LinkIndex > 0 {
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

// checkPrevResult validates that kernel state matches the host interface
// recorded in the prevResult returned by the most recent ADD. Tap mode has
// no guest-side interface or netns to validate against.
func checkPrevResult(rawPrevResult map[string]interface{}, _ string) error {
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

	for _, iface := range result.Interfaces {
		if iface.Name == "" || iface.Sandbox != "" {
			continue
		}
		if err := validateHostInterface(iface.Name, iface.Mac, iface.Mtu); err != nil {
			return fmt.Errorf("interface %q (host): %w", iface.Name, err)
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
