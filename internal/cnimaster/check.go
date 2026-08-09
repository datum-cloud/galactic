// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnimaster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// RunStatus implements the CNI spec STATUS operation shared by both master
// plugins: config is parseable and the API server is reachable for
// BGPAdvertisement CRD operations. Attachment-specific kernel resources
// (VRF, host interface) are NOT checked because STATUS must succeed before
// any ADD has ever run.
//
// cniConfig and confFile are the caller's own package state — see
// ParseConf's doc comment for why these aren't shared globals.
func RunStatus(stdinData []byte, cniConfig *config.CNIConfig, confFile string) error {
	// Validate config is parseable (minimal check — no VPC/VPCAttachment
	// validation since STATUS must succeed before any ADD has run).
	if err := ParseStatusConf(stdinData); err != nil {
		return err
	}

	// Load host CNI config to resolve Kubeconfig and LogFile
	hostConf, err := LoadHostConf(confFile)
	if err != nil {
		return &types.Error{Code: 7, Msg: fmt.Sprintf("load host CNI config: %v", err)}
	}

	// Resolve config: env var > conflist > default.
	cniConfig.Resolve(&config.ConflistValues{
		Kubeconfig: hostConf.Kubeconfig,
		Namespace:  hostConf.Namespace,
		LogFile:    hostConf.LogFile,
		LogLevel:   hostConf.LogLevel,
	})

	// Propagate Kubeconfig
	_ = os.Setenv("KUBECONFIG", cniConfig.Kubeconfig)

	// Setup Logging
	SetupLogging(cniConfig.LogFile, cniConfig.LogLevel)
	slog.Debug("CNI config received", "stdin", string(stdinData))

	// Config is parseable and API server is reachable.
	slog.Info("STATUS: probing API server reachability")
	if err := ProbeAPIServer(); err != nil {
		slog.Error("STATUS: API server probe failed", "err", err)
		return &types.Error{Code: 50, Msg: fmt.Sprintf("API server health check failed: %v", err)}
	}
	slog.Info("STATUS: ready")
	return nil
}

// ProbeAPIServerFn performs a lightweight GET against the in-cluster API
// server to verify reachability. Returns nil when the server responds (any
// HTTP status code) or when running outside a cluster with no kubeconfig.
//
// ProbeAPIServer is a variable so tests can override it.
var ProbeAPIServerFn = func() error {
	kubeconfig, err := ctrl.GetConfig()
	if err != nil {
		if errors.Is(err, rest.ErrNotInCluster) {
			// Not running in-cluster; skip API check.
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

// ProbeAPIServer is the seam cmdStatus/RunStatus call through; tests
// override it (and restore ProbeAPIServerFn afterward) to simulate API
// server reachability failures without a real cluster.
var ProbeAPIServer = ProbeAPIServerFn

// CheckNodeLevelState verifies that node-level networking resources exist:
// the VRF interface and the host-side endpoint interface. Returns the host
// interface name (for callers that need it, e.g. cmdCheck's prevResult
// validation) and a slice of errors (nil when all checks pass) so callers
// can accumulate and report all failures at once.
func CheckNodeLevelState(vpc, vpcAttachment string) (string, []error) {
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

// ValidateHostInterface checks that a host-side interface's MAC and MTU
// match the values recorded in prevResult.
func ValidateHostInterface(name, wantMac string, wantMtu int) error {
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
