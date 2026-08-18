// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/nadpatch"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// cmdCheck verifies that the BGP state cmdAdd published is still in place:
// the BGPVRFInstance and BGPAdvertisement CRDs exist, and — when this
// node's BGPRouter has SRv6 configured — the eBPF vrf_table entry for this
// attachment is still registered. None of this is a move from
// internal/cni's own CHECK; it's genuinely new, since nothing before this
// split ever verified CRD/eBPF state independently of kernel interface
// state.
func cmdCheck(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}
	slog.Info("CHECK: starting", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)

	k8s, err := newK8sClient()
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()

	var errs []error

	vrfInst := &bgpv1alpha1.BGPVRFInstance{}
	vrfName := crdnames.BGPVRFInstanceName(pluginConf.VPC, cniConfig.NodeName)
	vrfErr := k8s.Get(ctx, client.ObjectKey{Name: vrfName, Namespace: pluginConf.Namespace}, vrfInst)
	if vrfErr != nil {
		errs = append(errs, fmt.Errorf("BGPVRFInstance %s: %w", vrfName, vrfErr))
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advName := crdnames.BGPAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment)
	if err := k8s.Get(ctx, client.ObjectKey{Name: advName, Namespace: pluginConf.Namespace}, adv); err != nil {
		errs = append(errs, fmt.Errorf("BGPAdvertisement %s: %w", advName, err))
	}

	// ipamResult == nil or carrying no IPv6 address means cmdAdd never
	// published an EndpointSlice for this attachment in the first place —
	// same "no address to publish" skip as cmdAdd's own (see ops_add.go),
	// not tap/VM-specific (Open Decision 5).
	if _, ipamResult, _, prevErr := inferFromPrevResult(pluginConf.RawPrevResult); prevErr != nil {
		errs = append(errs, fmt.Errorf("infer from prevResult: %w", prevErr))
	} else if ipamResult != nil && ipamResult.IPv6Subnet != nil {
		podName := nadpatch.ParsePodName(args.Args)
		if podName == "" {
			errs = append(errs, errors.New("EndpointSlice: no K8S_POD_NAME in CNI_ARGS"))
		} else if err := checkEndpointSlice(
			ctx, k8s, pluginConf, podName, ipamResult.IPv6Subnet.IP, vrfErr == nil, vrfInst.Spec.VRFID,
		); err != nil {
			errs = append(errs, err)
		}
	}

	// The eBPF vrf_table entry is only checkable once the BGPVRFInstance
	// lookup succeeded (it carries the Argument value the entry is keyed
	// on) and this node's router actually has SRv6 configured — matches
	// registerEBPFDatapath's own no-op case.
	if vrfErr == nil {
		if err := checkEBPFEntry(ctx, k8s, pluginConf, uint16(vrfInst.Spec.VRFID)); err != nil {
			errs = append(errs, err)
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

// checkEBPFEntry verifies every eBPF table registerEBPFDatapath wrote for
// this attachment still exists and is intact: the locator_table entry (this
// router's own node), the function_table entry (SRv6 End.DT46 behavior),
// and the vrf_table entry (still resolving to this attachment's own VRF
// table id) — plus the same nodeID range check ADD treats as a hard error.
// Checking vrf_table alone would miss a corrupted/missing locator or
// function entry, or a nodeID that drifted out of range after ADD, while
// still reporting the attachment healthy. Returns nil (not an error) when
// this node's router has no SRv6Locator/nodeID configured — SRv6 was
// intentionally never set up for this attachment, matching
// registerEBPFDatapath's own no-op case.
func checkEBPFEntry(ctx context.Context, k8s client.Client, pluginConf *PluginConf, argument uint16) error {
	bgp, err := lookupBGPRouter(ctx, k8s, cniConfig.NodeName, pluginConf.Namespace)
	if err != nil {
		return fmt.Errorf("look up BGPRouter: %w", err)
	}
	if bgp.srv6Locator == "" || bgp.nodeID == 0 {
		return nil
	}

	if bgp.nodeID < uformat.NodeIDMin || bgp.nodeID > uformat.NodeIDMax {
		return fmt.Errorf("eBPF check: nodeID %d out of range [%#x,%#x]",
			bgp.nodeID, uint16(uformat.NodeIDMin), uint16(uformat.NodeIDMax))
	}

	prefix, err := netip.ParsePrefix(bgp.srv6Locator)
	if err != nil {
		return fmt.Errorf("parse SRv6 locator %q: %w", bgp.srv6Locator, err)
	}
	block, err := uformat.Block(prefix.Addr())
	if err != nil {
		return fmt.Errorf("derive eBPF uSID Block from locator %q: %w", bgp.srv6Locator, err)
	}

	vrfTableID, err := vrf.TableID(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("get VRF table ID: %w", err)
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(ebpfPinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()

	var errs []error

	if _, ok, err := registry.Locator.Get(block, uint16(bgp.nodeID)); err != nil {
		errs = append(errs, fmt.Errorf("read eBPF locator_table entry: %w", err))
	} else if !ok {
		errs = append(errs, fmt.Errorf(
			"eBPF locator_table entry for block %#x node-id %#x not found", block, uint16(bgp.nodeID)))
	}

	if funcEntry, ok, err := registry.Function.Get(block, uformat.FunctionEndDT46); err != nil {
		errs = append(errs, fmt.Errorf("read eBPF function_table entry: %w", err))
	} else if !ok {
		errs = append(errs, fmt.Errorf(
			"eBPF function_table entry for block %#x function %#x not found", block, uformat.FunctionEndDT46))
	} else if funcEntry.Behavior != usidmap.BehaviorEndDT46 {
		errs = append(errs, fmt.Errorf(
			"eBPF function_table entry Behavior = %#x, want %#x", funcEntry.Behavior, usidmap.BehaviorEndDT46))
	}

	entry, ok, err := registry.VRF.Get(block, argument)
	if err != nil {
		errs = append(errs, fmt.Errorf("read eBPF vrf_table entry: %w", err))
	} else if !ok {
		errs = append(errs, fmt.Errorf("eBPF vrf_table entry for block %#x argument %#x not found", block, argument))
	} else if entry.VRFTableID != vrfTableID {
		errs = append(errs, fmt.Errorf("eBPF vrf_table entry VRFTableID = %#x, want %#x", entry.VRFTableID, vrfTableID))
	}

	return errors.Join(errs...)
}

// checkEndpointSlice verifies the per-pod EndpointSlice cmdAdd published
// (endpointslice.go) is still in place: it exists, carries the pod's
// current address, and its tenant-id/SID label and annotations match
// freshly recomputed expected values. vrfIDKnown is false when the
// BGPVRFInstance lookup in cmdCheck above failed, in which case the SID
// can't be recomputed and its annotation is not checked — matches
// registerEBPFDatapath/checkEBPFEntry's own "can't check what we can't
// compute" convention.
func checkEndpointSlice(
	ctx context.Context, k8s client.Client, pluginConf *PluginConf, podName string,
	addr net.IP, vrfIDKnown bool, vrfID int32,
) error {
	name := crdnames.EndpointSliceName(podName)
	slice := &discoveryv1.EndpointSlice{}
	if err := k8s.Get(ctx, client.ObjectKey{Name: name, Namespace: pluginConf.Namespace}, slice); err != nil {
		return fmt.Errorf("EndpointSlice %s: %w", name, err)
	}

	var errs []error

	wantAddr := addr.String()
	var gotAddr string
	if len(slice.Endpoints) > 0 && len(slice.Endpoints[0].Addresses) > 0 {
		gotAddr = slice.Endpoints[0].Addresses[0]
	}
	if gotAddr != wantAddr {
		errs = append(errs, fmt.Errorf("EndpointSlice %s address = %q, want %q", name, gotAddr, wantAddr))
	}

	wantTenantID := crdnames.TenantIdentifier(pluginConf.VPC, pluginConf.VPCAttachment)
	if got := slice.Labels[crdnames.LabelTenantID]; got != wantTenantID {
		errs = append(errs, fmt.Errorf(
			"EndpointSlice %s label %s = %q, want %q", name, crdnames.LabelTenantID, got, wantTenantID))
	}
	if got := slice.Annotations[crdnames.AnnotationTenantID]; got != wantTenantID {
		errs = append(errs, fmt.Errorf(
			"EndpointSlice %s annotation %s = %q, want %q", name, crdnames.AnnotationTenantID, got, wantTenantID))
	}

	if vrfIDKnown {
		bgp, err := lookupBGPRouter(ctx, k8s, cniConfig.NodeName, pluginConf.Namespace)
		if err != nil {
			errs = append(errs, fmt.Errorf("look up BGPRouter for EndpointSlice SID check: %w", err))
		} else if bgp.srv6Locator != "" && bgp.nodeID != 0 {
			sid, err := srv6.ComputeSID(bgp.srv6Locator, bgp.nodeID, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)
			if err != nil {
				errs = append(errs, fmt.Errorf("compute expected SRv6 uSID for EndpointSlice check: %w", err))
			} else if got := slice.Annotations[crdnames.AnnotationSID]; got != sid.String() {
				errs = append(errs, fmt.Errorf(
					"EndpointSlice %s annotation %s = %q, want %q", name, crdnames.AnnotationSID, got, sid.String()))
			}
		}
	}

	return errors.Join(errs...)
}

// cmdStatus implements the CNI spec STATUS operation — galactic-bgp talks
// to the API server (BGP CRD reads/writes), so this probes it the same way
// internal/cni's own cmdStatus does.
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
