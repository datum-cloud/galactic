// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec: always return success.
	// Missing resources are not errors. We collect all cleanup errors,
	// log them, and return nil so the CNI runtime does not retry.
	var errs []error

	// Parse config — if we can't parse it we still return success but
	// won't be able to clean up any resources.
	pluginConf, parseErr := parseConf(args.StdinData)
	if parseErr != nil {
		slog.Error("DEL: failed to parse CNI config, skipping cleanup", "err", parseErr,
			"containerID", args.ContainerID)
		// Cannot determine what to clean up without a valid config.
		result := &type100.Result{}
		_ = types.PrintResult(result, cniVersion100)
		return nil
	}

	namespace := pluginConf.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}

	k8s, k8sErr := newK8sClient()
	if k8sErr != nil {
		slog.Error("DEL: failed to create k8s client, skipping IPAM deallocation and CRD cleanup", "err", k8sErr,
			"containerID", args.ContainerID)
		errs = append(errs, fmt.Errorf("create k8s client: %w", k8sErr))
	}

	// Deallocate IPAM subnet before any other cleanup (veth-only).
	if k8s != nil && pluginConf.InterfaceType == interfaceTypeVeth && (pluginConf.IPAM.Type != "" || enableLocalIPAM) {
		deallocateIPAM(args, pluginConf, k8s)
	}

	// Best-effort cleanup of all resources.
	if k8s != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
		defer cancel()

		// Delete the BGPAdvertisement first to withdraw prefixes, then the VRF instance.
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
				Namespace: namespace,
			},
		}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(adv), adv); client.IgnoreNotFound(err) != nil {
			slog.Error("DEL: failed to get BGPAdvertisement", "err", err,
				"name", adv.Name, "namespace", namespace)
			errs = append(errs, fmt.Errorf("get BGPAdvertisement %s: %w", adv.Name, err))
		} else if err := k8s.Delete(ctx, adv); client.IgnoreNotFound(err) != nil {
			slog.Error("DEL: failed to delete BGPAdvertisement", "err", err,
				"name", adv.Name, "namespace", namespace)
			errs = append(errs, fmt.Errorf("delete BGPAdvertisement %s: %w", adv.Name, err))
		}

		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpVRFInstanceName(pluginConf.VPC, pluginConf.VPCAttachment),
				Namespace: namespace,
			},
		}
		if err := k8s.Delete(ctx, vrfInst); client.IgnoreNotFound(err) != nil {
			slog.Error("DEL: failed to delete BGPVRFInstance", "err", err,
				"name", vrfInst.Name, "namespace", namespace)
			errs = append(errs, fmt.Errorf("delete BGPVRFInstance %s: %w", vrfInst.Name, err))
		}
	}

	dev := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)

	// host-device DEL is veth-only; tap has no guest interface to remove.
	if pluginConf.InterfaceType == interfaceTypeVeth {
		if err := hostDevice("DEL", args, pluginConf); err != nil {
			slog.Error("DEL: failed to delete host-device", "err", err,
				"containerID", args.ContainerID)
			errs = append(errs, fmt.Errorf("host-device DEL: %w", err))
		}
	}

	for _, termination := range pluginConf.Terminations {
		if err := route.Delete(
			pluginConf.VPC, pluginConf.VPCAttachment,
			termination.Network, termination.Via, dev,
		); err != nil {
			slog.Error("DEL: failed to delete route", "err", err,
				"network", termination.Network, "via", termination.Via)
			errs = append(errs, fmt.Errorf("delete route %s: %w", termination.Network, err))
		}
	}

	switch pluginConf.InterfaceType {
	case interfaceTypeVeth:
		if pluginConf.SRv6Locator != "" {
			if vpcHex, hexErr := intf.Base62ToHex(pluginConf.VPC); hexErr == nil {
				if vpcAttHex, attErr := intf.Base62ToHex(pluginConf.VPCAttachment); attErr == nil {
					if sid, sidErr := intf.EncodeSRv6Endpoint(pluginConf.SRv6Locator, vpcHex, vpcAttHex); sidErr == nil {
						if err := srv6.RouteIngressDel(sid); err != nil {
							slog.Error("DEL: failed to delete SRv6 ingress route", "err", err,
								"sid", sid)
							errs = append(errs, fmt.Errorf("delete SRv6 ingress route: %w", err))
						}
					}
				}
			}
		}
		if err := veth.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
			slog.Error("DEL: failed to delete veth", "err", err,
				"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			errs = append(errs, fmt.Errorf("delete veth: %w", err))
		}
	case interfaceTypeTap:
		if err := tap.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
			slog.Error("DEL: failed to delete tap", "err", err,
				"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			errs = append(errs, fmt.Errorf("delete tap: %w", err))
		}
	}

	if err := vrf.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		slog.Error("DEL: failed to delete VRF", "err", err,
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		errs = append(errs, fmt.Errorf("delete VRF: %w", err))
	}

	result := &type100.Result{}
	_ = types.PrintResult(result, cniVersion100)

	if len(errs) > 0 {
		slog.Error("DEL: completed with cleanup errors",
			"count", len(errs), "containerID", args.ContainerID)
	}

	return nil
}
