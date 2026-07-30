// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// containerIDStatusLen is the exact length VPCAttachmentStatus.ContainerID
// requires (go.datum.net/cloud's CEL/length validation: MinLength=MaxLength=46).
// Real container IDs in this codebase are 64 hex characters (see
// annotationContainerIDLen and cni_test.go's fullContainerID), so the value
// is truncated to fit — the same accommodation already made for annotation
// keys elsewhere in this package, not a new pattern.
const containerIDStatusLen = 46

// vpcAttachmentName returns the deterministic name for a VPCAttachment CR.
// Mirrors bgpVRFInstanceName/bgpAdvertisementName (bgp.go): the (vpc,
// vpcAttachment) pair is a reliable 1:1 key, so NAD and VPCAttachment end up
// with the same name without either looking the other up.
func vpcAttachmentName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}

// parsePodName extracts the K8S_POD_NAME value from the CNI_ARGS environment
// variable string passed as args.Args by Multus. Mirrors parsePodNamespace
// (nad.go). Returns an empty string when the value is not present.
func parsePodName(cniArgs string) string {
	for _, part := range strings.Split(cniArgs, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok && key == "K8S_POD_NAME" {
			return value
		}
	}
	return ""
}

// vpcAttachmentAddresses converts ipamResult's allocated address(es) into the
// CIDR-notation strings VPCAttachmentSpec.Interface.Addresses requires.
// Mirrors ipamAdvertisementPrefixes (bgp.go:300-317): the IPv4 address needs
// an explicit /32 appended, the IPv6 subnet is already CIDR-shaped.
func vpcAttachmentAddresses(ipamResult *ipamResult) []cloudv1alpha1.IPAddress {
	if ipamResult == nil {
		return nil
	}
	var addrs []cloudv1alpha1.IPAddress
	if ipamResult.ipv6Subnet != nil {
		addrs = append(addrs, cloudv1alpha1.IPAddress(ipamResult.ipv6Subnet.String()))
	}
	if ipamResult.ipv4Address != nil {
		addrs = append(addrs, cloudv1alpha1.IPAddress(ipamResult.ipv4Address.String()+"/32"))
	}
	return addrs
}

// vpcAttachmentPodSubnet returns the value for VPCAttachmentStatus.PodSubnet,
// derived from the same ipamResult used for Spec.Interface.Addresses above —
// kept consistent by construction, not by convention.
func vpcAttachmentPodSubnet(ipamResult *ipamResult) string {
	if ipamResult == nil || ipamResult.ipv6Subnet == nil {
		return ""
	}
	return ipamResult.ipv6Subnet.String()
}

// truncateContainerID shortens id to containerIDStatusLen characters. See
// containerIDStatusLen's doc comment for why this truncation is necessary.
func truncateContainerID(id string) string {
	if len(id) > containerIDStatusLen {
		return id[:containerIDStatusLen]
	}
	return id
}

// applyVPCAttachment creates (or updates) the VPCAttachment CR for this
// attachment and populates its Status with the attach-time facts galactic-cni
// has just gathered — Node, ContainerID, PodName, interface names, and
// PodSubnet. This mirrors how publishBGPStateK8s already creates
// BGPVRFInstance/BGPAdvertisement via controllerutil.CreateOrUpdate: the
// caller is expected to run this inside retryK8sOps so transient k8s errors
// retry, and to track success via tracker.vpcAttachmentCreated so a later ADD
// failure rolls this back the same way vrfInstanceCreated/advCreated do.
//
// Skipped (logged at Debug, not an error) when:
//   - pluginConf.VPCName is empty — VPCAttachment provisioning is additive;
//     CNI configs not built by galactic-webhook (e.g. existing e2e fixtures)
//     keep working exactly as before.
//   - ipamResult has no usable addresses — VPCAttachmentSpec.Interface.Addresses
//     (MinItems=1) and VPCAttachmentStatus.PodSubnet (MinLength=1, no
//     omitempty) are both required by the CRD schema; an attachment with no
//     IPAM allocation (e.g. a tap workload managing its own addressing —
//     see ipamAdvertisementPrefixes's doc comment) cannot satisfy either, so
//     there is nothing valid to create.
func applyVPCAttachment(
	ctx context.Context, k8s client.Client, args *skel.CmdArgs, pluginConf *PluginConf,
	podNamespace, nodeName, hostName, guestName string, ipamResult *ipamResult,
	tracker *resourceTracker,
) error {
	if pluginConf.VPCName == "" {
		slog.Debug("ADD: skipping VPCAttachment (no vpc_name in CNI config)",
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		return nil
	}
	if podNamespace == "" {
		return errors.New("K8S_POD_NAMESPACE not present in CNI_ARGS: cannot create VPCAttachment")
	}

	addresses := vpcAttachmentAddresses(ipamResult)
	podSubnet := vpcAttachmentPodSubnet(ipamResult)
	if len(addresses) == 0 || podSubnet == "" {
		slog.Debug("ADD: skipping VPCAttachment (no IPAM allocation for this attachment)",
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		return nil
	}

	vrfName := intf.GenerateInterfaceNameVRF(pluginConf.VPC, pluginConf.VPCAttachment)
	name := vpcAttachmentName(pluginConf.VPC, pluginConf.VPCAttachment)

	attachment := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: podNamespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, k8s, attachment, func() error {
		attachment.Spec = cloudv1alpha1.VPCAttachmentSpec{
			VPC: cloudv1alpha1.VPCRef{Name: pluginConf.VPCName},
			Interface: cloudv1alpha1.VPCAttachmentInterface{
				Name:      args.IfName,
				Addresses: addresses,
			},
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply VPCAttachment: %w", err)
	}
	tracker.vpcAttachmentCreated = true
	slog.Debug("ADD: VPCAttachment applied", "name", name, "namespace", podNamespace)

	attachment.Status = cloudv1alpha1.VPCAttachmentStatus{
		VPC:            pluginConf.VPC,
		VPCAttachment:  pluginConf.VPCAttachment,
		Node:           nodeName,
		ContainerID:    truncateContainerID(args.ContainerID),
		PodName:        parsePodName(args.Args),
		HostInterface:  hostName,
		VRFInterface:   vrfName,
		GuestInterface: guestName,
		PodSubnet:      podSubnet,
	}
	if err := k8s.Status().Update(ctx, attachment); err != nil {
		return fmt.Errorf("update VPCAttachment status: %w", err)
	}
	slog.Debug("ADD: VPCAttachment status updated", "name", name, "namespace", podNamespace,
		"node", nodeName, "containerID", attachment.Status.ContainerID, "podName", attachment.Status.PodName)
	return nil
}

// deleteVPCAttachment rolls back the VPCAttachment CR created during a
// failed ADD. Called from resourceTracker.cleanup(), mirroring how
// BGPAdvertisement/BGPVRFInstance are rolled back there.
func deleteVPCAttachment(ctx context.Context, k8s client.Client, vpc, vpcAttachment, namespace string) error {
	attachment := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vpcAttachmentName(vpc, vpcAttachment),
			Namespace: namespace,
		},
	}
	return client.IgnoreNotFound(k8s.Delete(ctx, attachment))
}
