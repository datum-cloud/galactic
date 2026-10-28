// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/hostconf"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/podslice"
)

// podNodeNameField is the pod field the repair lists this node's pods by.
const podNodeNameField = "spec.nodeName"

var nadGVK = schema.GroupVersionKind{Group: "k8s.cni.cncf.io", Version: "v1", Kind: "NetworkAttachmentDefinition"}

// endpointSliceRepairResult counts one repair pass.
type endpointSliceRepairResult struct {
	// Restored is how many missing EndpointSlices the pass recreated.
	Restored int
	// Skipped is how many attached pods the pass could not rebuild a slice
	// for from what the API holds, each logged with its reason.
	Skipped int
}

// bgpAttachment is a galactic-bgp stanza's identifiers.
type bgpAttachment struct {
	vpc, vpcAttachment, namespace string
}

// repairEndpointSlicesOnTick starts one repairEndpointSlices pass off Run's
// goroutine, unless a pass already holds sem, in which case that pass covers
// this tick. A pass gets one tick interval, so a hung API call cannot hold sem
// and stop every later pass.
func repairEndpointSlicesOnTick(ctx context.Context, sem chan struct{}, st ebpfDatapathState) {
	if st.k8sClient == nil {
		return
	}
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			passCtx, cancel := context.WithTimeout(ctx, ebpfGCSweepInterval)
			defer cancel()
			result, err := repairEndpointSlices(passCtx, st.k8sClient, st.namespace, st.nodeName)
			st.endpointSliceRepair.Pass(result.Restored, err != nil)
			attrs := []any{"restored", result.Restored, "skipped", result.Skipped}
			switch {
			case err != nil:
				slog.Warn("EndpointSlice repair failed; pods may still lack their EndpointSlice",
					append(attrs, "err", err)...)
			case result.Restored > 0 || result.Skipped > 0:
				slog.Info("EndpointSlice repair pass complete", attrs...)
			default:
				slog.Debug("EndpointSlice repair found nothing missing")
			}
		}()
	default:
	}
}

// repairEndpointSlices recreates the per-pod EndpointSlice of every Running
// pod on nodeName that has a galactic attachment with an IPv6 address but no
// slice. Only CNI ADD otherwise writes the slice, so one removed while its
// pod lives would stay missing, and the pod unreachable through HTTP ingress,
// until the pod is recreated.
//
// A pod's attachments come from its Multus network-status annotation: each
// entry names the NetworkAttachmentDefinition whose galactic-bgp stanza gives
// the VPC, the attachment and the namespace of its BGP objects, and carries
// the addresses the attachment received. The slice's SID comes from this
// node's BGPRouter and the VPC's BGPVRFInstance, as on ADD. A pod with more
// than one galactic attachment gets the last one with an IPv6 address, the
// one whose ADD runs last and so last writes the shared, per-pod slice.
//
// It only creates; a slice that exists is left alone. The recreated slice
// carries no sandbox annotation, so no DEL removes it; its owner reference
// does once the pod is deleted, and the pod's next ADD takes it over. A pod
// whose attachment cannot be resolved is skipped and logged, and the pass
// moves on: the next one retries it.
func repairEndpointSlices(
	ctx context.Context, k8s client.Client, defaultNamespace, nodeName string,
) (endpointSliceRepairResult, error) {
	var result endpointSliceRepairResult

	pods := &corev1.PodList{}
	if err := k8s.List(ctx, pods, client.MatchingFields{podNodeNameField: nodeName}); err != nil {
		return result, fmt.Errorf("list pods on node %s: %w", nodeName, err)
	}

	nads := map[client.ObjectKey]*bgpAttachment{}
	identities := nodeIdentities{}
	var errs []error
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		statuses, err := networkStatuses(pod)
		if err != nil {
			slog.Warn("EndpointSlice repair: skipping pod with an unreadable network-status annotation",
				"podRef", client.ObjectKeyFromObject(pod), "err", err)
			result.Skipped++
			continue
		}

		if !hasSecondaryIPv6(statuses) {
			continue
		}

		// The slice is read before the attachment is resolved, so a pod that
		// has its slice costs one read and is never skipped for a definition
		// that has since changed.
		key := client.ObjectKey{Name: crdnames.EndpointSliceName(pod.Name), Namespace: pod.Namespace}
		if err := k8s.Get(ctx, key, &discoveryv1.EndpointSlice{}); err == nil {
			continue
		} else if !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("get EndpointSlice %s: %w", key, err))
			continue
		}

		att, addr, err := lastGalacticIPv6Attachment(ctx, k8s, nads, statuses, defaultNamespace)
		if err != nil {
			slog.Warn("EndpointSlice repair: skipping pod whose attachment cannot be resolved",
				"podRef", client.ObjectKeyFromObject(pod), "err", err)
			result.Skipped++
			continue
		}
		if att == nil {
			continue
		}

		node, err := identities.get(ctx, k8s, att.namespace, nodeName)
		if err != nil {
			slog.Warn("EndpointSlice repair: skipping pod with no SRv6 identity to publish",
				"podRef", client.ObjectKeyFromObject(pod), "err", err)
			result.Skipped++
			continue
		}
		sid, err := attachmentSID(ctx, k8s, node, att, nodeName)
		if err != nil {
			slog.Warn("EndpointSlice repair: skipping pod whose SRv6 SID cannot be computed",
				"podRef", client.ObjectKeyFromObject(pod), "err", err)
			result.Skipped++
			continue
		}

		created, err := podslice.Restore(ctx, k8s, pod, podslice.Endpoint{
			VPC: att.vpc, VPCAttachment: att.vpcAttachment, Addr: addr, SID: sid,
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if created {
			slog.Info("EndpointSlice repair: recreated missing EndpointSlice",
				"podRef", client.ObjectKeyFromObject(pod), "vpc", att.vpc, "vpcAttachment", att.vpcAttachment)
			result.Restored++
		}
	}
	return result, errors.Join(errs...)
}

// networkStatuses parses pod's Multus network-status annotation. A pod
// without one has no secondary attachments to repair.
func networkStatuses(pod *corev1.Pod) ([]nadv1.NetworkStatus, error) {
	raw, ok := pod.Annotations[nadv1.NetworkStatusAnnot]
	if !ok {
		return nil, nil
	}
	var statuses []nadv1.NetworkStatus
	if err := json.Unmarshal([]byte(raw), &statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

// hasSecondaryIPv6 reports whether any non-default entry of statuses carries
// an IPv6 address, the precondition for any galactic attachment to need a
// slice.
func hasSecondaryIPv6(statuses []nadv1.NetworkStatus) bool {
	for _, st := range statuses {
		if !st.Default && firstIPv6(st.IPs) != nil {
			return true
		}
	}
	return false
}

// lastGalacticIPv6Attachment returns the last entry of statuses that names a
// definition chaining galactic-bgp and carries an IPv6 address, with that
// address. It returns nil when there is none. nads caches each definition's
// stanza for the pass, nil for one that chains no galactic-bgp.
func lastGalacticIPv6Attachment(
	ctx context.Context, k8s client.Client, nads map[client.ObjectKey]*bgpAttachment,
	statuses []nadv1.NetworkStatus, defaultNamespace string,
) (*bgpAttachment, net.IP, error) {
	for i := len(statuses) - 1; i >= 0; i-- {
		st := statuses[i]
		if st.Default {
			continue
		}
		addr := firstIPv6(st.IPs)
		if addr == nil {
			continue
		}
		nsName, name, ok := strings.Cut(st.Name, "/")
		if !ok {
			continue
		}
		key := client.ObjectKey{Namespace: nsName, Name: name}
		att, cached := nads[key]
		if !cached {
			var err error
			att, err = galacticBGPStanza(ctx, k8s, key, defaultNamespace)
			if err != nil {
				return nil, nil, err
			}
			nads[key] = att
		}
		if att != nil {
			return att, addr, nil
		}
	}
	return nil, nil, nil
}

// firstIPv6 returns the first global IPv6 address in ips, which Multus
// records with or without a prefix length. Link-local addresses are skipped,
// as they are never the address IPAM assigned.
func firstIPv6(ips []string) net.IP {
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			p, perr := netip.ParsePrefix(s)
			if perr != nil {
				continue
			}
			addr = p.Addr()
		}
		if addr.Is6() && !addr.Is4In6() && !addr.IsLinkLocalUnicast() {
			return net.IP(addr.AsSlice())
		}
	}
	return nil
}

// galacticBGPStanza reads the galactic-bgp stanza of the definition at key,
// or nil when the definition chains none or no longer exists. A stanza naming
// no namespace uses defaultNamespace, as galactic-bgp does.
func galacticBGPStanza(
	ctx context.Context, k8s client.Client, key client.ObjectKey, defaultNamespace string,
) (*bgpAttachment, error) {
	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	if err := k8s.Get(ctx, key, nad); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get NetworkAttachmentDefinition %s: %w", key, err)
	}
	configStr, _, err := unstructured.NestedString(nad.Object, "spec", "config")
	if err != nil {
		return nil, fmt.Errorf("NetworkAttachmentDefinition %s spec.config: %w", key, err)
	}
	var conflist struct {
		Plugins []struct {
			Type          string `json:"type"`
			VPC           string `json:"vpc"`
			VPCAttachment string `json:"vpcattachment"`
			Namespace     string `json:"namespace"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(configStr), &conflist); err != nil {
		return nil, fmt.Errorf("parse NetworkAttachmentDefinition %s config: %w", key, err)
	}
	for _, p := range conflist.Plugins {
		if p.Type != hostconf.BGPPluginType {
			continue
		}
		if p.VPC == "" || p.VPCAttachment == "" {
			return nil, fmt.Errorf("NetworkAttachmentDefinition %s: %s stanza names no vpc or vpcattachment",
				key, hostconf.BGPPluginType)
		}
		ns := p.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		return &bgpAttachment{vpc: p.VPC, vpcAttachment: p.VPCAttachment, namespace: ns}, nil
	}
	return nil, nil
}

// nodeIdentities caches this node's SRv6 identity per BGP namespace for one
// pass, including the error looking it up.
type nodeIdentities map[string]nodeIdentity

type nodeIdentity struct {
	node attachreg.Node
	err  error
}

// get returns nodeName's SRv6 identity in namespace. No BGPRouter targeting
// the node is an error, as it fails CNI ADD.
func (c nodeIdentities) get(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (attachreg.Node, error) {
	if id, ok := c[namespace]; ok {
		return id.node, id.err
	}
	node, _, found, err := gc.NodeSRv6Identity(ctx, k8s, namespace, nodeName)
	if err == nil && !found {
		err = fmt.Errorf("no BGPRouter targets node %s in namespace %s", nodeName, namespace)
	}
	c[namespace] = nodeIdentity{node: node, err: err}
	return node, err
}

// attachmentSID computes the SRv6 uSID routing to att's VRF on nodeName, as
// CNI ADD does, or the zero Addr when node has no SRv6 identity, for which
// ADD publishes no SID either.
func attachmentSID(
	ctx context.Context, k8s client.Client, node attachreg.Node, att *bgpAttachment, nodeName string,
) (netip.Addr, error) {
	if !node.Configured() {
		return netip.Addr{}, nil
	}
	inst := &bgpv1alpha1.BGPVRFInstance{}
	key := client.ObjectKey{Name: crdnames.BGPVRFInstanceName(att.vpc, nodeName), Namespace: att.namespace}
	if err := k8s.Get(ctx, key, inst); err != nil {
		return netip.Addr{}, fmt.Errorf("get BGPVRFInstance %s: %w", key, err)
	}
	return srv6.ComputeSID(node.Locator, node.NodeID, inst.Spec.VRFID, bgpv1alpha1.SRv6FunctionEndDT46)
}
