// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// annotationNetNS is the annotation key prefix used by the CNI plugin
// to store the netns path it was invoked with, keyed by container ID.
// This is the liveness signal GC uses — see cni.netnsAnnotationKey.
const annotationNetNS = "galactic.datum.net/netns"

// OrphanedCRD.Kind values.
const (
	kindBGPAdvertisement            = "BGPAdvertisement"
	kindBGPVRFInstance              = "BGPVRFInstance"
	kindVPCAttachment               = "VPCAttachment"
	kindNetworkAttachmentDefinition = "NetworkAttachmentDefinition"
)

// labelVPC marks a NetworkAttachmentDefinition as created by galactic-webhook
// for a specific VPC. Only NADs carrying this label are candidates for the
// reference-count orphan check below — NADs created any other way (manually,
// or by an external operator) are never touched by this GC pass. Must match
// the label galactic-webhook sets when it creates a NAD.
const labelVPC = "galactic.datumapis.com/vpc"

// networksAnnotation is the Multus annotation a pod uses to reference
// NetworkAttachmentDefinitions by name (and, optionally, namespace).
const networksAnnotation = "k8s.v1.cni.cncf.io/networks"

// nadGVK is the GroupVersionKind for NetworkAttachmentDefinition. Duplicated
// from internal/cni's nadGVK rather than imported — internal/gc and
// internal/cni are sibling packages with no existing dependency between them.
var nadGVK = schema.GroupVersionKind{
	Group:   "k8s.cni.cncf.io",
	Version: "v1",
	Kind:    kindNetworkAttachmentDefinition,
}

// networkSelectionElement mirrors the fields of Multus's NetworkSelectionElement
// this package needs to read from a pod's networks annotation. Only Name and
// Namespace are needed to check whether a pod references a given NAD.
type networkSelectionElement struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// OrphanedCRD represents a CRD (or NAD) that appears to be orphaned because
// its associated container or pod is no longer present.
type OrphanedCRD struct {
	Name        string
	Namespace   string
	Kind        string // kindBGPAdvertisement, kindBGPVRFInstance, kindVPCAttachment, or kindNetworkAttachmentDefinition
	ContainerID string // truncated container ID prefix from annotation; empty for VPCAttachment/NAD
}

// CleanupResult tracks the outcome of a GC pass.
type CleanupResult struct {
	OrphanedCRDsRemoved int
	OrphanedVRFsRemoved int
	Errors              int
}

// vrfNameRegex matches the deterministic VRF interface name pattern used by
// Galactic. The template is "G%09s%03sV" where %09s is the base62 VPC and
// %03s is the base62 VPCAttachment. Base62 includes digits and letters.
var vrfNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})([A-Za-z0-9]{3})V$`)

// routerNamesForNode returns the names of every BGPRouter in the namespace
// whose TargetRef points at nodeName. BGPAdvertisement/BGPVRFInstance CRDs
// are namespace-scoped, not node-scoped — a namespace can hold CRDs created
// by routers on other nodes (e.g. the tenant and tenant-control roles both
// watch the same namespace in the containerlab lab), and this node's local
// kernel/filesystem state (VRFs, /var/run/netns) can only ever confirm or
// deny liveness for containers that actually ran here. Callers must use this
// to skip CRDs belonging to other nodes entirely, rather than risk deleting
// another node's live resources because they look orphaned from here.
func routerNamesForNode(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (map[string]struct{}, error) {
	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := k8s.List(ctx, routerList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPRouters: %w", err)
	}

	names := make(map[string]struct{})
	for _, r := range routerList.Items {
		if r.Spec.TargetRef.Name == nodeName {
			names[r.Name] = struct{}{}
		}
	}
	return names, nil
}

// CollectOrphanedCRDs scans BGPAdvertisement and BGPVRFInstance CRDs owned by
// nodeName's BGPRouter(s) in the given namespace and returns those whose
// associated container no longer exists on this node.
//
// A CRD is considered orphaned when:
//   - It is a BGPAdvertisement targeting one of nodeName's BGPRouters, with
//     at least one netns annotation, and NONE of the recorded paths exist
//     under /var/run/netns. A vpc/vpcAttachment is shared across every pod
//     that has ever attached to it on this node (pod churn adds a new
//     annotation entry without removing old ones — see cmdDel in
//     internal/cni/ops_del.go), so the object is only orphaned once every
//     container that ever referenced it is gone, not just one.
//   - It is a BGPVRFInstance whose name matches a BGPAdvertisement that
//     is itself orphaned (same vpc-vpcattachment name).
func CollectOrphanedCRDs(ctx context.Context, k8s client.Client, namespace, nodeName string) ([]OrphanedCRD, error) {
	routerNames, err := routerNamesForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		return nil, err
	}

	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, advList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}

	var orphaned []OrphanedCRD
	orphanedAdvNames := make(map[string]struct{})

	for _, adv := range advList.Items {
		if _, ownedByThisNode := routerNames[adv.Spec.RouterRef.Name]; !ownedByThisNode {
			// Belongs to a router on another node — not ours to judge.
			continue
		}

		netnsPaths := collectNetNSPaths(&adv)
		if len(netnsPaths) == 0 {
			// No netns annotations — skip (might be legacy or manually
			// created). We cannot determine if it is orphaned.
			continue
		}

		liveContainerID := ""
		for containerID, netnsPathStr := range netnsPaths {
			if NetNSExists(netnsPathStr) {
				liveContainerID = containerID
				break
			}
		}
		if liveContainerID != "" {
			// At least one container that attached to this
			// vpc/vpcAttachment is still alive — not orphaned.
			continue
		}

		// None of the recorded containers are alive. Report an arbitrary
		// one purely for logging context.
		var anyContainerID string
		for containerID := range netnsPaths {
			anyContainerID = containerID
			break
		}
		orphaned = append(orphaned, OrphanedCRD{
			Name:        adv.Name,
			Namespace:   adv.Namespace,
			Kind:        kindBGPAdvertisement,
			ContainerID: anyContainerID,
		})
		orphanedAdvNames[adv.Name] = struct{}{}
	}

	// BGPVRFInstance CRDs share the same name as their corresponding
	// BGPAdvertisement (both use vpc-vpcattachment naming). If a
	// BGPAdvertisement is orphaned, its BGPVRFInstance counterpart is
	// also orphaned.
	for name := range orphanedAdvNames {
		orphaned = append(orphaned, OrphanedCRD{
			Name:      name,
			Namespace: namespace,
			Kind:      kindBGPVRFInstance,
		})
	}

	return orphaned, nil
}

// podReferencesNAD reports whether any pod in namespace still lists nadName
// in its Multus k8s.v1.cni.cncf.io/networks annotation. Malformed annotation
// values are ignored (treated as not-referencing) rather than failing the
// whole scan — a single bad pod annotation should not block reclaiming an
// otherwise-orphaned NAD.
func podReferencesNAD(ctx context.Context, k8s client.Client, namespace, nadName string) (bool, error) {
	var pods corev1.PodList
	if err := k8s.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return false, fmt.Errorf("list pods in namespace %s: %w", namespace, err)
	}
	for _, pod := range pods.Items {
		raw, ok := pod.Annotations[networksAnnotation]
		if !ok || raw == "" {
			continue
		}
		var elements []networkSelectionElement
		if err := json.Unmarshal([]byte(raw), &elements); err != nil {
			continue
		}
		for _, e := range elements {
			if e.Name == nadName && (e.Namespace == "" || e.Namespace == namespace) {
				return true, nil
			}
		}
	}
	return false, nil
}

// CollectOrphanedNADs scans every NetworkAttachmentDefinition labeled with
// labelVPC (i.e. created by galactic-webhook, never a manually-created or
// externally-managed NAD) across all namespaces, and returns those no live
// pod in their own namespace still references via the Multus networks
// annotation.
//
// Unlike BGPAdvertisement/VPCAttachment orphan checks, this is not scoped to
// a single node: a NAD's liveness depends on whether any pod anywhere still
// points at it, not on which node ran CNI for it. Every node's GC pass runs
// this same check redundantly — acceptable (delete is idempotent, a
// not-found response from another node's earlier pass is not an error) given
// the alternative would be a separate cluster-scoped controller this plan
// does not otherwise need.
func CollectOrphanedNADs(ctx context.Context, k8s client.Client) ([]OrphanedCRD, error) {
	nadList := &unstructured.UnstructuredList{}
	nadList.SetGroupVersionKind(nadGVK)
	if err := k8s.List(ctx, nadList, client.HasLabels{labelVPC}); err != nil {
		return nil, fmt.Errorf("list NetworkAttachmentDefinitions: %w", err)
	}

	var orphaned []OrphanedCRD
	for _, nad := range nadList.Items {
		referenced, err := podReferencesNAD(ctx, k8s, nad.GetNamespace(), nad.GetName())
		if err != nil {
			slog.Error("GC: failed to check pod references for NAD", "err", err,
				"name", nad.GetName(), "namespace", nad.GetNamespace())
			continue
		}
		if referenced {
			continue
		}
		orphaned = append(orphaned, OrphanedCRD{
			Name:      nad.GetName(),
			Namespace: nad.GetNamespace(),
			Kind:      kindNetworkAttachmentDefinition,
		})
	}
	return orphaned, nil
}

// CollectOrphanedVPCAttachments scans every VPCAttachment across all
// namespaces whose Status.Node matches nodeName (this node's own attachments
// only — the same per-node scoping philosophy routerNamesForNode already
// applies to BGP CRDs) and returns those whose Status.PodName no longer
// exists.
//
// VPCAttachments with an empty Status.PodName are skipped, not treated as
// orphaned: galactic-cni populates Status in the same call that creates
// Spec (see internal/cni's applyVPCAttachment), so an empty PodName here
// means either a stale read or a partially-failed create that
// resourceTracker's inline rollback already handles — not something this GC
// pass can safely judge with the same confidence as the pod-existence check
// below.
func CollectOrphanedVPCAttachments(ctx context.Context, k8s client.Client, nodeName string) ([]OrphanedCRD, error) {
	var attachments cloudv1alpha1.VPCAttachmentList
	if err := k8s.List(ctx, &attachments); err != nil {
		return nil, fmt.Errorf("list VPCAttachments: %w", err)
	}

	var orphaned []OrphanedCRD
	for _, a := range attachments.Items {
		if a.Status.Node != nodeName {
			continue
		}
		if a.Status.PodName == "" {
			continue
		}
		var pod corev1.Pod
		err := k8s.Get(ctx, types.NamespacedName{Name: a.Status.PodName, Namespace: a.Namespace}, &pod)
		if err == nil {
			continue // pod still exists — not orphaned
		}
		if !apierrors.IsNotFound(err) {
			slog.Error("GC: failed to check pod existence for VPCAttachment", "err", err,
				"name", a.Name, "namespace", a.Namespace, "podName", a.Status.PodName)
			continue
		}
		orphaned = append(orphaned, OrphanedCRD{
			Name:      a.Name,
			Namespace: a.Namespace,
			Kind:      kindVPCAttachment,
		})
	}
	return orphaned, nil
}

// RemoveOrphanedCRDs deletes the given orphaned CRDs from Kubernetes.
// Errors are logged but do not abort the cleanup — best-effort semantics.
func RemoveOrphanedCRDs(ctx context.Context, k8s client.Client, orphans []OrphanedCRD) CleanupResult {
	result := CleanupResult{}

	for _, o := range orphans {
		switch o.Kind {
		case kindBGPAdvertisement:
			adv := &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Name:      o.Name,
					Namespace: o.Namespace,
				},
			}
			if err := k8s.Delete(ctx, adv); err != nil {
				slog.Error("GC: failed to delete orphaned BGPAdvertisement",
					"name", o.Name, "namespace", o.Namespace, "err", err)
				result.Errors++
				continue
			}
			slog.Info("GC: removed orphaned BGPAdvertisement",
				"name", o.Name, "namespace", o.Namespace, "containerID", o.ContainerID)
			result.OrphanedCRDsRemoved++

		case kindBGPVRFInstance:
			vrfInst := &bgpv1alpha1.BGPVRFInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      o.Name,
					Namespace: o.Namespace,
				},
			}
			if err := k8s.Delete(ctx, vrfInst); err != nil {
				slog.Error("GC: failed to delete orphaned BGPVRFInstance",
					"name", o.Name, "namespace", o.Namespace, "err", err)
				result.Errors++
				continue
			}
			slog.Info("GC: removed orphaned BGPVRFInstance",
				"name", o.Name, "namespace", o.Namespace)
			result.OrphanedCRDsRemoved++

		case kindVPCAttachment:
			attachment := &cloudv1alpha1.VPCAttachment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      o.Name,
					Namespace: o.Namespace,
				},
			}
			if err := k8s.Delete(ctx, attachment); err != nil {
				slog.Error("GC: failed to delete orphaned VPCAttachment",
					"name", o.Name, "namespace", o.Namespace, "err", err)
				result.Errors++
				continue
			}
			slog.Info("GC: removed orphaned VPCAttachment", "name", o.Name, "namespace", o.Namespace)
			result.OrphanedCRDsRemoved++

		case kindNetworkAttachmentDefinition:
			nad := &unstructured.Unstructured{}
			nad.SetGroupVersionKind(nadGVK)
			nad.SetName(o.Name)
			nad.SetNamespace(o.Namespace)
			if err := k8s.Delete(ctx, nad); err != nil {
				slog.Error("GC: failed to delete orphaned NetworkAttachmentDefinition",
					"name", o.Name, "namespace", o.Namespace, "err", err)
				result.Errors++
				continue
			}
			slog.Info("GC: removed orphaned NetworkAttachmentDefinition", "name", o.Name, "namespace", o.Namespace)
			result.OrphanedCRDsRemoved++
		}
	}

	return result
}

// CollectOrphanedVRFs scans all VRF interfaces on this node and returns the
// vpc/vpcAttachment pairs for VRFs whose corresponding BGPAdvertisement CRD,
// owned by nodeName's BGPRouter(s), no longer exists in the given namespace.
//
// A VRF is considered orphaned when:
//   - Its interface name matches the Galactic VRF naming pattern.
//   - No BGPAdvertisement owned by this node (name = vpc-vpcattachment,
//     RouterRef pointing at one of nodeName's BGPRouters) exists for it.
//     Other nodes sharing this namespace may coincidentally reuse the same
//     vpc-vpcattachment name for their own, unrelated attachment — only
//     this node's own BGPAdvertisements can vouch for a local VRF.
func CollectOrphanedVRFs(ctx context.Context, k8s client.Client, namespace, nodeName string) ([]string, error) {
	vrfs, err := vrf.ListVRFLinks()
	if err != nil {
		return nil, fmt.Errorf("list VRF links: %w", err)
	}

	routerNames, err := routerNamesForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		return nil, err
	}

	// Build a set of active BGPAdvertisement names owned by this node.
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, advList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}

	activeAdvNames := make(map[string]struct{}, len(advList.Items))
	for _, adv := range advList.Items {
		if _, ownedByThisNode := routerNames[adv.Spec.RouterRef.Name]; !ownedByThisNode {
			continue
		}
		activeAdvNames[adv.Name] = struct{}{}
	}

	var orphaned []string
	for _, v := range vrfs {
		vpc, vpcAtt, ok := parseVRFName(v.Name)
		if !ok {
			// Not a Galactic VRF — skip.
			continue
		}

		// Check if the corresponding BGPAdvertisement exists.
		advName := fmt.Sprintf("%s-%s", vpc, vpcAtt)
		if _, exists := activeAdvNames[advName]; !exists {
			orphaned = append(orphaned, v.Name)
		}
	}

	return orphaned, nil
}

// RemoveOrphanedVRFs deletes the given orphaned VRF interfaces from the
// kernel. Errors are logged but do not abort the cleanup — best-effort
// semantics.
func RemoveOrphanedVRFs(vrfNames []string) CleanupResult {
	result := CleanupResult{}

	for _, name := range vrfNames {
		// We need the vpc/vpcAttachment to call vrf.Delete. Parse the name
		// back to get those values.
		vpc, vpcAtt, ok := parseVRFName(name)
		if !ok {
			// Try to delete by name directly.
			link, err := netlink.LinkByName(name)
			if err != nil {
				// Already gone — not an error.
				continue
			}
			if delErr := netlink.LinkDel(link); delErr != nil {
				slog.Error("GC: failed to delete orphaned VRF (parse failed)",
					"name", name, "err", delErr)
				result.Errors++
			}
			continue
		}

		if err := vrf.Delete(vpc, vpcAtt); err != nil {
			slog.Error("GC: failed to delete orphaned VRF",
				"name", name, "vpc", vpc, "vpcAttachment", vpcAtt, "err", err)
			result.Errors++
			continue
		}
		slog.Info("GC: removed orphaned VRF",
			"name", name, "vpc", vpc, "vpcAttachment", vpcAtt)
		result.OrphanedVRFsRemoved++
	}

	return result
}

// RunGC performs a full garbage collection pass: removes orphaned BGP CRDs
// and orphaned VRF interfaces. Returns a summary of what was cleaned up.
// nodeName scopes the pass to CRDs owned by this node's BGPRouter(s) — see
// routerNamesForNode.
func RunGC(ctx context.Context, k8s client.Client, namespace, nodeName string) CleanupResult {
	var result CleanupResult

	// Phase 1: Remove orphaned BGP CRDs.
	orphans, err := CollectOrphanedCRDs(ctx, k8s, namespace, nodeName)
	if err != nil {
		slog.Error("GC: failed to collect orphaned CRDs", "err", err)
		result.Errors++
	} else if len(orphans) > 0 {
		slog.Info("GC: found orphaned CRDs", "count", len(orphans))
		crResult := RemoveOrphanedCRDs(ctx, k8s, orphans)
		result.OrphanedCRDsRemoved += crResult.OrphanedCRDsRemoved
		result.Errors += crResult.Errors
	}

	// Phase 2: Remove orphaned VPCAttachments (this node's own, per Status.Node)
	// and NetworkAttachmentDefinitions (cluster-wide reference count) — see
	// CollectOrphanedVPCAttachments/CollectOrphanedNADs for why these use
	// different scoping than Phase 1's BGP CRDs.
	vpcAttachmentOrphans, err := CollectOrphanedVPCAttachments(ctx, k8s, nodeName)
	if err != nil {
		slog.Error("GC: failed to collect orphaned VPCAttachments", "err", err)
		result.Errors++
	} else if len(vpcAttachmentOrphans) > 0 {
		slog.Info("GC: found orphaned VPCAttachments", "count", len(vpcAttachmentOrphans))
		vaResult := RemoveOrphanedCRDs(ctx, k8s, vpcAttachmentOrphans)
		result.OrphanedCRDsRemoved += vaResult.OrphanedCRDsRemoved
		result.Errors += vaResult.Errors
	}

	nadOrphans, err := CollectOrphanedNADs(ctx, k8s)
	if err != nil {
		slog.Error("GC: failed to collect orphaned NetworkAttachmentDefinitions", "err", err)
		result.Errors++
	} else if len(nadOrphans) > 0 {
		slog.Info("GC: found orphaned NetworkAttachmentDefinitions", "count", len(nadOrphans))
		nadResult := RemoveOrphanedCRDs(ctx, k8s, nadOrphans)
		result.OrphanedCRDsRemoved += nadResult.OrphanedCRDsRemoved
		result.Errors += nadResult.Errors
	}

	// Phase 3: Remove orphaned VRF interfaces.
	orphanedVRFs, err := CollectOrphanedVRFs(ctx, k8s, namespace, nodeName)
	if err != nil {
		slog.Error("GC: failed to collect orphaned VRFs", "err", err)
		result.Errors++
	} else if len(orphanedVRFs) > 0 {
		slog.Info("GC: found orphaned VRFs", "count", len(orphanedVRFs))
		vrfResult := RemoveOrphanedVRFs(orphanedVRFs)
		result.OrphanedVRFsRemoved += vrfResult.OrphanedVRFsRemoved
		result.Errors += vrfResult.Errors
	}

	if result.OrphanedCRDsRemoved > 0 || result.OrphanedVRFsRemoved > 0 {
		slog.Info("GC: cleanup complete",
			"crdsRemoved", result.OrphanedCRDsRemoved,
			"vrfsRemoved", result.OrphanedVRFsRemoved,
			"errors", result.Errors)
	}

	return result
}

// collectNetNSPaths extracts every (containerID, netnsPath) pair recorded on
// a BGPAdvertisement's netns annotations — one per container that has ever
// attached to this vpc/vpcAttachment on this node. Pod churn adds a new
// annotation entry without removing old ones (see cmdDel in
// internal/cni/ops_del.go), so an object can carry several.
func collectNetNSPaths(adv *bgpv1alpha1.BGPAdvertisement) map[string]string {
	paths := make(map[string]string)
	if adv.Annotations == nil {
		return paths
	}
	prefix := annotationNetNS + "."
	for key, value := range adv.Annotations {
		if strings.HasPrefix(key, prefix) {
			// The key format is "galactic.datum.net/netns.<containerID-prefix>"
			paths[key[len(prefix):]] = value
		}
	}
	return paths
}

// parseVRFName extracts the base62-encoded VPC and VPCAttachment from a
// Galactic VRF interface name. Returns the parsed values and whether the
// name matched the expected pattern.
//
// The interface name template ("G%09s%03sV") zero-pads the base62 components,
// but BGP CRD names use the raw (unpadded) base62 values. parseVRFName strips
// leading zeros so the returned values match the CRD naming convention.
func parseVRFName(name string) (vpc, vpcAttachment string, ok bool) {
	// The template is "G%09s%03sV" — 1 + 9 + 3 + 1 = 14 characters.
	// But base62 encoding can produce mixed alphanumeric, so we need a
	// regex approach.
	matches := vrfNameRegex.FindStringSubmatch(name)
	if matches == nil {
		return "", "", false
	}
	// Strip leading zeros to reverse the %09s/%03s padding. BGP CRD names
	// use the raw base62 values (e.g. "10-10" not "000000010-010").
	return strings.TrimLeft(matches[1], "0"), strings.TrimLeft(matches[2], "0"), true
}
