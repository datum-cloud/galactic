// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	// annotationAllocatedSubnet is the annotation key prefix used by the
	// CNI plugin to store allocated subnets keyed by container ID.
	annotationAllocatedSubnet = "galactic.datum.net/allocated-subnet"

	// annotationNetNS is the annotation key prefix used by the CNI plugin
	// to store the netns path it was invoked with, keyed by container ID.
	// This is the liveness signal GC uses — see cni.netnsAnnotationKey.
	annotationNetNS = "galactic.datum.net/netns"
)

// OrphanedCRD represents a BGP CRD that appears to be orphaned because its
// associated container is no longer present on the node.
type OrphanedCRD struct {
	Name        string
	Namespace   string
	Kind        string // "BGPAdvertisement" or "BGPVRFInstance"
	ContainerID string // truncated container ID prefix from annotation
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

// CollectOrphanedCRDs scans all BGPAdvertisement and BGPVRFInstance CRDs in
// the given namespace and returns those whose associated container no longer
// exists on this node.
//
// A CRD is considered orphaned when:
//   - It is a BGPAdvertisement with at least one netns annotation, and NONE
//     of the recorded paths exist under /var/run/netns. A vpc/vpcAttachment
//     is shared across every pod that has ever attached to it on this node
//     (pod churn adds a new annotation entry without removing old ones — see
//     cmdDel in internal/cni/ops_del.go), so the object is only orphaned
//     once every container that ever referenced it is gone, not just one.
//   - It is a BGPVRFInstance whose name matches a BGPAdvertisement that
//     is itself orphaned (same vpc-vpcattachment name).
func CollectOrphanedCRDs(ctx context.Context, k8s client.Client, namespace string) ([]OrphanedCRD, error) {
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, advList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}

	var orphaned []OrphanedCRD
	orphanedAdvNames := make(map[string]struct{})

	for _, adv := range advList.Items {
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
			Kind:        "BGPAdvertisement",
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
			Kind:      "BGPVRFInstance",
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
		case "BGPAdvertisement":
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

		case "BGPVRFInstance":
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
		}
	}

	return result
}

// CollectOrphanedVRFs scans all VRF interfaces on this node and returns the
// vpc/vpcAttachment pairs for VRFs whose corresponding BGPAdvertisement CRD
// no longer exists in the given namespace.
//
// A VRF is considered orphaned when:
//   - Its interface name matches the Galactic VRF naming pattern.
//   - The derived BGPAdvertisement CRD (name = vpc-vpcattachment) does not
//     exist in Kubernetes.
func CollectOrphanedVRFs(ctx context.Context, k8s client.Client, namespace string) ([]string, error) {
	vrfs, err := vrf.ListVRFLinks()
	if err != nil {
		return nil, fmt.Errorf("list VRF links: %w", err)
	}

	// Build a set of active BGPAdvertisement names for this namespace.
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, advList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}

	activeAdvNames := make(map[string]struct{}, len(advList.Items))
	for _, adv := range advList.Items {
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
func RunGC(ctx context.Context, k8s client.Client, namespace string) CleanupResult {
	var result CleanupResult

	// Phase 1: Remove orphaned BGP CRDs.
	orphans, err := CollectOrphanedCRDs(ctx, k8s, namespace)
	if err != nil {
		slog.Error("GC: failed to collect orphaned CRDs", "err", err)
		result.Errors++
	} else if len(orphans) > 0 {
		slog.Info("GC: found orphaned CRDs", "count", len(orphans))
		crResult := RemoveOrphanedCRDs(ctx, k8s, orphans)
		result.OrphanedCRDsRemoved += crResult.OrphanedCRDsRemoved
		result.Errors += crResult.Errors
	}

	// Phase 2: Remove orphaned VRF interfaces.
	orphanedVRFs, err := CollectOrphanedVRFs(ctx, k8s, namespace)
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
