// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/nptv6map"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/nptv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// annotationNetNS is the annotation key prefix used by the CNI plugin
// to store the netns path it was invoked with, keyed by container ID.
// This is the liveness signal GC uses — see cni.netnsAnnotationKey.
const annotationNetNS = "galactic.datum.net/netns"

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
	// EBPFVRFEntriesRemoved counts stale eBPF uSID datapath vrf_table map
	// entries removed by SweepEBPFVRFTable -- a distinct kind of resource
	// from OrphanedVRFsRemoved's kernel VRF *interfaces* above (Milestone
	// 7.3).
	EBPFVRFEntriesRemoved int
	// EBPFNPTv6EntriesRemoved counts stale eBPF uSID datapath nptv6_table
	// map entries removed by SweepEBPFNPTv6Table.
	EBPFNPTv6EntriesRemoved int
	Errors                  int
}

// vrfNameRegex matches the deterministic VRF interface name pattern used by
// Galactic. The template is "G%09sV" where %09s is the base62 VPC — the
// kernel VRF is shared by every attachment on this VPC on this node, so
// unlike the host/guest veth templates it carries no VPCAttachment segment.
// Base62 includes digits and letters.
var vrfNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})V$`)

// legacyVRFNameRegex matches the VRF interface name Galactic generated before
// the VRF became per-VPC: the template was "G%09s%03sV", carrying the same
// VPCAttachment segment the host/guest veth names still do (14 chars). A node
// upgraded in place keeps whatever VRFs it created under the old template, and
// those interfaces hold a routing table ID and its routes for as long as they
// survive — so collection has to recognise them, map them to the same VPC the
// current name would yield, and reclaim them once nothing references that VPC.
//
// This is deliberately a collection-only concern: nothing creates these names
// any more, and the removal path must NOT resolve one back through
// intf.GenerateInterfaceNameVRF (see vpcFromVRFName and RemoveOrphanedVRFs).
var legacyVRFNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})[A-Za-z0-9]{3}V$`)

// routerNamesForNode returns the names of every BGPRouter in the namespace
// whose TargetRef points at nodeName. BGPAdvertisement/BGPVRFInstance CRDs
// are namespace-scoped, not node-scoped — a namespace can hold CRDs created
// by routers on other nodes (e.g. the default and rr roles both
// watch the same namespace in the containerlab lab), and this node's local
// kernel/filesystem state (VRFs, /var/run/netns) can only ever confirm or
// deny liveness for containers that actually ran here. Callers must use this
// to skip CRDs belonging to other nodes entirely, rather than risk deleting
// another node's live resources because they look orphaned from here.
func routerNamesForNode(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (map[string]struct{}, error) {
	routers, err := routersForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{}, len(routers))
	for name := range routers {
		names[name] = struct{}{}
	}
	return names, nil
}

// routersForNode is routerNamesForNode's fuller sibling: it keeps the full
// BGPRouter object (keyed by name) rather than just membership, for
// callers that need more than the name -- SweepEBPFVRFTable (Milestone
// 7.3) needs each router's Spec.SRv6Locator to derive the eBPF uSID Block
// its BGPVRFInstances resolve into.
func routersForNode(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (map[string]bgpv1alpha1.BGPRouter, error) {
	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := k8s.List(ctx, routerList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPRouters: %w", err)
	}

	routers := make(map[string]bgpv1alpha1.BGPRouter)
	for _, r := range routerList.Items {
		if r.Spec.TargetRef.Name == nodeName {
			routers[r.Name] = r
		}
	}
	return routers, nil
}

// vpcFromName extracts the VPC segment from a "vpc-suffix" CRD name —
// BGPAdvertisement's vpc-vpcAttachment (crdnames.BGPAdvertisementName) or
// BGPVRFInstance's vpc-node (crdnames.BGPVRFInstanceName). The base62 VPC
// value itself never contains '-', so the first segment is always
// unambiguous regardless of what the suffix contains — including a node
// name that itself contains '-' (e.g. "dfw-worker-control").
func vpcFromName(name string) string {
	vpc, _, _ := strings.Cut(name, "-")
	return vpc
}

// vpcKeys returns every form a VPC may appear as in a CRD name: the value
// itself, plus its encoded form (crdnames.VPCSegment). CRD names written
// before the encoding change carry the raw base62 VPC, which is also what a
// kernel VRF name yields, so both have to join for as long as either exists.
func vpcKeys(vpc string) []string {
	encoded := crdnames.VPCSegment(vpc)
	if encoded == vpc {
		return []string{vpc}
	}
	return []string{vpc, encoded}
}

// addVPC records every key form of vpc in set.
func addVPC(set map[string]struct{}, vpc string) {
	for _, key := range vpcKeys(vpc) {
		set[key] = struct{}{}
	}
}

// vpcInSet reports whether any key form of vpc is present in set.
func vpcInSet(set map[string]struct{}, vpc string) bool {
	for _, key := range vpcKeys(vpc) {
		if _, ok := set[key]; ok {
			return true
		}
	}
	return false
}

// CollectOrphanedCRDs scans BGPAdvertisement and BGPVRFInstance CRDs owned by
// nodeName's BGPRouter(s) in the given namespace and returns those whose
// associated container(s)/attachment(s) no longer exist on this node.
//
// A CRD is considered orphaned when:
//   - It is a BGPAdvertisement targeting one of nodeName's BGPRouters, with
//     at least one netns annotation, and NONE of the recorded paths exist
//     under /var/run/netns. A vpc/vpcAttachment is shared across every pod
//     that has ever attached to it on this node (pod churn adds a new
//     annotation entry without removing old ones — see cmdDel in
//     internal/cni/ops_del.go), so the object is only orphaned once every
//     container that ever referenced it is gone, not just one.
//   - It is a BGPVRFInstance (named vpc-node — crdnames.BGPVRFInstanceName —
//     shared by every attachment on this VPC on this node, unlike the 1:1
//     BGPAdvertisement) whose VPC has no surviving BGPAdvertisement: every
//     BGPAdvertisement whose name's vpc segment matches is either orphaned
//     or absent entirely. A BGPAdvertisement this pass could not determine
//     the liveness of (no netns annotations at all) counts as surviving,
//     not orphaned — GC must never guess a shared VRF is safe to reclaim.
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
	// vpcSurvives records every VPC (attachments owned by this node's
	// router(s) only) with at least one BGPAdvertisement that is live, or
	// whose liveness could not be determined — the shared BGPVRFInstance for
	// that VPC must not be touched while any of these remain.
	vpcSurvives := make(map[string]struct{})

	for _, adv := range advList.Items {
		if _, ownedByThisNode := routerNames[adv.Spec.RouterRef.Name]; !ownedByThisNode {
			// Belongs to a router on another node — not ours to judge.
			continue
		}
		vpc := vpcFromName(adv.Name)

		netnsPaths := collectNetNSPaths(&adv)
		if len(netnsPaths) == 0 {
			// No netns annotations — skip (might be legacy or manually
			// created). We cannot determine if it is orphaned, so its VPC
			// must be treated as surviving.
			addVPC(vpcSurvives, vpc)
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
			addVPC(vpcSurvives, vpc)
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
	}

	// A BGPVRFInstance is orphaned only once every attachment on its VPC —
	// not just one — is gone, since it's shared by all of them. This counts
	// across every BGPAdvertisement for the VPC rather than aliasing 1:1 off
	// a single BGPAdvertisement's name, the way the two used to share an
	// identical vpc-vpcattachment name before BGPVRFInstance moved to
	// vpc-node naming.
	vrfList := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, vrfList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPVRFInstances: %w", err)
	}
	for _, inst := range vrfList.Items {
		if inst.Spec.RouterRef == nil {
			continue
		}
		if _, ownedByThisNode := routerNames[inst.Spec.RouterRef.Name]; !ownedByThisNode {
			continue
		}
		if vpcInSet(vpcSurvives, vpcFromName(inst.Name)) {
			continue
		}
		orphaned = append(orphaned, OrphanedCRD{
			Name:      inst.Name,
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

// activeVPCsFromEndpointSlices returns every VPC named by an EndpointSlice
// carrying crdnames.LabelTenantID, cluster-wide — the same label
// internal/ingresssidecar's own controller watches (hasTenantLabel in
// internal/ingresssidecar/controller.go) to decide it needs a local VRF for
// that VPC, entirely independent of any BGPAdvertisement/BGPVRFInstance CRD.
//
// SweepEBPFVRFTable already exempts that sidecar's own eBPF vrf_table
// entries by their reserved uformat.BlockMax block (see that function's own
// doc comment: "confirmed live in us-central-1-staging-lab, where vrf_table
// sat permanently empty while ifindex_vrf_table... held the same entries").
// This is the same exemption at the kernel-VRF-interface layer instead,
// needed because CollectOrphanedVRFs runs inside galactic-router
// (cmd/galactic-router), which — deliberately, per SweepEBPFVRFTable's own
// doc comment on why that sweep runs inside galactic-cni instead — has
// neither the /sys/fs/bpf hostPath mount nor CAP_BPF to read vrf_table
// itself. Found live: without this, ensureEgressDatapath's own VRF for a
// real tenant VPC (created for the sidecar's own outbound routing, sharing
// that VPC's identifier with — but never advertised by — any real CNI
// attachment) gets reaped as orphaned on this sweep's very next tick,
// stranding EnsureRoute with "no VRF interface found" on every subsequent
// reconcile.
//
// Deliberately not scoped to this node, unlike the BGPAdvertisement check
// above: an EndpointSlice carries no node affinity to filter on, so the
// conservative direction is to err toward not reaping — a VPC claimed by
// some other node's ingress sidecar is not this function's call to make,
// the same way an unrelated node's BGPAdvertisement already isn't allowed
// to vouch for a *different* node's VRF, just inverted (there, cross-node
// claims are excluded to avoid a false "still alive"; here, they're
// included to avoid a false "orphaned").
func activeVPCsFromEndpointSlices(ctx context.Context, k8s client.Client) (map[string]struct{}, error) {
	sliceList := &discoveryv1.EndpointSliceList{}
	if err := k8s.List(ctx, sliceList, client.HasLabels{crdnames.LabelTenantID}); err != nil {
		return nil, fmt.Errorf("list tenant EndpointSlices: %w", err)
	}

	vpcs := make(map[string]struct{}, len(sliceList.Items))
	for _, slice := range sliceList.Items {
		vpc, _, ok := crdnames.ParseTenantIdentifier(slice.Labels[crdnames.LabelTenantID])
		if !ok {
			continue
		}
		addVPC(vpcs, vpc)
	}
	return vpcs, nil
}

// CollectOrphanedVRFs scans all VRF interfaces on this node and returns the
// names of VRFs whose VPC has no surviving BGPAdvertisement CRD owned by
// nodeName's BGPRouter(s) in the given namespace, and no ingress-sidecar
// EndpointSlice claiming it either (see activeVPCsFromEndpointSlices).
//
// A VRF is considered orphaned when:
//   - Its interface name matches the Galactic VRF naming pattern — either the
//     current per-VPC name or the legacy pre-rename name that carried a
//     VPCAttachment segment, both of which resolve to the same VPC (see
//     vpcFromVRFName). A node upgraded in place still carries the latter, and
//     they must be reclaimed too rather than stranding a routing table ID and
//     its routes forever.
//   - No BGPAdvertisement owned by this node (name's vpc segment matches,
//     RouterRef pointing at one of nodeName's BGPRouters) exists for its
//     VPC. The VRF is shared by every attachment on this VPC on this node
//     (crdnames.BGPVRFInstanceName), so any one surviving BGPAdvertisement
//     for the VPC — regardless of which vpcAttachment it names — keeps it
//     alive, not just a single exact-name match. Other nodes sharing this
//     namespace may coincidentally reuse the same VPC for their own,
//     unrelated attachment — only this node's own BGPAdvertisements can
//     vouch for a local VRF.
//   - No EndpointSlice claims the VPC either, per
//     activeVPCsFromEndpointSlices's own doc comment — internal/ingresssidecar
//     creates and owns its own VRF for a VPC entirely independent of any
//     BGPAdvertisement, and this sweep has no other way to see that claim.
func CollectOrphanedVRFs(ctx context.Context, k8s client.Client, namespace, nodeName string) ([]string, error) {
	vrfs, err := vrf.ListVRFLinks()
	if err != nil {
		return nil, fmt.Errorf("list VRF links: %w", err)
	}

	routerNames, err := routerNamesForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		return nil, err
	}

	// Build the set of VPCs with at least one active BGPAdvertisement owned
	// by this node.
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, advList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}

	activeVPCs := make(map[string]struct{}, len(advList.Items))
	for _, adv := range advList.Items {
		if _, ownedByThisNode := routerNames[adv.Spec.RouterRef.Name]; !ownedByThisNode {
			continue
		}
		addVPC(activeVPCs, vpcFromName(adv.Name))
	}

	sidecarVPCs, err := activeVPCsFromEndpointSlices(ctx, k8s)
	if err != nil {
		return nil, err
	}
	for vpc := range sidecarVPCs {
		addVPC(activeVPCs, vpc)
	}

	var orphaned []string
	for _, v := range vrfs {
		vpc, ok := vpcFromVRFName(v.Name)
		if !ok {
			// Not a Galactic VRF — skip.
			continue
		}

		if !vpcInSet(activeVPCs, vpc) {
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
		// We need the vpc to call vrf.Delete. Parse the name back to get it —
		// deliberately with parseVRFName, not vpcFromVRFName: vrf.Delete
		// rebuilds the current "G%09sV" interface name from the VPC, so a
		// legacy "G%09s%03sV" interface resolved that way would be looked up
		// under a name that does not exist and silently reported as removed.
		vpc, ok := parseVRFName(name)
		if !ok {
			// Not a current-shape name — this is where a legacy VRF collected
			// by vpcFromVRFName lands. Delete the interface we actually
			// observed, by name, but flush its routing table first — the
			// same order vrf.Delete uses — so this path leaves behind the
			// same state as the one above rather than leaning on Add's own
			// flush-on-reuse to clean up a table this path skipped (#343).
			link, err := netlink.LinkByName(name)
			if err != nil {
				// Already gone — not an error.
				continue
			}
			if vrfLink, ok := link.(*netlink.Vrf); ok {
				if flushErr := vrf.FlushTable(vrfLink.Table); flushErr != nil {
					slog.Error("GC: failed to flush routing table for orphaned VRF by name",
						"name", name, "table", vrfLink.Table, "err", flushErr)
					result.Errors++
					continue
				}
			} else {
				// CollectOrphanedVRFs only ever collects names from
				// vrf.ListVRFLinks, which filters to *netlink.Vrf — this
				// branch means the interface changed kind between that scan
				// and this delete. Nothing to flush; fall through and
				// remove whatever is there now.
				slog.Warn("GC: orphaned VRF name no longer resolves to a VRF interface, skipping flush",
					"name", name)
			}
			if delErr := netlink.LinkDel(link); delErr != nil {
				slog.Error("GC: failed to delete orphaned VRF by name",
					"name", name, "err", delErr)
				result.Errors++
				continue
			}
			slog.Info("GC: removed orphaned VRF by name", "name", name)
			result.OrphanedVRFsRemoved++
			continue
		}

		if err := vrf.Delete(vpc); err != nil {
			slog.Error("GC: failed to delete orphaned VRF",
				"name", name, "vpc", vpc, "err", err)
			result.Errors++
			continue
		}
		slog.Info("GC: removed orphaned VRF", "name", name, "vpc", vpc)
		result.OrphanedVRFsRemoved++
	}

	return result
}

// SweepEBPFVRFTable removes eBPF uSID datapath vrf_table map entries whose
// (Block, Argument) key no longer corresponds to a live BGPVRFInstance CRD
// owned by nodeName's BGPRouter(s) (design plan §5.3; Milestone 7.3).
// Unlike RunGC's CRD/kernel-VRF sweep above, this deliberately does NOT run
// from galactic-router's existing GC controller (internal/controller/
// gc_controller.go): the pinned vrf_table map only exists inside
// galactic-cni's "run" container, which has the /sys/fs/bpf hostPath mount
// and CAP_BPF (Milestone 3.1) that galactic-router's own DaemonSet does
// not and, for this alone, should not need. internal/installer.Run calls
// this directly on its own ticker instead -- see that package's doc
// comment for the full reasoning. The RBAC galactic-cni's ServiceAccount
// already has (get/list bgprouters; get/list/...  bgpvrfinstances, see
// config/galactic-cni/rbac.yaml) is exactly what this function needs, so no
// permission change was required to place it there.
//
// A pin directory this process can't confirm exists -- either genuinely
// absent (the "run" container's eBPF datapath hasn't finished loading yet)
// or inaccessible (e.g. /sys/fs/bpf's own restrictive mode denying a
// non-root stat, which the production "run" container never hits since it
// runs as root, design plan §9) -- is treated as "nothing to do this
// tick," not an error; any stat failure here means there's no pinned
// datapath this process can reach right now, and it isn't this function's
// job to diagnose why.
func SweepEBPFVRFTable(ctx context.Context, k8s client.Client, namespace, nodeName, pinDir string) CleanupResult {
	result := CleanupResult{}

	if _, statErr := os.Stat(pinDir); statErr != nil {
		return result
	}

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		slog.Error("GC: failed to open pinned eBPF vrf_table for sweep", "pinDir", pinDir, "err", err)
		result.Errors++
		return result
	}
	defer func() { _ = closer.Close() }()

	// Capture the cutoff *before* listing BGPVRFInstance CRDs below --
	// VRFTable.Generation's own doc comment and doc.go's
	// "plugin-binary-vs-run-container race" section explain why the
	// ordering matters: a Register landing between this line and the List
	// call below must survive this sweep.
	cutoff := reg.VRF.Generation()

	routers, err := routersForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		slog.Error("GC: failed to list BGPRouters for eBPF vrf_table sweep", "err", err)
		result.Errors++
		return result
	}
	if len(routers) == 0 {
		// A node with any live eBPF-registered attachment at all necessarily
		// has a BGPRouter targeting it -- registerEBPFDatapath requires one
		// to run at all (internal/cnibgp/bgp.go). Finding none here is
		// indistinguishable from a transient listing/cache hiccup or the
		// router having just been renamed/recreated, so it must not be
		// treated the same as "genuinely zero live attachments": doing so
		// would fold every entry into the below-cutoff, absent-from-live
		// case and wipe the entire vrf_table -- every pod on this node --
		// on what may just be one bad tick. Skip this sweep instead; the
		// next tick tries again once router listing is reliable again.
		slog.Warn("GC: no BGPRouter found for node during eBPF vrf_table sweep, skipping reconcile this tick",
			"nodeName", nodeName)
		return result
	}

	vrfInstList := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, vrfInstList, client.InNamespace(namespace)); err != nil {
		slog.Error("GC: failed to list BGPVRFInstances for eBPF vrf_table sweep", "err", err)
		result.Errors++
		return result
	}

	live := make(map[usidmap.VRFKey]struct{}, len(vrfInstList.Items))
	for _, inst := range vrfInstList.Items {
		if inst.Spec.RouterRef == nil {
			continue
		}
		router, ok := routers[inst.Spec.RouterRef.Name]
		if !ok {
			continue // not one of this node's routers
		}
		if router.Spec.SRv6Locator == "" {
			continue // this router has no eBPF-relevant locator configured
		}
		prefix, err := netip.ParsePrefix(router.Spec.SRv6Locator)
		if err != nil {
			slog.Warn("GC: skipping BGPVRFInstance with unparseable router locator during eBPF sweep",
				"vrfInstance", inst.Name, "router", router.Name, "locator", router.Spec.SRv6Locator, "err", err)
			continue
		}
		block, err := uformat.Block(prefix.Addr())
		if err != nil {
			slog.Warn("GC: skipping BGPVRFInstance with invalid router locator during eBPF sweep",
				"vrfInstance", inst.Name, "router", router.Name, "locator", router.Spec.SRv6Locator, "err", err)
			continue
		}
		// inst.Spec.VRFID is the real, allocated Argument value directly
		// (Milestone 6.1) -- no derivation needed. Guard the int32->uint16
		// narrowing explicitly rather than trusting an external CRD value
		// (a boundary this GC sweep does not otherwise validate) to
		// already be in range.
		if inst.Spec.VRFID < int32(uformat.ArgumentMin) || inst.Spec.VRFID > int32(uformat.ArgumentMax) {
			slog.Warn("GC: skipping BGPVRFInstance with out-of-range VRFID during eBPF sweep",
				"vrfInstance", inst.Name, "vrfID", inst.Spec.VRFID)
			continue
		}
		argument := uint16(inst.Spec.VRFID)
		live[usidmap.VRFKey{Block: block, Argument: argument}] = struct{}{}
	}

	// internal/ingresssidecar registers its own vrf_table entries under
	// uformat.BlockMax -- a block deliberately reserved so it can never
	// collide with a real BGPRouter locator (see that package's
	// ingressSidecarBlock doc comment) -- and owns their entire lifecycle
	// itself (ensureEgressDatapath/removeEgressDatapath), independent of
	// any BGPVRFInstance CRD. Without this, every entry it ever registers
	// is invisible to the CRD-built live set above and gets reaped as an
	// orphan on this sweep's very next tick: confirmed live in
	// us-central-1-staging-lab, where vrf_table sat permanently empty
	// while ifindex_vrf_table (which this sweep never touches) held the
	// same entries, silently blackholing that sidecar's own outbound
	// connections to VPC backends. Preserve every entry in that block
	// unconditionally, the same way an entry with a live CRD is preserved.
	existing, err := reg.VRF.List()
	if err != nil {
		slog.Error("GC: failed to list eBPF vrf_table for sweep", "err", err)
		result.Errors++
		return result
	}
	for _, e := range existing {
		if e.Block == uformat.BlockMax {
			live[e.VRFKey] = struct{}{}
		}
	}

	removed, err := reg.VRF.Reconcile(live, cutoff)
	for _, e := range removed {
		slog.Info("GC: removed stale eBPF vrf_table entry", "block", e.Block, "argument", e.Argument)
	}
	result.EBPFVRFEntriesRemoved = len(removed)
	if err != nil {
		slog.Error("GC: errors while reconciling eBPF vrf_table", "err", err)
		result.Errors++
	}

	return result
}

// SweepEBPFNPTv6Table registers/reconciles the eBPF uSID datapath's
// nptv6_table map (internal/plumbing/ebpf/nptv6map) against every live
// BGPVRFInstance CRD's own Spec.NPTv6 field, owned by nodeName's
// BGPRouter(s).
//
// Unlike SweepEBPFVRFTable (whose vrf_table registration happens at CNI ADD
// time via internal/cnibgp's registerEBPFDatapath, and this function only
// reconciles stale entries away), this function is nptv6_table's *only*
// writer: nothing registers an NPTv6 mapping at CNI ADD time at all (the CNI
// ADD path has no per-attachment notion of NPTv6 -- it is a per-VRF, not
// per-attachment, config field). Every currently-live mapping is therefore
// (re-)registered here, on the same tick that also reconciles stale ones
// away -- see internal/plumbing/ebpf/nptv6map/doc.go's "no Generation/
// monotonic-clock kernel field" section for why a single, sequential writer
// (this function, never raced by a second writer) makes that safe without
// vrf_table's own kernel-persisted generation field.
//
// Runs from the same place as SweepEBPFVRFTable
// (internal/installer.Run's ebpfGCSweepTicker), for the identical reason:
// the pinned nptv6_table map only exists inside that container -- see
// SweepEBPFVRFTable's own doc comment for the full reasoning (galactic-router's
// own DaemonSet has no /sys/fs/bpf mount or CAP_BPF, so the BGPVRFInstance
// controller-runtime reconciler cannot open this map directly regardless of
// how it validates the CRD's own NPTv6 field).
func SweepEBPFNPTv6Table(ctx context.Context, k8s client.Client, namespace, nodeName, pinDir string) CleanupResult {
	result := CleanupResult{}

	if _, statErr := os.Stat(pinDir); statErr != nil {
		return result
	}

	table, closer, err := nptv6map.OpenPinned(pinDir)
	if err != nil {
		slog.Error("GC: failed to open pinned eBPF nptv6_table for sweep", "pinDir", pinDir, "err", err)
		result.Errors++
		return result
	}
	defer func() { _ = closer.Close() }()

	// Capture the cutoff *before* listing BGPVRFInstance CRDs and
	// (re-)registering their live mappings below -- every entry this same
	// call registers therefore stamps a generation >= cutoff, and Reconcile
	// keeps it regardless (it is also always in live directly). See
	// nptv6map/doc.go for why this table has no second writer to race.
	cutoff := table.Generation()

	routers, err := routersForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		slog.Error("GC: failed to list BGPRouters for eBPF nptv6_table sweep", "err", err)
		result.Errors++
		return result
	}
	if len(routers) == 0 {
		// See SweepEBPFVRFTable's own identical guard for why zero routers
		// found is treated as "skip this tick," not "genuinely nothing is
		// live."
		slog.Warn("GC: no BGPRouter found for node during eBPF nptv6_table sweep, skipping reconcile this tick",
			"nodeName", nodeName)
		return result
	}

	vrfInstList := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, vrfInstList, client.InNamespace(namespace)); err != nil {
		slog.Error("GC: failed to list BGPVRFInstances for eBPF nptv6_table sweep", "err", err)
		result.Errors++
		return result
	}

	live := make(map[nptv6map.NPTv6Key]struct{}, len(vrfInstList.Items))
	for _, inst := range vrfInstList.Items {
		if inst.Spec.RouterRef == nil || inst.Spec.NPTv6 == nil {
			continue
		}
		router, ok := routers[inst.Spec.RouterRef.Name]
		if !ok {
			continue // not one of this node's routers
		}
		if router.Spec.SRv6Locator == "" {
			continue // this router has no eBPF-relevant locator configured
		}
		prefix, err := netip.ParsePrefix(router.Spec.SRv6Locator)
		if err != nil {
			slog.Warn("GC: skipping BGPVRFInstance with unparseable router locator during eBPF nptv6_table sweep",
				"vrfInstance", inst.Name, "router", router.Name, "locator", router.Spec.SRv6Locator, "err", err)
			continue
		}
		block, err := uformat.Block(prefix.Addr())
		if err != nil {
			slog.Warn("GC: skipping BGPVRFInstance with invalid router locator during eBPF nptv6_table sweep",
				"vrfInstance", inst.Name, "router", router.Name, "locator", router.Spec.SRv6Locator, "err", err)
			continue
		}
		if inst.Spec.VRFID < int32(uformat.ArgumentMin) || inst.Spec.VRFID > int32(uformat.ArgumentMax) {
			slog.Warn("GC: skipping BGPVRFInstance with out-of-range VRFID during eBPF nptv6_table sweep",
				"vrfInstance", inst.Name, "vrfID", inst.Spec.VRFID)
			continue
		}
		argument := uint16(inst.Spec.VRFID)

		mapping, err := buildNPTv6Mapping(inst.Spec.NPTv6)
		if err != nil {
			slog.Warn("GC: skipping BGPVRFInstance with invalid NPTv6 mapping during eBPF nptv6_table sweep",
				"vrfInstance", inst.Name, "err", err)
			continue
		}
		if err := table.Register(block, argument, mapping); err != nil {
			slog.Error("GC: failed to register eBPF nptv6_table entry", "vrfInstance", inst.Name, "err", err)
			result.Errors++
			continue
		}
		live[nptv6map.NPTv6Key{Block: block, Argument: argument}] = struct{}{}
	}

	removed, err := table.Reconcile(live, cutoff)
	for _, e := range removed {
		slog.Info("GC: removed stale eBPF nptv6_table entry", "block", e.Block, "argument", e.Argument)
	}
	result.EBPFNPTv6EntriesRemoved = len(removed)
	if err != nil {
		slog.Error("GC: errors while reconciling eBPF nptv6_table", "err", err)
		result.Errors++
	}

	return result
}

// buildNPTv6Mapping converts a BGPVRFInstanceSpec's NPTv6 field (validated
// only as parseable CIDRs here; nptv6.Mapping.Adjustment/Register perform
// the fuller RFC 6296 range validation) into an internal/plumbing/nptv6.Mapping.
func buildNPTv6Mapping(spec *bgpv1alpha1.NPTv6Spec) (nptv6.Mapping, error) {
	_, ula, err := net.ParseCIDR(spec.ULAPrefix)
	if err != nil {
		return nptv6.Mapping{}, fmt.Errorf("parse ulaPrefix %q: %w", spec.ULAPrefix, err)
	}
	_, pub, err := net.ParseCIDR(spec.PublicPrefix)
	if err != nil {
		return nptv6.Mapping{}, fmt.Errorf("parse publicPrefix %q: %w", spec.PublicPrefix, err)
	}
	return nptv6.Mapping{ULAPrefix: ula, PublicPrefix: pub}, nil
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

	// Phase 2: Remove orphaned VRF interfaces.
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
func parseVRFName(name string) (vpc string, ok bool) {
	// The template is "G%09sV" — 1 + 9 + 1 = 11 characters. But base62
	// encoding can produce mixed alphanumeric, so we need a regex approach.
	matches := vrfNameRegex.FindStringSubmatch(name)
	if matches == nil {
		return "", false
	}
	// Strip leading zeros to reverse the %09s padding. BGP CRD names use the
	// raw base62 value (e.g. "10-dfw-worker" not "000000010-dfw-worker").
	return strings.TrimLeft(matches[1], "0"), true
}

// vpcFromVRFName resolves the VPC that a kernel VRF interface belongs to,
// accepting both the current per-VPC name (parseVRFName) and the legacy
// pre-rename name (legacyVRFNameRegex). Both shapes carry the same base62 VPC
// in the same leading position, so a legacy VRF resolves to exactly the VPC
// its BGPAdvertisements are named after and is judged against them like any
// other.
//
// Only CollectOrphanedVRFs uses this. RemoveOrphanedVRFs deliberately keeps
// using parseVRFName: it deletes a resolved VPC via vrf.Delete, which rebuilds
// the *current* interface name from that VPC and so would silently no-op
// against a legacy interface. Leaving a legacy name unresolved there routes it
// into the by-name fallback, which deletes the interface actually observed.
func vpcFromVRFName(name string) (vpc string, ok bool) {
	if vpc, ok := parseVRFName(name); ok {
		return vpc, true
	}
	matches := legacyVRFNameRegex.FindStringSubmatch(name)
	if matches == nil {
		return "", false
	}
	// Strip the %09s padding exactly as parseVRFName does, so the VPC matches
	// CRD naming.
	return strings.TrimLeft(matches[1], "0"), true
}
