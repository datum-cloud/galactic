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

// annotationNetNS is the annotation key prefix the CNI plugin uses to record
// the netns path it was invoked with, keyed by container ID. It is the
// liveness signal GC reads.
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
	// EBPFVRFEntriesRemoved counts stale eBPF vrf_table map entries removed by
	// SweepEBPFVRFTable, a different resource from the kernel VRF interfaces
	// OrphanedVRFsRemoved counts.
	EBPFVRFEntriesRemoved int
	// EBPFVRFEntriesRegistered counts vrf_table entries SweepEBPFVRFTable
	// re-registered for a live BGPVRFInstance CRD that had no matching row.
	EBPFVRFEntriesRegistered int
	// EBPFNPTv6EntriesRemoved counts stale eBPF uSID datapath nptv6_table
	// map entries removed by SweepEBPFNPTv6Table.
	EBPFNPTv6EntriesRemoved int
	Errors                  int
}

// vrfNameRegex matches the deterministic VRF interface name Galactic
// generates, "G%09sV", where the padded field is the base62 VPC. The kernel
// VRF is shared by every attachment on this VPC on this node, so unlike the
// host and guest veth templates it carries no VPCAttachment segment.
var vrfNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})V$`)

// legacyVRFNameRegex matches the VRF interface name generated before the VRF
// became per-VPC: "G%09s%03sV", carrying the VPCAttachment segment the veth
// names still do. A node upgraded in place keeps whatever VRFs it created
// under that template, and each holds a routing table ID and its routes for as
// long as it survives, so collection has to recognise them, map them to the
// same VPC the current name would yield, and reclaim them.
//
// Collection only. Nothing creates these names, and the removal path must not
// resolve one back through intf.GenerateInterfaceNameVRF; see vpcFromVRFName
// and RemoveOrphanedVRFs.
var legacyVRFNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})[A-Za-z0-9]{3}V$`)

// routerNamesForNode returns the names of every BGPRouter in namespace whose
// TargetRef points at nodeName.
//
// BGPAdvertisement and BGPVRFInstance CRDs are namespace-scoped, not
// node-scoped, so a namespace can hold CRDs created by routers on other nodes,
// while this node's kernel and filesystem state can only confirm liveness for
// containers that ran here. Callers must use this to skip other nodes' CRDs
// rather than delete live resources that merely look orphaned from here.
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

// routersForNode is routerNamesForNode's fuller sibling, keeping each
// BGPRouter object keyed by name rather than just its membership.
// SweepEBPFVRFTable needs each router's Spec.SRv6Locator to derive the uSID
// Block its BGPVRFInstances resolve into.
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

// vpcFromName extracts the VPC segment from a "vpc-suffix" CRD name, either a
// BGPAdvertisement's vpc-vpcAttachment or a BGPVRFInstance's vpc-node. The
// base62 VPC never contains '-', so the first segment is unambiguous whatever
// the suffix holds, including a node name that itself contains '-'.
func vpcFromName(name string) string {
	vpc, _, _ := strings.Cut(name, "-")
	return vpc
}

// vpcKeys returns every form a VPC may appear as in a CRD name: the value
// itself, plus its encoded form. CRD names written before the encoding change
// carry the raw base62 VPC, which is also what a kernel VRF name yields, so
// both must match for as long as either exists.
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
// nodeName's BGPRouters in namespace and returns those whose containers or
// attachments no longer exist on this node.
//
// A CRD is orphaned when:
//   - It is a BGPAdvertisement with at least one netns annotation, and none of
//     the recorded paths exist under /var/run/netns. An attachment is shared
//     by every pod that has ever attached to it on this node, and pod churn
//     adds annotations without removing old ones, so the object is orphaned
//     only once every container that referenced it is gone.
//   - It is a BGPVRFInstance, shared by every attachment on this VPC on this
//     node, whose VPC has no surviving BGPAdvertisement. A BGPAdvertisement
//     whose liveness this pass cannot determine, having no netns annotations,
//     counts as surviving: GC must never guess that a shared VRF is safe to
//     reclaim.
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
	// vpcSurvives records every VPC, among attachments owned by this node's
	// routers, with at least one BGPAdvertisement that is live or whose
	// liveness could not be determined. That VPC's shared BGPVRFInstance must
	// not be touched while any of these remain.
	vpcSurvives := make(map[string]struct{})

	for _, adv := range advList.Items {
		if _, ownedByThisNode := routerNames[adv.Spec.RouterRef.Name]; !ownedByThisNode {
			// Belongs to a router on another node — not ours to judge.
			continue
		}
		vpc := vpcFromName(adv.Name)

		netnsPaths := collectNetNSPaths(&adv)
		if len(netnsPaths) == 0 {
			// No netns annotations, so liveness is unknown. Its VPC counts as
			// surviving.
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

	// A BGPVRFInstance is shared by every attachment on its VPC, so it is
	// orphaned only once all of them are gone. This counts across every
	// BGPAdvertisement for the VPC rather than aliasing off a single one's
	// name.
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
// carrying crdnames.LabelTenantID, cluster-wide. It is the same label the
// ingress sidecar watches to decide it needs a local VRF for that VPC,
// independent of any BGPAdvertisement or BGPVRFInstance CRD.
//
// Without this, a VRF the sidecar created for its own outbound routing, which
// no CNI attachment ever advertises, is reaped as orphaned on the next sweep
// and every later reconcile fails to find a VRF interface. SweepEBPFVRFTable
// makes the equivalent exemption one layer down, at the eBPF map, by reserving
// a block; this is the kernel-interface layer, which needs its own because
// CollectOrphanedVRFs runs inside galactic-router, which has neither the
// /sys/fs/bpf mount nor CAP_BPF to read that map.
//
// Not scoped to this node, unlike the BGPAdvertisement check above: an
// EndpointSlice carries no node affinity to filter on, so the conservative
// direction is to err away from reaping. A cross-node BGPAdvertisement is
// excluded to avoid a false "still alive"; a cross-node EndpointSlice is
// included to avoid a false "orphaned".
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

// CollectOrphanedVRFs scans the VRF interfaces on this node and returns those
// whose VPC has no surviving BGPAdvertisement owned by nodeName's BGPRouters in
// namespace, and no ingress-sidecar EndpointSlice claiming it.
//
// A VRF is orphaned when:
//   - Its name matches the current per-VPC pattern or the legacy pattern that
//     carried a VPCAttachment segment. Both resolve to the same VPC. A node
//     upgraded in place still carries legacy names, and leaving them behind
//     strands a routing table ID and its routes forever.
//   - No BGPAdvertisement owned by this node exists for its VPC. The VRF is
//     shared by every attachment on this VPC on this node, so any one
//     surviving BGPAdvertisement for the VPC keeps it alive, whichever
//     attachment it names. Only this node's own advertisements can vouch for
//     a local VRF, since another node may reuse the same VPC for an unrelated
//     attachment.
//   - No EndpointSlice claims the VPC, per activeVPCsFromEndpointSlices.
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

// RemoveOrphanedVRFs deletes the named orphaned VRF interfaces from the
// kernel. Errors are logged rather than returned; cleanup is best effort and
// continues past a failure.
func RemoveOrphanedVRFs(vrfNames []string) CleanupResult {
	result := CleanupResult{}

	for _, name := range vrfNames {
		// Parse the name back to the VPC that vrf.Delete needs. Deliberately
		// parseVRFName, not vpcFromVRFName: vrf.Delete rebuilds the current
		// "G%09sV" name from the VPC, so a legacy interface resolved that way
		// would be looked up under a name that does not exist and silently
		// reported as removed.
		vpc, ok := parseVRFName(name)
		if !ok {
			// Not a current-shape name, so this is where a legacy VRF lands.
			// Delete the interface actually observed, by name, flushing its
			// routing table first in the same order vrf.Delete uses, so this
			// path leaves the same state behind rather than leaning on Add's
			// flush-on-reuse to clean up a table it skipped.
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
				// Names are only ever collected from vrf.ListVRFLinks, which
				// filters to VRF links, so this means the interface changed
				// kind between that scan and this delete. Nothing to flush.
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

// SweepEBPFVRFTable removes eBPF vrf_table entries whose (Block, Argument) key
// no longer matches a live BGPVRFInstance CRD owned by nodeName's BGPRouters,
// and re-registers entries a live CRD expects but the map lacks. pinDir is the
// bpffs directory holding the pinned map.
//
// It runs from internal/installer.Run's ticker rather than galactic-router's GC
// controller because the pinned map exists only inside galactic-cni's run
// container, which has the /sys/fs/bpf hostPath mount and CAP_BPF that
// galactic-router does not need and should not have. The RBAC galactic-cni
// already holds covers everything this reads.
//
// A pin directory this process cannot confirm exists, whether genuinely absent
// because the datapath has not finished loading or merely inaccessible, means
// there is no reachable datapath this tick. That is treated as nothing to do,
// not an error.
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

	// Capture the cutoff before listing CRDs below, so a Register landing
	// between here and the List survives this sweep.
	cutoff := reg.VRF.Generation()

	routers, err := routersForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		slog.Error("GC: failed to list BGPRouters for eBPF vrf_table sweep", "err", err)
		result.Errors++
		return result
	}
	if len(routers) == 0 {
		// A node with any live eBPF-registered attachment necessarily has a
		// BGPRouter targeting it, since registerEBPFDatapath requires one.
		// Finding none is indistinguishable from a transient listing hiccup or
		// a router just renamed, so it must not read as "genuinely nothing is
		// live": that would fold every entry into the stale case and wipe the
		// whole vrf_table, and every pod on this node with it, on one bad
		// tick. Skip and retry next tick instead.
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
	// liveCRDNames tracks the BGPVRFInstance name each key came from. The
	// repair step below needs the name back to re-derive vrfTableID and
	// egressKind, while Reconcile needs only the key, so this stays separate
	// rather than widening live's value type.
	liveCRDNames := make(map[usidmap.VRFKey]string, len(vrfInstList.Items))
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
		// Spec.VRFID is the allocated Argument value directly. Guard the
		// int32 to uint16 narrowing explicitly rather than trust an external
		// CRD value this sweep does not otherwise validate.
		if inst.Spec.VRFID < int32(uformat.ArgumentMin) || inst.Spec.VRFID > int32(uformat.ArgumentMax) {
			slog.Warn("GC: skipping BGPVRFInstance with out-of-range VRFID during eBPF sweep",
				"vrfInstance", inst.Name, "vrfID", inst.Spec.VRFID)
			continue
		}
		key := usidmap.VRFKey{Block: block, Argument: uint16(inst.Spec.VRFID)}
		live[key] = struct{}{}
		liveCRDNames[key] = inst.Name
	}

	// The ingress sidecar registers its own vrf_table entries under a reserved
	// block that can never collide with a real BGPRouter locator, and owns
	// their whole lifecycle independent of any BGPVRFInstance CRD. Without
	// this exemption they are invisible to the CRD-built live set and reaped
	// on the next tick, leaving vrf_table empty for those entries while
	// ifindex_vrf_table, which this sweep never touches, still holds them, and
	// silently blackholing the sidecar's outbound connections. Preserve every
	// entry in that block unconditionally.
	existing, err := reg.VRF.List()
	if err != nil {
		slog.Error("GC: failed to list eBPF vrf_table for sweep", "err", err)
		result.Errors++
		return result
	}
	existingKeys := make(map[usidmap.VRFKey]struct{}, len(existing))
	for _, e := range existing {
		existingKeys[e.VRFKey] = struct{}{}
		if e.Block == uformat.BlockMax {
			live[e.VRFKey] = struct{}{}
		}
	}

	// Repair entries a live BGPVRFInstance expects but vrf_table lacks. An
	// incompatible-schema reload wipes every pinned map, and nothing
	// repopulates a pre-existing attachment: registerEBPFDatapath runs once,
	// at CNI ADD, and is never re-invoked for an attachment that already
	// succeeded. Reconcile above only deletes, so this is vrf_table's only
	// self-healing path.
	for key, instName := range liveCRDNames {
		if _, ok := existingKeys[key]; ok {
			continue // already present -- Reconcile above is what handles this one
		}
		vrfTableID, egressKind, ok, err := resolveVRFKernelState(nodeName, instName)
		if err != nil {
			slog.Error("GC: failed to resolve kernel VRF state while repairing eBPF vrf_table entry",
				"vrfInstance", instName, "block", key.Block, "argument", key.Argument, "err", err)
			result.Errors++
			continue
		}
		if !ok {
			// No matching kernel VRF interface right now, because teardown is
			// in flight or the CNI ADD that creates it has not run. Nothing
			// to repopulate from this tick.
			continue
		}
		if err := reg.VRF.Register(key.Block, key.Argument, vrfTableID, egressKind); err != nil {
			slog.Error("GC: failed to repair missing eBPF vrf_table entry",
				"vrfInstance", instName, "block", key.Block, "argument", key.Argument, "err", err)
			result.Errors++
			continue
		}
		slog.Info("GC: repaired missing eBPF vrf_table entry",
			"vrfInstance", instName, "block", key.Block, "argument", key.Argument,
			"vrfTableID", vrfTableID, "egressKind", egressKind)
		result.EBPFVRFEntriesRegistered++
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

// listVRFLinksFn and listAllLinksFn indirect the netlink calls
// resolveVRFKernelState makes, so tests can substitute fabricated links
// needing no real VRF interface or CAP_NET_ADMIN.
var (
	listVRFLinksFn = vrf.ListVRFLinks
	listAllLinksFn = netlink.LinkList
)

// resolveVRFKernelState recovers the Linux VRF routing table ID and egress
// kind that a live BGPVRFInstance named instName should register in vrf_table,
// by matching it against a kernel VRF interface that currently exists.
// SweepEBPFVRFTable uses it to repair a missing entry.
//
// instName carries neither value, and BGPVRFInstance's Spec has no field for
// either, so this works backwards: it lists every kernel VRF interface, an
// ordinary kernel object unaffected by an eBPF map wipe, and checks whether
// re-deriving its CRD name reproduces instName. Both the current and legacy
// CRD name shapes are accepted.
//
// ok is false, not an error, when no matching interface exists, the ordinary
// case for a BGPVRFInstance whose attachment is already torn down: there is
// nothing to repopulate an entry from, and Reconcile is what eventually
// removes the CRD.
//
// The egress kind is read off whichever interface is enslaved to the matched
// VRF. A tuntap link yields EgressKindTap and anything else EgressKindVeth,
// the same distinction the CNI ADD path makes from its config, read back from
// the kernel because this call site has no config. A VRF with nothing enslaved
// yet falls back to EgressKindVeth, the common case and vrf_table's zero
// value.
func resolveVRFKernelState(nodeName, instName string) (vrfTableID uint32, egressKind uint32, ok bool, err error) {
	links, err := listVRFLinksFn()
	if err != nil {
		return 0, 0, false, fmt.Errorf("list kernel VRF interfaces: %w", err)
	}

	var match *netlink.Vrf
	for _, link := range links {
		vpc, vpcOK := parseVRFName(link.Name)
		if !vpcOK {
			continue
		}
		for _, key := range vpcKeys(vpc) {
			if key+"-"+nodeName == instName {
				match = link
				break
			}
		}
		if match != nil {
			break
		}
	}
	if match == nil {
		return 0, 0, false, nil
	}

	kind := usidmap.EgressKindVeth
	allLinks, err := listAllLinksFn()
	if err != nil {
		return 0, 0, false, fmt.Errorf("list kernel interfaces: %w", err)
	}
	for _, l := range allLinks {
		if l.Attrs().MasterIndex != match.Attrs().Index {
			continue
		}
		if l.Type() == "tuntap" {
			kind = usidmap.EgressKindTap
		}
		break
	}

	return match.Table, kind, true, nil
}

// SweepEBPFNPTv6Table reconciles the eBPF nptv6_table map against the NPTv6
// field of every live BGPVRFInstance CRD owned by nodeName's BGPRouters in
// namespace. pinDir is the bpffs directory holding the pinned map.
//
// Unlike SweepEBPFVRFTable, which only reaps entries the CNI ADD path
// registered, this is nptv6_table's only writer: NPTv6 is a per-VRF field with
// no per-attachment counterpart, so nothing registers a mapping at ADD time.
// Every live mapping is therefore re-registered on the same tick that reaps
// stale ones. Being the sole writer is what makes that safe without the
// kernel-persisted generation field vrf_table relies on.
//
// It runs alongside SweepEBPFVRFTable, from the same ticker and for the same
// reason: the pinned map exists only in the container with the /sys/fs/bpf
// mount and CAP_BPF, so the BGPVRFInstance reconciler cannot open it whatever
// it does with the CRD field.
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

	// Capture the cutoff before listing CRDs and re-registering their mappings
	// below, so every entry this call registers stamps a generation at or
	// above it and Reconcile keeps it.
	cutoff := table.Generation()

	routers, err := routersForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		slog.Error("GC: failed to list BGPRouters for eBPF nptv6_table sweep", "err", err)
		result.Errors++
		return result
	}
	if len(routers) == 0 {
		// Zero routers found means skip this tick, not "nothing is live". See
		// SweepEBPFVRFTable's identical guard.
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

// buildNPTv6Mapping converts a BGPVRFInstanceSpec's NPTv6 field into an
// nptv6.Mapping. It checks only that the CIDRs parse; nptv6.Mapping performs
// the fuller RFC 6296 range validation.
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

// RunGC performs a full garbage collection pass, removing orphaned BGP CRDs
// and orphaned VRF interfaces, and returns a summary of what it cleaned up.
// nodeName scopes the pass to CRDs owned by this node's BGPRouters.
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

// collectNetNSPaths extracts every (containerID, netnsPath) pair recorded on a
// BGPAdvertisement's netns annotations, one per container that has ever
// attached to this attachment on this node. Pod churn adds entries without
// removing old ones, so an object can carry several.
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

// parseVRFName extracts the base62 VPC from a Galactic VRF interface name,
// reporting whether the name matched the current pattern.
//
// The interface name template zero-pads its base62 components while BGP CRD
// names use the raw values, so leading zeros are stripped to match the CRD
// naming convention.
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

// vpcFromVRFName resolves the VPC a kernel VRF interface belongs to, accepting
// both the current per-VPC name and the legacy pre-rename name. Both carry the
// same base62 VPC in the same leading position, so a legacy VRF resolves to
// exactly the VPC its BGPAdvertisements are named after.
//
// Only CollectOrphanedVRFs uses this. RemoveOrphanedVRFs keeps parseVRFName,
// because it deletes through vrf.Delete, which rebuilds the current interface
// name from the VPC and would silently no-op against a legacy interface.
// Leaving a legacy name unresolved there routes it into the by-name fallback,
// which deletes the interface actually observed.
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
