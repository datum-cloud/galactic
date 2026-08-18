// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/vip"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// serviceVIPBindingFinalizer guards ServiceVIPBinding teardown: the
// veth/tap-specific unbind (vip.Unbind, or the translation table's
// Unregister calls) must complete before the object is actually removed
// from etcd, mirroring networkRuleFinalizer's identical ordering purpose
// on NetworkRule.
const serviceVIPBindingFinalizer = "galactic.datum.net/servicevipbinding-teardown"

// ipProtoTCP/ipProtoUDP are the wire protocol numbers (IANA) matching
// usid.c's USID_IPPROTO_TCP/USID_IPPROTO_UDP constants -- the only two
// protocols vip_xlat_table's rewrite path ever applies to.
const (
	ipProtoTCP = uint8(6)
	ipProtoUDP = uint8(17)
)

// vipBindFn/vipUnbindFn/vipVerifyFn are package-level overridable indirections
// onto internal/plumbing/vip's Bind/Unbind/Verify -- the same pattern
// internal/plumbing/ebpf/attach.go uses (routeListFn/linkByIndexFn/
// preflightCheckFn/filterPriorityFn) so tests can exercise the
// EgressKindVeth branch's control flow without CAP_NET_ADMIN or a real
// netlink socket. Production code never reassigns these; vip.go itself is
// untouched.
var (
	vipBindFn   = vip.Bind
	vipUnbindFn = vip.Unbind
	vipVerifyFn = vip.Verify
)

// VIPTranslationTable is the interface ServiceVIPBindingReconciler drives
// for both EgressKindVeth and EgressKindTap bindings (see
// registerVIPTranslation), satisfied by *vipxlatmap.VipXlatTable in
// production and a fake in tests -- the same interface-seam pattern
// GatewayEngine (networkgateway_controller.go) provides for *gateway.Engine.
type VIPTranslationTable interface {
	RegisterIngress(block uint64, argument uint16, proto uint8,
		vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16) error
	RegisterEgress(block uint64, argument uint16, proto uint8,
		backendAddr net.IP, backendPort uint16, vipAddr net.IP, vipPort uint16) error
	UnregisterIngress(block uint64, argument uint16, proto uint8, vipPort uint16) error
	UnregisterEgress(block uint64, argument uint16, proto uint8, backendPort uint16) error
}

// ServiceVIPBindingReconciler reconciles ServiceVIPBinding objects targeting
// this node (spec.targetRef.name == NodeName) -- the backend-side half of
// the DSR/Maglev gateway redesign (see ServiceVIPBinding's own doc
// comment). It branches on Spec.EgressKind exactly like usid.c's own
// vrf_table egress_kind field does, but both branches now converge on the
// same delivery mechanism:
//
//   - EgressKindTap calls VIPTranslationTable's Register/Unregister methods
//     (vip_xlat_table's two independent rows -- see
//     internal/plumbing/ebpf/vipxlatmap's package doc comment), after
//     resolving this node's own uSID Block and the tenant VRF's Argument
//     via resolveVIPBindingContext.
//   - EgressKindVeth does the *same* vip_xlat_table registration (see
//     registerVIPTranslation), plus internal/plumbing/vip.Bind/Unbind/Verify.
//
// # Why veth needs vip_xlat_table too, not just vip.Bind
//
// vip.Bind only assigns the VIP to a plain dummy interface in the node's
// *root* network namespace -- not enslaved to any tenant VRF (see
// internal/plumbing/vip's own doc comment). But a DSR-forwarded ingress
// packet is decapsulated by usid_ingress and delivered into the owning
// tenant's *own* VRF routing table, which has no route to an address that
// only exists on a root-namespace interface outside that VRF entirely.
// Found live in containerlab: a NetworkRule's VIP reported fully
// Advertised/Ready, the edge datapath's own metrics showed it matching and
// forwarding every packet with zero drops, and the connection still never
// completed -- traced to exactly this: iad-worker's own vrf60 routing
// table had a route for the backend pod's real address but none at all for
// the VIP. vip_xlat_table's ingress row rewrites the packet's destination
// from VIP to the backend's real, already-routed address *before* that VRF
// lookup happens (usid.c's own comment on this step: "translate the inner
// packet's destination before the FIB lookup ... so the lookup resolves
// against the tenant's real, routed address") -- exactly the missing
// piece, and usid_ingress applies it unconditionally whenever a matching
// vip_xlat_table row exists, regardless of egress_kind; only the control
// plane was ever kind-gated. vip.Bind is kept alongside it for veth (not
// replaced): it still gives the node itself a locally-verifiable answer on
// the VIP (see vip.Verify), which registerVIPTranslation alone would not.
//
// VIPTranslationTable is nil-safe for tests that never reconcile a live
// binding: a nil table only matters once one actually is, at which point
// it fails with a clear, actionable error rather than a nil-pointer panic.
type ServiceVIPBindingReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	NodeName string

	// VIPTranslationTable is the kernel-map handle both EgressKindVeth and
	// EgressKindTap now drive (see the type doc comment above). See its own
	// nil-safety contract there.
	VIPTranslationTable VIPTranslationTable
}

// Reconcile reconciles a single ServiceVIPBinding.
func (r *ServiceVIPBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	binding := &bgpv1alpha1.ServiceVIPBinding{}
	if err := r.Get(ctx, req.NamespacedName, binding); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get ServiceVIPBinding %s: %w", req.NamespacedName, err)
	}

	if binding.Spec.TargetRef.Name != r.NodeName {
		return ctrl.Result{}, nil
	}

	if !binding.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, binding)
	}

	if !controllerutil.ContainsFinalizer(binding, serviceVIPBindingFinalizer) {
		patchBase := binding.DeepCopy()
		controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
		if err := r.Patch(ctx, binding, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer to ServiceVIPBinding %s: %w", req.NamespacedName, err)
		}
	}

	if err := r.reconcileBind(ctx, binding); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// reconcileBind applies binding's desired bind/translation state and
// records the outcome on Status.Conditions[Bound], mirroring
// networkrule_controller.go's own condition-update style (status update
// happens regardless of success/failure, and the bind/register error, if
// any, is returned afterward so the controller-runtime requeues it).
func (r *ServiceVIPBindingReconciler) reconcileBind(ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding) error {
	bindErr := r.applyBind(ctx, binding)

	bindingCopy := binding.DeepCopy()
	cond := metav1.Condition{Type: bgpv1alpha1.ConditionTypeBound}
	if bindErr != nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "BindFailed"
		cond.Message = bindErr.Error()
	} else {
		cond.Status = metav1.ConditionTrue
		cond.Reason = "Bound"
		cond.Message = fmt.Sprintf("backend is reachable on VIP %s:%d (%s)",
			binding.Spec.VIPAddress, binding.Spec.Port, binding.Spec.EgressKind)
	}
	setBindingCondition(bindingCopy, cond)
	bindingCopy.Status.ObservedGeneration = binding.Generation
	if err := r.Status().Update(ctx, bindingCopy); err != nil {
		return fmt.Errorf("update ServiceVIPBinding %s/%s status: %w", binding.Namespace, binding.Name, err)
	}

	if bindErr != nil {
		return fmt.Errorf("bind ServiceVIPBinding %s/%s: %w", binding.Namespace, binding.Name, bindErr)
	}
	return nil
}

// applyBind performs the actual veth or tap binding for binding, branching
// on Spec.EgressKind. Both kinds now register the same vip_xlat_table rows
// (see registerVIPTranslation and the type doc comment above); veth
// additionally does the root-namespace vip.Bind/Verify.
func (r *ServiceVIPBindingReconciler) applyBind(ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding) error {
	switch binding.Spec.EgressKind {
	case bgpv1alpha1.ServiceVIPBindingEgressKindVeth:
		vipAddr := net.ParseIP(binding.Spec.VIPAddress)
		if vipAddr == nil {
			return fmt.Errorf("invalid vipAddress %q", binding.Spec.VIPAddress)
		}
		if err := vipBindFn(vipAddr); err != nil {
			return fmt.Errorf("vip.Bind: %w", err)
		}
		if err := vipVerifyFn(vipAddr); err != nil {
			return fmt.Errorf("vip.Verify: %w", err)
		}
		return r.registerVIPTranslation(ctx, binding)
	case bgpv1alpha1.ServiceVIPBindingEgressKindTap:
		return r.registerVIPTranslation(ctx, binding)
	default:
		return fmt.Errorf("unknown egressKind %q", binding.Spec.EgressKind)
	}
}

// registerVIPTranslation registers both vip_xlat_table rows (ingress and
// egress) for binding, after resolving this node's own uSID Block and the
// owning tenant VRF's Argument (resolveVIPBindingContext). Shared by both
// EgressKindVeth and EgressKindTap -- see ServiceVIPBindingReconciler's own
// doc comment for why veth needs this too, not just tap.
func (r *ServiceVIPBindingReconciler) registerVIPTranslation(
	ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding,
) error {
	if r.VIPTranslationTable == nil {
		return fmt.Errorf("vip_xlat_table is not available on this node (eBPF uSID datapath not loaded); "+
			"cannot bind a %s-kind ServiceVIPBinding", binding.Spec.EgressKind)
	}

	vipAddr := net.ParseIP(binding.Spec.VIPAddress)
	if vipAddr == nil {
		return fmt.Errorf("invalid vipAddress %q", binding.Spec.VIPAddress)
	}
	backendAddr := net.ParseIP(binding.Spec.BackendAddress)
	if backendAddr == nil {
		return fmt.Errorf("invalid backendAddress %q (required for both egressKind veth and tap)",
			binding.Spec.BackendAddress)
	}
	backendAddrIP, err := netip.ParseAddr(binding.Spec.BackendAddress)
	if err != nil {
		return fmt.Errorf("parse backendAddress %q: %w", binding.Spec.BackendAddress, err)
	}

	proto, err := ipProtocolNumber(binding.Spec.Protocol)
	if err != nil {
		return err
	}

	block, argument, err := resolveVIPBindingContext(ctx, r.Client, binding.Namespace, r.NodeName, backendAddrIP.Unmap())
	if err != nil {
		return fmt.Errorf("resolve VRF context for VIP binding: %w", err)
	}

	vipPort := uint16(binding.Spec.Port)            //nolint:gosec // kubebuilder-validated 1-65535
	backendPort := uint16(binding.Spec.BackendPort) //nolint:gosec // kubebuilder-validated 1-65535

	if err := r.VIPTranslationTable.RegisterIngress(
		block, argument, proto, vipAddr, vipPort, backendAddr, backendPort); err != nil {
		return fmt.Errorf("register vip_xlat_table ingress row: %w", err)
	}
	if err := r.VIPTranslationTable.RegisterEgress(
		block, argument, proto, backendAddr, backendPort, vipAddr, vipPort); err != nil {
		return fmt.Errorf("register vip_xlat_table egress row: %w", err)
	}
	return nil
}

// reconcileDelete performs the finalizer-guarded unbind/unregister on
// ServiceVIPBinding deletion, mirroring networkrule_controller.go's
// reconcileDelete pattern: the finalizer is only removed once the
// underlying unbind/unregister has actually succeeded, so a failure here
// blocks deletion (and is retried) rather than silently leaking kernel/host
// state.
func (r *ServiceVIPBindingReconciler) reconcileDelete(
	ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding,
) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(binding, serviceVIPBindingFinalizer) {
		return ctrl.Result{}, nil
	}

	if err := r.applyUnbind(ctx, binding); err != nil {
		return ctrl.Result{}, fmt.Errorf("unbind ServiceVIPBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}

	patchBase := binding.DeepCopy()
	controllerutil.RemoveFinalizer(binding, serviceVIPBindingFinalizer)
	if err := r.Patch(ctx, binding, client.MergeFrom(patchBase)); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer from ServiceVIPBinding %s/%s: %w",
			binding.Namespace, binding.Name, err)
	}
	return ctrl.Result{}, nil
}

// applyUnbind performs the actual veth or tap unbind for binding, branching
// on Spec.EgressKind. Both kinds now unregister the same vip_xlat_table
// rows (see unregisterVIPTranslation); veth additionally does the
// root-namespace vip.Unbind. For veth, both are attempted even if one
// fails, and any errors are joined -- mirroring unregisterVIPTranslation's
// own "attempt every candidate even if one fails" convention -- so a
// failure in one mechanism never silently skips tearing down the other.
func (r *ServiceVIPBindingReconciler) applyUnbind(ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding) error {
	switch binding.Spec.EgressKind {
	case bgpv1alpha1.ServiceVIPBindingEgressKindVeth:
		var errs []error
		if err := r.unregisterVIPTranslation(ctx, binding); err != nil {
			errs = append(errs, err)
		}
		if vipAddr := net.ParseIP(binding.Spec.VIPAddress); vipAddr != nil {
			if err := vipUnbindFn(vipAddr); err != nil {
				errs = append(errs, err)
			}
		} // else: already-invalid address; nothing meaningful for vip.Unbind to do
		return errors.Join(errs...)
	case bgpv1alpha1.ServiceVIPBindingEgressKindTap:
		return r.unregisterVIPTranslation(ctx, binding)
	default:
		return nil
	}
}

// unregisterVIPTranslation removes both vip_xlat_table rows for binding.
// Shared by both EgressKindVeth and EgressKindTap -- see
// ServiceVIPBindingReconciler's own doc comment. Both directions are
// attempted even if resolving the VRF context or the first Unregister call
// fails, and any errors are joined together -- mirroring
// usidmap.VRFTable.Reconcile's own "attempt every candidate even if one
// fails" convention -- so a partial failure never silently leaves the
// other row behind unregistered.
func (r *ServiceVIPBindingReconciler) unregisterVIPTranslation(
	ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding,
) error {
	if r.VIPTranslationTable == nil {
		return fmt.Errorf("vip_xlat_table is not available on this node; cannot unregister a %s-kind ServiceVIPBinding",
			binding.Spec.EgressKind)
	}

	proto, err := ipProtocolNumber(binding.Spec.Protocol)
	if err != nil {
		return err
	}

	backendAddrIP, err := netip.ParseAddr(binding.Spec.BackendAddress)
	if err != nil {
		return fmt.Errorf("parse backendAddress %q: %w", binding.Spec.BackendAddress, err)
	}

	block, argument, err := resolveVIPBindingContext(ctx, r.Client, binding.Namespace, r.NodeName, backendAddrIP.Unmap())
	if err != nil {
		return fmt.Errorf("resolve VRF context for VIP unbind: %w", err)
	}

	vipPort := uint16(binding.Spec.Port)            //nolint:gosec // kubebuilder-validated 1-65535
	backendPort := uint16(binding.Spec.BackendPort) //nolint:gosec // kubebuilder-validated 1-65535

	var errs []error
	if err := r.VIPTranslationTable.UnregisterIngress(block, argument, proto, vipPort); err != nil {
		errs = append(errs, fmt.Errorf("unregister vip_xlat_table ingress row: %w", err))
	}
	if err := r.VIPTranslationTable.UnregisterEgress(block, argument, proto, backendPort); err != nil {
		errs = append(errs, fmt.Errorf("unregister vip_xlat_table egress row: %w", err))
	}
	return errors.Join(errs...)
}

// ipProtocolNumber maps a NetworkRuleProtocol to the IANA protocol number
// vip_xlat_table's key uses (usid.c's USID_IPPROTO_TCP/UDP).
func ipProtocolNumber(proto bgpv1alpha1.NetworkRuleProtocol) (uint8, error) {
	switch proto {
	case bgpv1alpha1.NetworkRuleProtocolTCP:
		return ipProtoTCP, nil
	case bgpv1alpha1.NetworkRuleProtocolUDP:
		return ipProtoUDP, nil
	default:
		return 0, fmt.Errorf(
			"unsupported protocol %q (vip_xlat_table only supports tcp/udp, matching usid.c's USID_IPPROTO_TCP/UDP)", proto)
	}
}

// resolveVIPBindingContext resolves this node's own uSID Block (from its
// BGPRouter's SRv6Locator) and the owning tenant VRF's Argument (from the
// BGPVRFInstance whose VRFID is associated with a BGPAdvertisement whose
// advertised prefix contains backendAddr) -- the (block, argument) pair
// vip_xlat_table's key needs (usid.c's struct vip_xlat_key), for a
// tap-kind ServiceVIPBinding on this node.
//
// # A documented ambiguity (no VPCRef/VRFRef field on ServiceVIPBinding)
//
// ServiceVIPBinding carries no VPCRef or VRFRef field of its own (see its
// own doc comment and internal/controller/usidresolver.go's identical
// concern for NetworkRule backends) -- the writer that is expected to
// eventually populate ServiceVIPBinding objects (a future extension of
// NetworkRuleReconciler, out of this reconciler's scope) has direct access
// to the owning NetworkRule's VPCRef at creation time, but that identity is
// not carried onto the ServiceVIPBinding object itself today. Absent that
// field, this function resolves ownership the same way
// usidresolver.go's backendSIDIndex already does for NetworkRule backends:
// by matching BackendAddress against this node's own BGPVRFInstances'
// advertised prefixes (reusing buildBackendSIDIndex directly rather than
// re-listing the same CRDs) -- restricted to VRFs whose BGPVRFInstance
// actually targets *this node's* own BGPRouter, since a tap binding's VRF
// context is always local to the node it was written for.
//
// This resolution is unambiguous as long as no two VRFs on this same node
// advertise overlapping prefixes that both contain backendAddr (e.g. two
// tenants independently choosing the same ULA range) -- exactly the
// scenario backendSIDIndex.verifyTenantOwnership already exists to guard
// against elsewhere, but that guard needs a known vpcRef to check
// ownership *against*, which this function does not have. When more than
// one candidate VRF matches, this function fails closed (an explicit
// error) rather than guessing, on the same reasoning
// verifyTenantOwnership's own doc comment gives: silently picking one
// candidate over another risks translating a backend's traffic into the
// wrong tenant's VRF, not merely an inconvenience.
//
// TODO(dsr-maglev): once ServiceVIPBinding gains a VPCRef/VRFRef field (or
// the writer encodes the resolved (block, argument) directly on the
// object), replace this address-containment heuristic with a direct
// lookup -- see crdnames.BGPVRFInstanceName(vpc, nodeName) for the
// deterministic name that lookup would use.
func resolveVIPBindingContext(
	ctx context.Context, c client.Client, namespace, nodeName string, backendAddr netip.Addr,
) (block uint64, argument uint16, err error) {
	idx, err := buildBackendSIDIndex(ctx, c, namespace)
	if err != nil {
		return 0, 0, fmt.Errorf("build backend SID index: %w", err)
	}

	var router *bgpv1alpha1.BGPRouter
	for _, rt := range idx.routers {
		if rt.Spec.TargetRef.Name == nodeName {
			router = rt
			break
		}
	}
	if router == nil {
		return 0, 0, fmt.Errorf("no BGPRouter targets node %q in namespace %q", nodeName, namespace)
	}
	if router.Spec.SRv6Locator == "" {
		return 0, 0, fmt.Errorf("BGPRouter %s has no SRv6Locator set", router.Name)
	}

	prefix, err := netip.ParsePrefix(router.Spec.SRv6Locator)
	if err != nil {
		return 0, 0, fmt.Errorf("parse SRv6Locator %q of BGPRouter %s: %w", router.Spec.SRv6Locator, router.Name, err)
	}
	block, err = uformat.Block(prefix.Addr())
	if err != nil {
		return 0, 0, fmt.Errorf("derive uSID Block from BGPRouter %s's SRv6Locator: %w", router.Name, err)
	}

	localVRFIDs := make(map[int32]struct{})
	for _, instance := range idx.vrfInstances {
		if vrfInstanceTargetsRouter(instance, router) {
			localVRFIDs[instance.Spec.VRFID] = struct{}{}
		}
	}

	seen := make(map[int32]struct{})
	var matches []int32
	for _, adv := range idx.advs {
		if adv.Spec.RouterRef.Name != router.Name || adv.Spec.VRFID == nil {
			continue
		}
		vrfID := *adv.Spec.VRFID
		if _, ok := localVRFIDs[vrfID]; !ok {
			continue // not one of this node's own local VRFs
		}
		if _, already := seen[vrfID]; already {
			continue
		}
		for _, p := range adv.Spec.Prefixes {
			pfx, perr := netip.ParsePrefix(string(p))
			if perr != nil {
				continue
			}
			if pfx.Contains(backendAddr) {
				seen[vrfID] = struct{}{}
				matches = append(matches, vrfID)
				break
			}
		}
	}

	switch len(matches) {
	case 0:
		return 0, 0, fmt.Errorf(
			"no local BGPVRFInstance on node %q has an advertised BGPAdvertisement prefix containing backend address %s",
			nodeName, backendAddr)
	case 1:
		return block, uint16(matches[0]), nil //nolint:gosec // VRFID is kubebuilder-validated 1-65535
	default:
		return 0, 0, fmt.Errorf(
			"ambiguous VRF ownership for backend address %s on node %q: %d candidate VRFIDs %v all advertise a "+
				"containing prefix, and ServiceVIPBinding carries no VPCRef/VRFRef to disambiguate "+
				"(see resolveVIPBindingContext's doc comment); refusing to guess",
			backendAddr, nodeName, len(matches), matches)
	}
}

// vrfInstanceTargetsRouter reports whether vrf's RouterTarget (RouterRef or
// RouterSelector) resolves to router -- mirroring routing.go's
// enqueueRoutersForTarget matching logic, but as a boolean test against one
// already-known router rather than a List-driven fan-out.
func vrfInstanceTargetsRouter(vrf *bgpv1alpha1.BGPVRFInstance, router *bgpv1alpha1.BGPRouter) bool {
	if vrf.Spec.RouterRef != nil {
		return vrf.Spec.RouterRef.Name == router.Name
	}
	if vrf.Spec.RouterSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
			MatchLabels:      vrf.Spec.RouterSelector.MatchLabels,
			MatchExpressions: vrf.Spec.RouterSelector.MatchExpressions,
		})
		if err != nil {
			return false
		}
		return sel.Matches(labels.Set(router.Labels))
	}
	return false
}

// SetupWithManager registers the ServiceVIPBindingReconciler with the
// manager. ServiceVIPBinding is a leaf CRD written by another controller
// and consumed only here -- no additional watch is needed beyond the
// object itself, unlike NetworkRuleReconciler's NetworkGateway watch
// (which reacts to a namespace-wide gateway-node pool changing).
func (r *ServiceVIPBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.ServiceVIPBinding{}).
		Named("servicevipbinding").
		Complete(r)
}
