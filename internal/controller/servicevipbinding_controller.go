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

// serviceVIPBindingFinalizer guards teardown: the veth or tap unbind must
// complete before the object is removed from etcd.
const serviceVIPBindingFinalizer = "galactic.datum.net/servicevipbinding-teardown"

// ipProtoTCP and ipProtoUDP are the IANA wire protocol numbers matching the
// datapath's own constants, the only two protocols vip_xlat_table's rewrite
// path applies to.
const (
	ipProtoTCP = uint8(6)
	ipProtoUDP = uint8(17)
)

// vipBindFn, vipUnbindFn, and vipVerifyFn indirect internal/plumbing/vip so
// tests can exercise the veth branch without CAP_NET_ADMIN or a real netlink
// socket. Production never reassigns them.
var (
	vipBindFn   = vip.Bind
	vipUnbindFn = vip.Unbind
	vipVerifyFn = vip.Verify
)

// VIPTranslationTable is the interface ServiceVIPBindingReconciler drives for
// both egress kinds, satisfied by *vipxlatmap.VipXlatTable in production and a
// fake in tests.
type VIPTranslationTable interface {
	RegisterIngress(block uint64, argument uint16, proto uint8,
		vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16) error
	RegisterEgress(block uint64, argument uint16, proto uint8,
		backendAddr net.IP, backendPort uint16, vipAddr net.IP, vipPort uint16) error
	UnregisterIngress(block uint64, argument uint16, proto uint8, vipPort uint16) error
	UnregisterEgress(block uint64, argument uint16, proto uint8, backendPort uint16) error
}

// ServiceVIPBindingReconciler reconciles ServiceVIPBinding objects targeting
// this node. It branches on Spec.EgressKind the way the datapath's vrf_table
// egress_kind field does, but both branches converge on the same delivery
// mechanism:
//
//   - EgressKindTap registers vip_xlat_table's two rows, after resolving this
//     node's uSID Block and the tenant VRF's Argument.
//   - EgressKindVeth registers the same rows, and additionally binds the VIP in
//     the root namespace through internal/plumbing/vip.
//
// # Why veth needs vip_xlat_table too, not just the bind
//
// Binding assigns the VIP to a dummy interface in the node's root namespace,
// enslaved to no tenant VRF. A DSR-forwarded ingress packet is decapsulated and
// delivered into the owning tenant's VRF routing table, which has no route to an
// address that exists only outside that VRF. The symptom is a VIP that reports
// fully advertised and ready, with the edge datapath matching and forwarding
// every packet and no drops, while the connection never completes.
//
// The ingress row rewrites the destination from VIP to the backend's real,
// already-routed address before that lookup happens. usid_ingress applies it
// whenever a matching row exists, whatever the egress kind; only the control
// plane was ever kind-gated. The bind is kept alongside it for veth rather than
// replaced, because it still gives the node a locally verifiable answer on the
// VIP.
//
// VIPTranslationTable may be nil for tests that never reconcile a live binding.
// A nil table matters only once one is, at which point it fails with a clear
// error rather than a nil-pointer panic.
type ServiceVIPBindingReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	NodeName string

	// VIPTranslationTable is the kernel-map handle both egress kinds drive. See
	// the type doc comment for its nil-safety contract.
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

// reconcileBind applies binding's desired bind and translation state and records
// the outcome on the Bound condition. The status update happens whether or not
// the bind succeeded, and the error is returned afterward so controller-runtime
// requeues.
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

// applyBind performs the veth or tap binding for binding, branching on
// Spec.EgressKind. Both kinds register the same vip_xlat_table rows; veth
// additionally binds and verifies the VIP in the root namespace.
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

// registerVIPTranslation registers both vip_xlat_table rows for binding, after
// resolving this node's uSID Block and the owning tenant VRF's Argument. Shared
// by both egress kinds; see the type doc comment for why veth needs it too.
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

// reconcileDelete performs the finalizer-guarded unbind on deletion. The
// finalizer is removed only once the unbind has succeeded, so a failure blocks
// deletion and is retried rather than silently leaking kernel state.
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

// applyUnbind performs the veth or tap unbind for binding, branching on
// Spec.EgressKind. Both kinds unregister the same vip_xlat_table rows; veth
// additionally unbinds in the root namespace. For veth both are attempted even
// if one fails, and the errors are joined, so a failure in one never skips
// tearing down the other.
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

// unregisterVIPTranslation removes both vip_xlat_table rows for binding. Shared
// by both egress kinds. Both directions are attempted even if resolving the VRF
// context or the first removal fails, and the errors are joined, so a partial
// failure never leaves the other row behind.
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

// resolveVIPBindingContext resolves the (block, argument) pair vip_xlat_table's
// key needs for a binding on this node: the Block from this node's BGPRouter
// locator, and the Argument from the BGPVRFInstance whose advertised prefix
// contains backendAddr.
//
// # A documented ambiguity
//
// ServiceVIPBinding carries no VPC or VRF reference of its own. The writer that
// creates these objects has the owning rule's VPC reference at creation time,
// but does not record it here. Absent that field, ownership is resolved by
// matching backendAddr against the advertised prefixes of BGPVRFInstances
// targeting this node's own BGPRouter, since a binding's VRF context is always
// local to the node it was written for.
//
// That is unambiguous only while no two VRFs on this node advertise overlapping
// prefixes containing backendAddr, such as two tenants choosing the same ULA
// range. The ownership guard used elsewhere needs a known VPC reference to check
// against, which this function does not have, so when more than one candidate
// matches it fails with an explicit error rather than guessing: picking one
// would translate a backend's traffic into the wrong tenant's VRF.
//
// TODO(dsr-maglev): once ServiceVIPBinding carries a VPC or VRF reference, or
// the writer records the resolved (block, argument) on the object, replace this
// address-containment heuristic with a direct lookup by
// crdnames.BGPVRFInstanceName.
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

// vrfInstanceTargetsRouter reports whether vrf's router target, by reference or
// selector, resolves to router. The same matching the watch fan-out does, as a
// boolean test against one known router rather than a list.
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

// SetupWithManager registers the reconciler with the manager. ServiceVIPBinding
// is a leaf CRD written outside this repo and consumed only here, so no watch
// beyond the object itself is needed.
func (r *ServiceVIPBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.ServiceVIPBinding{}).
		Named("servicevipbinding").
		Complete(r)
}
