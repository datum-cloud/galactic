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
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
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
	RegisterIngress(block uint64, argument, slot uint16, proto uint8,
		vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16) error
	RegisterEgress(block uint64, argument uint16, proto uint8,
		backendAddr net.IP, backendPort uint16, vipAddr net.IP, vipPort uint16) error
	UnregisterIngress(block uint64, argument, slot uint16, proto uint8, vipAddr net.IP, vipPort uint16) error
	UnregisterEgress(block uint64, argument uint16, proto uint8, backendAddr net.IP, backendPort uint16) error
	UnregisterBinding(slot uint16, proto uint8, vipAddr net.IP, vipPort uint16,
		backendAddr net.IP, backendPort uint16) ([]vipxlatmap.Entry, error)
	UnregisterBindingAt(block uint64, argument, slot uint16, proto uint8, vipAddr net.IP, vipPort uint16,
		backendAddr net.IP, backendPort uint16) ([]vipxlatmap.Entry, error)
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
// # One owner per row
//
// A vip_xlat_table row is keyed by VRF, protocol, address and port, so two
// bindings on this node can claim the same row: the same VIP and port, or the
// same backend address and port. The kernel row can only point one way. The
// oldest live binding claiming a row owns it, by creation time and then name,
// so the choice does not change from one reconcile to the next. A binding that
// loses either of its rows writes neither, removes any row it alone held, and
// reports Bound=False with reason Conflict. Deleting a binding removes only rows
// that still hold its own values, and a change to any binding on this node
// requeues the others, so the next owner writes the row.
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
	var conflict *vipRowConflictError
	if errors.As(bindErr, &conflict) {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "Conflict"
		cond.Message = conflict.Error()
		// Not retried on a timer: a change to the owning binding requeues
		// this one through the peer watch in SetupWithManager.
		bindErr = nil
	} else if bindErr != nil {
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
//
// It writes the rows only if binding owns both of them. Otherwise it removes
// any row binding alone claims and returns a *vipRowConflictError naming the
// owner of each row it lost. See the type doc comment's "One owner per row".
func (r *ServiceVIPBindingReconciler) registerVIPTranslation(
	ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding,
) error {
	if r.VIPTranslationTable == nil {
		return fmt.Errorf("vip_xlat_table is not available on this node (eBPF uSID datapath not loaded); "+
			"cannot bind a %s-kind ServiceVIPBinding", binding.Spec.EgressKind)
	}

	idx, err := buildBackendSIDIndex(ctx, r.Client, binding.Namespace)
	if err != nil {
		return fmt.Errorf("build backend SID index: %w", err)
	}
	self, err := resolveVIPBindingRows(idx, r.NodeName, binding)
	if err != nil {
		return err
	}
	peers, err := r.livePeers(ctx, idx, binding)
	if err != nil {
		return err
	}

	conflict := &vipRowConflictError{}
	var owned []vipRow
	for _, row := range []vipRow{self.ingress, self.egress} {
		if owner := rowOwner(row, binding, peers); owner != nil {
			conflict.lost = append(conflict.lost, lostRow{row: row, owner: owner})
		} else {
			owned = append(owned, row)
		}
	}
	if len(conflict.lost) > 0 {
		// A binding serves traffic only with both rows. Drop the one it alone
		// claims, in case an earlier reconcile wrote it.
		var errs []error
		for _, row := range owned {
			errs = append(errs, r.unregisterRow(row))
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
		return conflict
	}

	if err := r.VIPTranslationTable.RegisterIngress(
		self.ingress.block, self.ingress.argument, self.ingress.slot, self.ingress.proto,
		self.vipAddr, self.vipPort, self.backendAddr, self.backendPort); err != nil {
		return fmt.Errorf("register vip_xlat_table ingress row: %w", err)
	}
	if err := r.VIPTranslationTable.RegisterEgress(
		self.egress.block, self.egress.argument, self.egress.proto,
		self.backendAddr, self.backendPort, self.vipAddr, self.vipPort); err != nil {
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
		// Bindings for other ports share the VIP's address on the dummy
		// interface, so it stays while any of them is live.
		if vipAddr := net.ParseIP(binding.Spec.VIPAddress); vipAddr != nil {
			shared, err := r.vipAddressShared(ctx, binding, vipAddr)
			switch {
			case err != nil:
				errs = append(errs, err)
			case !shared:
				if err := vipUnbindFn(vipAddr); err != nil {
					errs = append(errs, err)
				}
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
// by both egress kinds.
//
// Teardown must not depend on the binding's VRF still being on the node: a VPC
// can leave the node before its bindings are deleted, and a delete that needs
// it would hold the finalizer forever and leave the rows in the map. Rows are
// therefore removed in two passes, and failing to resolve the VRF context is
// not an error:
//
//  1. UnregisterBinding finds the rows by key and value, under whatever block
//     and argument they were written, with no lookup of BGP objects.
//  2. If the VRF context still resolves, UnregisterBindingAt checks that
//     location too.
//
// Both passes read each row before deleting it and leave a row another binding
// has since written its own values to. Neither can tell this binding's rows
// from those of another live binding with the same values, so when one exists
// on this node nothing is removed: that binding owns the rows now.
//
// Registration writes rows only for an IPv6 VIP and backend, so an IPv4 or
// unparseable address means there is nothing to remove, which must not block
// deletion. Every removal is attempted even if an earlier one fails, and the
// errors are joined.
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
	logger := log.FromContext(ctx).WithValues("binding", client.ObjectKeyFromObject(binding))

	vipAddr, vipOK := ipv6Address(binding.Spec.VIPAddress)
	backendAddr, backendOK := ipv6Address(binding.Spec.BackendAddress)
	if !vipOK || !backendOK {
		logger.Info("vipAddress or backendAddress is not an IPv6 address; no vip_xlat_table rows to remove",
			"vipAddress", binding.Spec.VIPAddress, "backendAddress", binding.Spec.BackendAddress)
		return nil
	}

	vipPort := uint16(binding.Spec.Port)            //nolint:gosec // kubebuilder-validated 1-65535
	backendPort := uint16(binding.Spec.BackendPort) //nolint:gosec // kubebuilder-validated 1-65535

	twin, err := r.liveTwin(ctx, binding, proto, vipAddr, backendAddr)
	if err != nil {
		return err
	}
	if twin != nil {
		logger.Info("another live binding has the same values and keeps the vip_xlat_table rows", "owner", twin.Name)
		return nil
	}

	backendAddrIP, _ := netip.AddrFromSlice(backendAddr) // a 16-byte slice ipv6Address returned
	slot := srv6.BackendSlot(backendAddrIP.Unmap(), backendPort)

	var errs []error
	if _, err := r.VIPTranslationTable.UnregisterBinding(
		slot, proto, vipAddr, vipPort, backendAddr, backendPort); err != nil {
		errs = append(errs, fmt.Errorf("unregister vip_xlat_table rows by value: %w", err))
	}

	block, argument, err := resolveVIPBindingContext(ctx, r.Client, binding.Namespace, r.NodeName, binding.Spec.VPCRef)
	if err != nil {
		logger.Info("VRF context no longer resolves; skipped checking its vip_xlat_table location", "reason", err.Error())
		return errors.Join(errs...)
	}
	if _, err := r.VIPTranslationTable.UnregisterBindingAt(
		block, argument, slot, proto, vipAddr, vipPort, backendAddr, backendPort); err != nil {
		errs = append(errs, fmt.Errorf("unregister vip_xlat_table rows at the resolved VRF: %w", err))
	}
	return errors.Join(errs...)
}

// liveTwin returns another live binding on this node with binding's protocol,
// VIP and port, and backend and port, or nil if there is none. Such a binding
// writes exactly binding's rows.
func (r *ServiceVIPBindingReconciler) liveTwin(
	ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding, proto uint8, vipAddr, backendAddr net.IP,
) (*bgpv1alpha1.ServiceVIPBinding, error) {
	bindings, err := r.nodeBindings(ctx, binding.Namespace, binding.Name)
	if err != nil {
		return nil, err
	}
	for _, b := range bindings {
		bProto, err := ipProtocolNumber(b.Spec.Protocol)
		if err != nil || bProto != proto ||
			b.Spec.Port != binding.Spec.Port || b.Spec.BackendPort != binding.Spec.BackendPort {
			continue
		}
		bVIP, vipOK := ipv6Address(b.Spec.VIPAddress)
		bBackend, backendOK := ipv6Address(b.Spec.BackendAddress)
		if vipOK && backendOK && bVIP.Equal(vipAddr) && bBackend.Equal(backendAddr) {
			return b, nil
		}
	}
	return nil, nil
}

// ipv6Address parses s and reports whether it is an IPv6 address, the only
// family vip_xlat_table holds. An IPv4-mapped address counts as IPv4.
func ipv6Address(s string) (net.IP, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Unmap().Is6() {
		return nil, false
	}
	return net.IP(addr.AsSlice()), true
}

// unregisterRow removes one vip_xlat_table row.
func (r *ServiceVIPBindingReconciler) unregisterRow(row vipRow) error {
	addr := net.IP(row.addr.AsSlice())
	if row.egress {
		if err := r.VIPTranslationTable.UnregisterEgress(row.block, row.argument, row.proto, addr, row.port); err != nil {
			return fmt.Errorf("unregister vip_xlat_table egress row: %w", err)
		}
		return nil
	}
	if err := r.VIPTranslationTable.UnregisterIngress(
		row.block, row.argument, row.slot, row.proto, addr, row.port); err != nil {
		return fmt.Errorf("unregister vip_xlat_table ingress row: %w", err)
	}
	return nil
}

// vipRow identifies one vip_xlat_table row. addr and port are the VIP's for an
// ingress row and the backend's for an egress row. slot is the backend slot an
// ingress row is keyed on, so two backends of one VIP claim different ingress
// rows; it is always 0 on an egress row.
type vipRow struct {
	egress   bool
	block    uint64
	argument uint16
	slot     uint16
	proto    uint8
	addr     netip.Addr
	port     uint16
}

func (r vipRow) String() string {
	if r.egress {
		return fmt.Sprintf("egress row for VRF %d %s", r.argument, netip.AddrPortFrom(r.addr, r.port))
	}
	return fmt.Sprintf("ingress row for VRF %d slot %#04x %s", r.argument, r.slot, netip.AddrPortFrom(r.addr, r.port))
}

// vipBindingRows is one binding's claim on vip_xlat_table, with the addresses
// and ports its two rows are written from.
type vipBindingRows struct {
	ingress, egress      vipRow
	vipAddr, backendAddr net.IP
	vipPort, backendPort uint16
}

// resolveVIPBindingRows resolves the two vip_xlat_table rows binding claims on
// nodeName. The backend address must lie in a prefix the binding's VRF
// advertises on nodeName: otherwise the node does not serve that address, and
// rows written for it would report the binding Bound while every flow to it is
// lost. This covers a hand-written binding, one generated from an attachment
// whose interface is not up yet, and a stale attachment address. Teardown does
// not resolve rows this way, so a binding whose advertisement is already gone
// can still be deleted.
func resolveVIPBindingRows(
	idx *backendSIDIndex, nodeName string, binding *bgpv1alpha1.ServiceVIPBinding,
) (vipBindingRows, error) {
	rows, err := parseVIPBindingRows(binding)
	if err != nil {
		return vipBindingRows{}, err
	}
	vrf, err := resolveVIPBindingVRF(idx, nodeName, binding.Spec.VPCRef)
	if err != nil {
		return vipBindingRows{}, fmt.Errorf("resolve VRF context for VIP binding: %w", err)
	}
	backendIP, _ := netip.AddrFromSlice(rows.backendAddr)
	if !idx.vrfAdvertises(vrf.router.Name, vrf.instance.Spec.VRFID, backendIP.Unmap()) {
		return vipBindingRows{}, fmt.Errorf(
			"backend address %s is not in any prefix VPC %s's VRF %d advertises on node %q",
			backendIP.Unmap(), binding.Spec.VPCRef, vrf.instance.Spec.VRFID, nodeName)
	}
	return rows.at(vrf.block, vrf.argument()), nil
}

// parseVIPBindingRows derives the two rows binding claims from its spec alone,
// with their block and argument left zero for the caller to fill in with at.
func parseVIPBindingRows(binding *bgpv1alpha1.ServiceVIPBinding) (vipBindingRows, error) {
	vipIP, err := netip.ParseAddr(binding.Spec.VIPAddress)
	if err != nil {
		return vipBindingRows{}, fmt.Errorf("invalid vipAddress %q: %w", binding.Spec.VIPAddress, err)
	}
	backendIP, err := netip.ParseAddr(binding.Spec.BackendAddress)
	if err != nil {
		return vipBindingRows{}, fmt.Errorf("invalid backendAddress %q (required for both egressKind veth and tap): %w",
			binding.Spec.BackendAddress, err)
	}
	vipIP, backendIP = vipIP.Unmap(), backendIP.Unmap()

	proto, err := ipProtocolNumber(binding.Spec.Protocol)
	if err != nil {
		return vipBindingRows{}, err
	}

	vipPort := uint16(binding.Spec.Port)            //nolint:gosec // kubebuilder-validated 1-65535
	backendPort := uint16(binding.Spec.BackendPort) //nolint:gosec // kubebuilder-validated 1-65535

	slot := srv6.BackendSlot(backendIP, backendPort)

	return vipBindingRows{
		ingress:     vipRow{slot: slot, proto: proto, addr: vipIP, port: vipPort},
		egress:      vipRow{egress: true, proto: proto, addr: backendIP, port: backendPort},
		vipAddr:     net.IP(vipIP.AsSlice()),
		backendAddr: net.IP(backendIP.AsSlice()),
		vipPort:     vipPort,
		backendPort: backendPort,
	}, nil
}

// at returns rows placed in the VRF identified by (block, argument).
func (rows vipBindingRows) at(block uint64, argument uint16) vipBindingRows {
	rows.ingress.block, rows.ingress.argument = block, argument
	rows.egress.block, rows.egress.argument = block, argument
	return rows
}

// vipPeer is another live binding on this node and the rows it claims.
type vipPeer struct {
	binding *bgpv1alpha1.ServiceVIPBinding
	rows    vipBindingRows
}

// nodeBindings lists the live ServiceVIPBindings in namespace targeting this
// node, other than exclude. A binding being deleted is not live: it gives up
// its rows to whoever else claims them.
func (r *ServiceVIPBindingReconciler) nodeBindings(
	ctx context.Context, namespace, exclude string,
) ([]*bgpv1alpha1.ServiceVIPBinding, error) {
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := r.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list ServiceVIPBindings: %w", err)
	}
	var out []*bgpv1alpha1.ServiceVIPBinding
	for i := range list.Items {
		b := &list.Items[i]
		if b.Name == exclude || b.Spec.TargetRef.Name != r.NodeName || !b.DeletionTimestamp.IsZero() {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

// livePeers returns every other live binding on this node whose rows resolve.
// One that does not resolve, including one whose backend address its VRF does
// not advertise here, cannot be programmed, so it claims nothing.
func (r *ServiceVIPBindingReconciler) livePeers(
	ctx context.Context, idx *backendSIDIndex, binding *bgpv1alpha1.ServiceVIPBinding,
) ([]vipPeer, error) {
	bindings, err := r.nodeBindings(ctx, binding.Namespace, binding.Name)
	if err != nil {
		return nil, err
	}
	peers := make([]vipPeer, 0, len(bindings))
	for _, b := range bindings {
		rows, err := resolveVIPBindingRows(idx, r.NodeName, b)
		if err != nil {
			continue
		}
		peers = append(peers, vipPeer{binding: b, rows: rows})
	}
	return peers, nil
}

// vipAddressShared reports whether another live veth-kind binding on this node
// binds the same VIP address as binding.
func (r *ServiceVIPBindingReconciler) vipAddressShared(
	ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding, vipAddr net.IP,
) (bool, error) {
	bindings, err := r.nodeBindings(ctx, binding.Namespace, binding.Name)
	if err != nil {
		return false, err
	}
	for _, b := range bindings {
		if b.Spec.EgressKind == bgpv1alpha1.ServiceVIPBindingEgressKindVeth &&
			vipAddr.Equal(net.ParseIP(b.Spec.VIPAddress)) {
			return true, nil
		}
	}
	return false, nil
}

// claims reports whether rows includes row.
func (rows vipBindingRows) claims(row vipRow) bool {
	return rows.ingress == row || rows.egress == row
}

// rowOwner returns the peer that owns row ahead of self, or nil if self owns
// it. The oldest claimant owns a row, by creation time and then name.
func rowOwner(row vipRow, self *bgpv1alpha1.ServiceVIPBinding, peers []vipPeer) *bgpv1alpha1.ServiceVIPBinding {
	var owner *bgpv1alpha1.ServiceVIPBinding
	for _, p := range peers {
		if !p.rows.claims(row) || !bindingOlder(p.binding, self) {
			continue
		}
		if owner == nil || bindingOlder(p.binding, owner) {
			owner = p.binding
		}
	}
	return owner
}

// bindingOlder reports whether a was created before b, breaking a tie on
// creation time, which has one-second resolution, by name.
func bindingOlder(a, b *bgpv1alpha1.ServiceVIPBinding) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Name < b.Name
}

// lostRow is one row a binding claims that an older binding owns.
type lostRow struct {
	row   vipRow
	owner *bgpv1alpha1.ServiceVIPBinding
}

// vipRowConflictError reports that a binding cannot be programmed without
// displacing an older binding's vip_xlat_table row.
type vipRowConflictError struct {
	lost []lostRow
}

func (e *vipRowConflictError) Error() string {
	parts := make([]string, 0, len(e.lost))
	for _, l := range e.lost {
		parts = append(parts, fmt.Sprintf("%s is held by ServiceVIPBinding %s", l.row, l.owner.Name))
	}
	return "not programmed: " + strings.Join(parts, "; ")
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
// locator, and the Argument from vpcRef's BGPVRFInstance on this node, named
// crdnames.BGPVRFInstanceName(vpcRef, nodeName).
//
// The binding names its VPC, so this is a direct lookup. Two tenants on one
// node using the same backend address resolve to their own VRFs, and a VPC
// with no VRF on this node yet fails rather than borrowing another's.
func resolveVIPBindingContext(
	ctx context.Context, c client.Client, namespace, nodeName, vpcRef string,
) (block uint64, argument uint16, err error) {
	idx, err := buildBackendSIDIndex(ctx, c, namespace)
	if err != nil {
		return 0, 0, fmt.Errorf("build backend SID index: %w", err)
	}
	return resolveVIPBindingContextFromIndex(idx, nodeName, vpcRef)
}

// resolveVIPBindingContextFromIndex is resolveVIPBindingContext over an index
// the caller already built, so resolving every binding on a node lists each
// resource once.
func resolveVIPBindingContextFromIndex(
	idx *backendSIDIndex, nodeName, vpcRef string,
) (block uint64, argument uint16, err error) {
	vrf, err := resolveVIPBindingVRF(idx, nodeName, vpcRef)
	if err != nil {
		return 0, 0, err
	}
	return vrf.block, vrf.argument(), nil
}

// vipBindingVRF is vpcRef's VRF on a node: the node's BGPRouter, the uSID Block
// from its locator, and the VPC's BGPVRFInstance targeting it.
type vipBindingVRF struct {
	router   *bgpv1alpha1.BGPRouter
	instance *bgpv1alpha1.BGPVRFInstance
	block    uint64
}

// argument is the vip_xlat_table key's Argument, the VRF's ID.
func (v vipBindingVRF) argument() uint16 {
	return uint16(v.instance.Spec.VRFID) //nolint:gosec // VRFID is kubebuilder-validated 1-65535
}

// resolveVIPBindingVRF finds vpcRef's VRF on nodeName. See
// resolveVIPBindingContext.
func resolveVIPBindingVRF(idx *backendSIDIndex, nodeName, vpcRef string) (vipBindingVRF, error) {
	if vpcRef == "" {
		return vipBindingVRF{}, errors.New("binding has no vpcRef")
	}
	var router *bgpv1alpha1.BGPRouter
	for _, rt := range idx.routers {
		if rt.Spec.TargetRef.Name == nodeName {
			router = rt
			break
		}
	}
	if router == nil {
		return vipBindingVRF{}, fmt.Errorf("no BGPRouter targets node %q", nodeName)
	}
	if router.Spec.SRv6Locator == "" {
		return vipBindingVRF{}, fmt.Errorf("BGPRouter %s has no SRv6Locator set", router.Name)
	}

	prefix, err := netip.ParsePrefix(router.Spec.SRv6Locator)
	if err != nil {
		return vipBindingVRF{}, fmt.Errorf(
			"parse SRv6Locator %q of BGPRouter %s: %w", router.Spec.SRv6Locator, router.Name, err)
	}
	block, err := uformat.Block(prefix.Addr())
	if err != nil {
		return vipBindingVRF{}, fmt.Errorf("derive uSID Block from BGPRouter %s's SRv6Locator: %w", router.Name, err)
	}

	name := crdnames.BGPVRFInstanceName(vpcRef, nodeName)
	instance, ok := idx.vrfInstances[name]
	if !ok {
		return vipBindingVRF{}, fmt.Errorf("VPC %s has no BGPVRFInstance %s on node %q", vpcRef, name, nodeName)
	}
	if !vrfInstanceTargetsRouter(instance, router) {
		return vipBindingVRF{}, fmt.Errorf(
			"BGPVRFInstance %s does not target node %q's BGPRouter %s", name, nodeName, router.Name)
	}
	return vipBindingVRF{router: router, instance: instance, block: block}, nil
}

// vrfAdvertises reports whether a BGPAdvertisement on routerName for vrfID has
// a prefix containing addr. The index holds only advertisements with a VRFID
// and Function, so a prefix the node advertises without SRv6 decap never
// counts.
func (idx *backendSIDIndex) vrfAdvertises(routerName string, vrfID int32, addr netip.Addr) bool {
	for _, adv := range idx.advs {
		if adv.Spec.RouterRef.Name != routerName || *adv.Spec.VRFID != vrfID {
			continue
		}
		for _, p := range adv.Spec.Prefixes {
			prefix, err := netip.ParsePrefix(string(p))
			if err == nil && prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
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
// is a leaf CRD written outside this repo and consumed only here. Besides the
// object itself, a change to any binding on this node requeues the others, since
// it can change which of them owns a shared vip_xlat_table row.
//
// A binding binds only once its VRF advertises a prefix containing its backend
// address, and the attachment's advertisement can land after the binding. A
// BGPAdvertisement on this node's router therefore requeues this node's
// bindings, so one written first converges without waiting for an unrelated
// event. Advertisements buildBackendSIDIndex ignores are filtered out.
func (r *ServiceVIPBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.ServiceVIPBinding{}).
		Watches(&bgpv1alpha1.ServiceVIPBinding{}, handler.EnqueueRequestsFromMapFunc(r.nodePeerRequests)).
		Watches(&bgpv1alpha1.BGPAdvertisement{}, handler.EnqueueRequestsFromMapFunc(r.advertisementRequests),
			builder.WithPredicates(bindingAdvertisementPredicate())).
		Named("servicevipbinding").
		Complete(r)
}

// bindingAdvertisementPredicate passes BGPAdvertisement events that can change
// whether a binding's backend address is advertised: a create or delete of one
// buildBackendSIDIndex keeps, or a spec change where either side is kept.
func bindingAdvertisementPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool { return locatesBackend(e.Object) },
		DeleteFunc: func(e event.DeleteEvent) bool { return locatesBackend(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil ||
				e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration() {
				return false
			}
			return locatesBackend(e.ObjectOld) || locatesBackend(e.ObjectNew)
		},
		GenericFunc: func(e event.GenericEvent) bool { return locatesBackend(e.Object) },
	}
}

// advertisementRequests maps a BGPAdvertisement on this node's BGPRouter to
// every binding in its namespace that targets this node, including ones being
// deleted. An advertisement on another node's router maps to nothing.
func (r *ServiceVIPBindingReconciler) advertisementRequests(
	ctx context.Context, obj client.Object,
) []ctrlreconcile.Request {
	adv, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
	if !ok {
		return nil
	}
	logger := log.FromContext(ctx).WithValues("advertisement", client.ObjectKeyFromObject(adv))
	router := &bgpv1alpha1.BGPRouter{}
	key := client.ObjectKey{Namespace: adv.Namespace, Name: adv.Spec.RouterRef.Name}
	if err := r.Get(ctx, key, router); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "get BGPRouter to requeue ServiceVIPBindings", "router", key.Name)
		}
		return nil
	}
	if router.Spec.TargetRef.Name != r.NodeName {
		return nil
	}
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := r.List(ctx, list, client.InNamespace(adv.Namespace)); err != nil {
		logger.Error(err, "list ServiceVIPBindings to requeue")
		return nil
	}
	var reqs []ctrlreconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.TargetRef.Name == r.NodeName {
			reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return reqs
}

// nodePeerRequests maps a binding targeting this node to every other binding in
// its namespace that targets this node, including ones being deleted, which
// still need their finalizer handled.
func (r *ServiceVIPBindingReconciler) nodePeerRequests(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
	binding, ok := obj.(*bgpv1alpha1.ServiceVIPBinding)
	if !ok || binding.Spec.TargetRef.Name != r.NodeName {
		return nil
	}
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := r.List(ctx, list, client.InNamespace(binding.Namespace)); err != nil {
		log.FromContext(ctx).Error(err, "list ServiceVIPBindings to requeue peers", "binding", binding.Name)
		return nil
	}
	var reqs []ctrlreconcile.Request
	for i := range list.Items {
		peer := &list.Items[i]
		if peer.Name == binding.Name || peer.Spec.TargetRef.Name != r.NodeName {
			continue
		}
		reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(peer)})
	}
	return reqs
}
