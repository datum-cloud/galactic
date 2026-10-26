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
	"sort"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// bindingNodeLabel is set on every ServiceVIPBinding NetworkServiceBindingReconciler
// writes, to gatewayNodeLabelValue of the node it was written for, so each
// node lists only its own bindings.
const bindingNodeLabel = "galactic.datum.net/binding-node"

// bindingManagedByLabel and bindingManagedByValue mark a ServiceVIPBinding as
// generated. NetworkServiceBindingReconciler deletes only bindings carrying them,
// so it never removes one it did not write.
const (
	bindingManagedByLabel = "app.kubernetes.io/managed-by"
	bindingManagedByValue = "galactic-router"
)

// conditionTypeBackendsBound is the per-node NetworkService condition, as
// "<node>/BackendsBound", recording whether every binding node needs for the
// rule exists and reports Bound. Reasons are the reasonBindings* constants.
const conditionTypeBackendsBound = "BackendsBound"

// bindingTargetKind is the targetRef kind of every generated binding.
const bindingTargetKind = "Node"

const (
	// reasonBindingsBound: every backend of the rule on this node is bound.
	reasonBindingsBound = "Bound"

	// reasonBindingsPending: at least one binding is not Bound yet, or reports
	// why it cannot be.
	reasonBindingsPending = "BindingsNotBound"

	// reasonBindingsInvalid: the rule's spec cannot be built into bindings: a
	// second IPv6 VIP, a selector that does not parse, or a protocol or port
	// the datapath does not serve. Only nodes that serve the rule report it,
	// and they keep their bindings until the spec is fixed. A second IPv4 VIP
	// is reported the same way, but invalidates only the IPv4 family: the
	// IPv6 VIP's bindings are still kept current, and the IPv4 ones kept as
	// they are.
	reasonBindingsInvalid = "InvalidRule"

	// reasonBindingsClaimed: at least one backend the rule selects on this
	// node is served by an older rule on the same backend port, so it gets no
	// binding for this rule.
	reasonBindingsClaimed = "BackendsClaimed"
)

// NetworkServiceBindingReconciler writes, on its own node, the ServiceVIPBindings
// that a NetworkService's backends need: one per translated VIP per backend
// whose VPCAttachment reports this node. A rule has at most one IPv6 and one
// IPv4 VIP translated (ruleTranslatedVIPs). Workloads are IPv6 only, so both
// VIPs' backends are the selected attachments' IPv6 addresses, and an IPv4
// VIP's binding pairs the IPv4 VIP with an IPv6 backendAddress, which its node
// serves by translation. It runs in galactic-router on every node.
//
// The IPv4 VIP gets bindings only while some gateway node reports it loaded
// (ipv4LoadedOnSomeNode). Until then, and once no node does, it gets none and
// the node deletes the IPv4 bindings it wrote: an IPv4 binding rewrites every
// reply from its backend port to the VIP and sends it out the fabric uplink,
// and a veth binding also puts the VIP on the node, neither of which is right
// for a VIP no gateway serves.
//
// It is the only writer of generated bindings, and each node writes only its
// own, so gateway replicas never race and a gateway rollout never touches
// them. A binding is owned by its rule, so deleting the rule garbage-collects
// it, and the binding's own finalizer still lets ServiceVIPBindingReconciler
// remove its vip_xlat_table rows first. A backend that moves to another node,
// changes address, or stops matching the selector has its binding deleted
// here and a new one written by whichever node now hosts it. A rule whose
// spec cannot be built into bindings keeps the ones it has.
//
// The binding's egressKind comes from the attachment's interface mode, which
// is known before the backend's interface exists, and its vpcRef from the
// rule, which names the VRF the binding's rows go into. Both sides of the
// datapath derive the backend set from selectRuleBackends, and the binding's
// slot from its backend address and port, so the slot the gateway encodes and
// the row this node writes always agree.
//
// A backend's reply on a backend port can be translated back to only one VIP,
// so a backend serves only the oldest rule selecting it on that port and
// protocol (ruleBackendOwners). Every rule in the namespace is compared, the
// same set the gateways compare, so a rule that loses a backend gets no binding
// for it here and no flows for it from the gateways.
//
// The rule's "<node>/BackendsBound" condition summarizes this node's bindings,
// so a rule that is Programmed on the gateways but cannot reach a backend on
// some node says so on the rule itself.
type NetworkServiceBindingReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string

	// Namespace is the gateway namespace, where galactic-router's BGP objects
	// live: every binding for a rule in another namespace is written here,
	// beside the BGPRouter its rows resolve against. Empty writes each
	// rule's bindings in the rule's own namespace.
	Namespace string
}

// Reconcile converges this node's generated bindings for one NetworkService.
func (r *NetworkServiceBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rule := &bgpv1alpha1.NetworkService{}
	if err := r.Get(ctx, req.NamespacedName, rule); err != nil {
		if apierrors.IsNotFound(err) {
			// Owner references garbage-collect the bindings of a rule in
			// their own namespace. A tenant rule's cannot carry one, so this
			// node deletes its own.
			return ctrl.Result{}, r.deleteTenantBindings(ctx, req.NamespacedName)
		}
		return ctrl.Result{}, fmt.Errorf("get NetworkService %s: %w", req.NamespacedName, err)
	}
	if !rule.DeletionTimestamp.IsZero() {
		// The gateways keep serving a deleting rule until its routes are
		// withdrawn and drained, so its bindings stay until the rule is gone
		// and garbage collection removes them.
		return ctrl.Result{}, nil
	}

	if !meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		// Not accepted yet, or no longer: Accepted goes False whenever no
		// NetworkGateway exists in the namespace, which a delete and re-apply
		// of the gateways passes through. Deleting the bindings then would
		// remove every backend node's vip_xlat_table rows for a moment that
		// costs nothing to wait out, so existing bindings stay. The gateways
		// do not serve an unaccepted rule, so an idle binding draws no traffic.
		return ctrl.Result{}, nil
	}

	attachments, err := listVPCAttachmentsInVPC(ctx, r.Client, rule.Spec.VPCRef)
	if err != nil {
		return ctrl.Result{}, err
	}
	rules := &bgpv1alpha1.NetworkServiceList{}
	if err := r.List(ctx, rules); err != nil {
		return ctrl.Result{}, fmt.Errorf("list NetworkServices: %w", err)
	}
	owners := ruleBackendOwners(rules.Items, attachments, r.Namespace)
	desired, claimed, ipv4Err, buildErr := r.desiredBindings(rule, attachments, owners)
	if buildErr != nil {
		// The spec cannot be built into bindings: a second IPv6 VIP, a
		// selector that does not parse, or a protocol or port the datapath
		// does not serve. Deleting the bindings then would remove every
		// backend node's vip_xlat_table rows at once, while the gateways
		// still drain the rule's established flows toward them, so an edit
		// that is reverted minutes later would still have dropped every
		// connection. Existing bindings stay untouched until a valid spec
		// says otherwise, and the rule says why. A spec error does not heal
		// on retry, so none is requested: the fix bumps the generation,
		// which the predicate passes.
		existing, err := r.nodeBindings(ctx, rule)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := r.publishCondition(ctx, rule, nil, nil, buildErr, len(existing) > 0); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// A rule with a second IPv4 VIP keeps its IPv4 bindings as they are, for
	// the same reason an invalid spec keeps all of them, while its IPv6
	// bindings follow the spec.
	kept, err := r.applyBindings(ctx, rule, desired, ipv4Err != nil && ipv4LoadedOnSomeNode(rule))
	if err != nil {
		return ctrl.Result{}, err
	}
	if ipv4Err != nil {
		served := len(desired) > 0 || len(claimed) > 0 || kept > 0
		if err := r.publishCondition(ctx, rule, nil, nil, ipv4Err, served); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if err := r.publishCondition(ctx, rule, desired, claimed, nil, false); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// desiredBindings returns the bindings this node needs for rule: one for each
// translated VIP (ruleTranslatedVIPs) per selected backend of the VIP's family
// on this node that owners does not assign to another rule. It also returns the
// backends on this node it left out for that reason. A rule with no VIP of a
// family needs no bindings for it. A protocol or port the datapath does not
// serve (rulePorts), a second IPv6 VIP and a selector that does not parse are
// errors. A second IPv4 VIP is returned as ipv4Err, with the IPv6 VIP's
// bindings, since it invalidates the IPv4 family alone. The IPv4 VIP's
// bindings are left out unless a gateway node has it loaded.
func (r *NetworkServiceBindingReconciler) desiredBindings(
	rule *bgpv1alpha1.NetworkService, attachments []*cloudv1alpha1.VPCAttachment, owners backendOwners,
) (desired []*bgpv1alpha1.ServiceVIPBinding, claimed []claimedBackend, ipv4Err, err error) {
	if _, _, err := rulePorts(rule); err != nil {
		return nil, nil, nil, err
	}
	vips, err := ruleTranslatedVIPs(rule)
	if err != nil {
		return nil, nil, nil, err
	}
	ipv4Served := ipv4LoadedOnSomeNode(rule)
	for _, tv := range vips.valid() {
		if tv.family == familyIPv4 && !ipv4Served {
			continue
		}
		sel, err := selectRuleBackends(rule, attachments, owners, tv.family, r.Namespace)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, b := range sel.backends {
			if b.node == r.NodeName {
				desired = append(desired, r.newBinding(rule, tv.addr, b))
			}
		}
		for _, c := range sel.claimed {
			if c.node == r.NodeName {
				claimed = append(claimed, c)
			}
		}
	}
	return desired, claimed, vips.v4Err, nil
}

// newBinding builds the binding for one VIP and one backend on this node.
func (r *NetworkServiceBindingReconciler) newBinding(
	rule *bgpv1alpha1.NetworkService, vip netip.Addr, b ruleBackend,
) *bgpv1alpha1.ServiceVIPBinding {
	return generatedBinding(rule, r.Namespace, r.NodeName, vip, b)
}

// generatedBinding returns the binding node writes for rule's VIP vip and
// backend b, in objNS when rule is a tenant rule (generatedNamespace): its
// name, labels and spec. The gateway compares a binding against it before
// trusting its Bound condition.
func generatedBinding(
	rule *bgpv1alpha1.NetworkService, objNS, node string, vip netip.Addr, b ruleBackend,
) *bgpv1alpha1.ServiceVIPBinding {
	name := crdnames.ServiceVIPBindingName(rule.Name, node, vip.String(), b.addr.String(), int32(b.port))
	if ruleIsTenant(rule, objNS) {
		name = crdnames.TenantServiceVIPBindingName(
			rule.Namespace, rule.Name, node, vip.String(), b.addr.String(), int32(b.port))
	}
	l := ruleLabels(rule, objNS)
	l[bindingNodeLabel] = gatewayNodeLabelValue(node)
	l[bindingManagedByLabel] = bindingManagedByValue
	return &bgpv1alpha1.ServiceVIPBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: generatedNamespace(rule, objNS),
			Name:      name,
			Labels:    l,
		},
		Spec: bgpv1alpha1.ServiceVIPBindingSpec{
			TargetRef:      bgpv1alpha1.TargetRef{Kind: bindingTargetKind, Name: node},
			VPCRef:         rule.Spec.VPCRef,
			VIPAddress:     vip.String(),
			Port:           rule.Spec.Port,
			Protocol:       rule.Spec.Protocol,
			BackendAddress: b.addr.String(),
			BackendPort:    int32(b.port),
			EgressKind:     b.egressKind,
		},
	}
}

// applyBindings creates or updates every binding in desired and deletes this
// node's other generated bindings for rule. With keepIPv4, an existing binding
// of an IPv4 VIP is left as it is instead, and the count of those left is
// returned.
func (r *NetworkServiceBindingReconciler) applyBindings(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, desired []*bgpv1alpha1.ServiceVIPBinding, keepIPv4 bool,
) (kept int, err error) {
	keep := make(map[string]bool, len(desired))
	var errs []error
	for _, want := range desired {
		keep[want.Name] = true
		binding := &bgpv1alpha1.ServiceVIPBinding{ObjectMeta: metav1.ObjectMeta{
			Namespace: want.Namespace, Name: want.Name,
		}}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, binding, func() error {
			if binding.Labels == nil {
				binding.Labels = make(map[string]string, len(want.Labels))
			}
			for k, v := range want.Labels {
				binding.Labels[k] = v
			}
			binding.Spec = want.Spec
			// Not a controller reference, and not blocking owner deletion:
			// the binding's own finalizer orders its teardown.
			return setRuleOwner(rule, binding, r.Scheme)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("apply ServiceVIPBinding %s: %w", want.Name, err))
		}
	}

	existing, err := r.nodeBindings(ctx, rule)
	if err != nil {
		return 0, errors.Join(append(errs, err)...)
	}
	for i := range existing {
		binding := &existing[i]
		if keep[binding.Name] {
			continue
		}
		if keepIPv4 && bindingIsIPv4(binding) {
			kept++
			continue
		}
		if err := r.Delete(ctx, binding); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete stale ServiceVIPBinding %s: %w", binding.Name, err))
		}
	}
	return kept, errors.Join(errs...)
}

// bindingIsIPv4 reports whether binding's VIP is an IPv4 address, written
// plainly or IPv4-mapped.
func bindingIsIPv4(binding *bgpv1alpha1.ServiceVIPBinding) bool {
	vip, err := netip.ParseAddr(binding.Spec.VIPAddress)
	return err == nil && familyIPv4.has(vip)
}

// nodeBindings lists the generated bindings this node wrote for rule.
func (r *NetworkServiceBindingReconciler) nodeBindings(
	ctx context.Context, rule *bgpv1alpha1.NetworkService,
) ([]bgpv1alpha1.ServiceVIPBinding, error) {
	return r.keyBindings(ctx, client.ObjectKeyFromObject(rule))
}

// keyBindings lists the generated bindings this node wrote for the rule known
// by key.
func (r *NetworkServiceBindingReconciler) keyBindings(
	ctx context.Context, key client.ObjectKey,
) ([]bgpv1alpha1.ServiceVIPBinding, error) {
	objNS := r.Namespace
	if objNS == "" {
		objNS = key.Namespace
	}
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := r.List(ctx, list, ruleKeySelector(key, objNS, map[string]string{
		bindingNodeLabel:      gatewayNodeLabelValue(r.NodeName),
		bindingManagedByLabel: bindingManagedByValue,
	})); err != nil {
		return nil, fmt.Errorf("list ServiceVIPBindings for NetworkService %s: %w", key, err)
	}
	return list.Items, nil
}

// deleteTenantBindings deletes the generated bindings this node wrote for the
// deleted tenant rule known by key. A rule in the bindings' own namespace is
// left to garbage collection.
func (r *NetworkServiceBindingReconciler) deleteTenantBindings(ctx context.Context, key client.ObjectKey) error {
	if r.Namespace == "" || key.Namespace == r.Namespace {
		return nil
	}
	bindings, err := r.keyBindings(ctx, key)
	if err != nil {
		return err
	}
	var errs []error
	for i := range bindings {
		if err := r.Delete(ctx, &bindings[i]); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete ServiceVIPBinding %s of deleted NetworkService %s: %w",
				bindings[i].Name, key, err))
		}
	}
	return errors.Join(errs...)
}

// publishCondition sets this node's BackendsBound condition on rule, or removes
// it when the node hosts none of the rule's backends, so a rule's status names
// only the nodes that serve it. claimed are the backends on this node that
// another rule serves, which the condition reports as not bound, so a node
// holding only claimed backends still has a stake in the rule.
//
// An invalid rule is reported only by the nodes that serve it: those that
// hold bindings for it (served), which a build error leaves in place. Every
// other node stays silent. The gateways already report the error on the
// rule, and a condition from every router node would cost a status write per
// node per edit, each conflicting with the others.
func (r *NetworkServiceBindingReconciler) publishCondition(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, desired []*bgpv1alpha1.ServiceVIPBinding,
	claimed []claimedBackend, buildErr error, served bool,
) error {
	condType := backendsBoundConditionType(r.NodeName)
	stake := len(desired) > 0 || len(claimed) > 0
	if buildErr != nil {
		stake = served
	}
	if !stake {
		// A node with no condition writes nothing: updateRuleCondition
		// writes only a change.
		return r.updateRuleCondition(ctx, rule, func(conds *[]metav1.Condition) bool {
			return meta.RemoveStatusCondition(conds, condType)
		})
	}

	cond := metav1.Condition{Type: condType}
	switch {
	case buildErr != nil:
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonBindingsInvalid
		cond.Message = buildErr.Error()
	default:
		unbound, err := r.unboundBindings(ctx, rule, desired)
		if err != nil {
			return err
		}
		// Claimed backends lead the list: they stay unbound until the
		// owning rule lets them go, while the rest are usually transient.
		problems := make([]string, 0, len(claimed)+len(unbound))
		for _, c := range claimed {
			problems = append(problems, c.String())
		}
		problems = append(problems, unbound...)
		switch {
		case len(problems) == 0:
			cond.Status = metav1.ConditionTrue
			cond.Reason = reasonBindingsBound
			cond.Message = fmt.Sprintf("%d bindings bound on node %s", len(desired), r.NodeName)
		case len(claimed) > 0:
			cond.Status = metav1.ConditionFalse
			cond.Reason = reasonBindingsClaimed
			cond.Message = fmt.Sprintf("%d of %d backends on node %s not bound: %s",
				len(problems), len(desired)+len(claimed), r.NodeName, cappedList(problems))
		default:
			cond.Status = metav1.ConditionFalse
			cond.Reason = reasonBindingsPending
			cond.Message = fmt.Sprintf("%d of %d bindings on node %s not bound: %s",
				len(unbound), len(desired), r.NodeName, cappedList(unbound))
		}
	}
	return r.updateRuleCondition(ctx, rule, func(conds *[]metav1.Condition) bool {
		c := cond
		c.ObservedGeneration = rule.Generation
		return meta.SetStatusCondition(conds, c)
	})
}

// unboundBindings returns "vip -> backend: reason" for every desired binding
// that is not Bound yet, reading each one's current status.
func (r *NetworkServiceBindingReconciler) unboundBindings(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, desired []*bgpv1alpha1.ServiceVIPBinding,
) ([]string, error) {
	existing, err := r.nodeBindings(ctx, rule)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*bgpv1alpha1.ServiceVIPBinding, len(existing))
	for i := range existing {
		byName[existing[i].Name] = &existing[i]
	}

	var unbound []string
	for _, want := range desired {
		label := net.JoinHostPort(want.Spec.VIPAddress, strconv.Itoa(int(want.Spec.Port))) + " -> " +
			net.JoinHostPort(want.Spec.BackendAddress, strconv.Itoa(int(want.Spec.BackendPort)))
		got, ok := byName[want.Name]
		if !ok {
			unbound = append(unbound, label+": not created yet")
			continue
		}
		if reason := bindingUnboundReason(got); reason != "" {
			unbound = append(unbound, label+": "+reason)
		}
	}
	sort.Strings(unbound)
	return unbound, nil
}

// bindingUnboundReason returns why binding is not Bound for its current
// generation, "not reconciled yet" or its Bound condition's reason, or ""
// when it is Bound.
func bindingUnboundReason(binding *bgpv1alpha1.ServiceVIPBinding) string {
	bound := meta.FindStatusCondition(binding.Status.Conditions, bgpv1alpha1.ConditionTypeBound)
	switch {
	case bound == nil || bound.ObservedGeneration != binding.Generation:
		return "not reconciled yet"
	case bound.Status != metav1.ConditionTrue:
		return bound.Reason
	}
	return ""
}

// updateRuleCondition applies mutate to rule's current conditions and writes
// them only if mutate reports a change. Every status write fans out to every
// reconciler watching NetworkServices, so an unconditional write would never
// settle.
func (r *NetworkServiceBindingReconciler) updateRuleCondition(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, mutate func(*[]metav1.Condition) bool,
) error {
	key := client.ObjectKeyFromObject(rule)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkService{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		if !mutate(&current.Status.Conditions) {
			return nil
		}
		return r.Status().Update(ctx, current)
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("update %s condition on NetworkService %s: %w", conditionTypeBackendsBound, key, err)
	}
	return nil
}

// backendsBoundConditionType returns node's BackendsBound condition type. Rule
// status is shared by every node, so each node owns its own condition type and
// never overwrites another node's result.
func backendsBoundConditionType(node string) string {
	return node + "/" + conditionTypeBackendsBound
}

// SetupWithManager registers the NetworkServiceBindingReconciler with the manager.
func (r *NetworkServiceBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// A rule's bindings depend on its spec and on whether it is
		// Accepted. Other status writes, including this reconciler's own
		// conditions and the gateways' Programmed conditions, change neither.
		For(&bgpv1alpha1.NetworkService{}, builder.WithPredicates(ruleBindingInputsChanged())).
		// Rules in one VPC compete for backends, whatever their namespace, so
		// a rule appearing, going, or changing its spec can give another rule
		// a backend or take one away. Every rule in its VPC is re-queued; an
		// update maps both versions, so a rule moving VPC re-queues both.
		Watches(&bgpv1alpha1.NetworkService{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				rule, ok := obj.(*bgpv1alpha1.NetworkService)
				if !ok {
					return nil
				}
				return vpcRulesRequests(ctx, r.Client, rule.Spec.VPCRef)
			}),
			builder.WithPredicates(ruleBindingInputsChanged()),
		).
		// An attachment can enter or leave the selection only of rules in
		// its VPC, or move to or from this node, so only the rules whose
		// VPC is its observed VPC are re-queued. An update maps both the old
		// and the new object, so an attachment moving between VPCs
		// re-queues the rules of both. Updates that change nothing
		// ruleCandidateBackends reads are dropped. This also covers backend
		// ownership: rules compete for a backend only within its VPC, so
		// every rule an attachment change can give a backend to or take one
		// from is in that VPC and is re-queued here.
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return vpcRuleRequests(ctx, r.Client, obj)
			}),
			builder.WithPredicates(vpcAttachmentBackendChanged()),
		).
		// A binding's Bound condition feeds the rule's BackendsBound
		// condition, and a deleted binding must be rewritten.
		Watches(&bgpv1alpha1.ServiceVIPBinding{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []ctrlreconcile.Request {
				return r.bindingRuleRequests(obj)
			}),
		).
		Named("networkservice-binding").
		Complete(r)
}

// ruleBindingInputsChanged passes NetworkService events that can change the
// bindings it needs: a create or delete, a spec change, a change to its
// Accepted condition, or a change in whether some gateway node has its IPv4
// VIP loaded.
func ruleBindingInputsChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldRule, okOld := e.ObjectOld.(*bgpv1alpha1.NetworkService)
			newRule, okNew := e.ObjectNew.(*bgpv1alpha1.NetworkService)
			if !okOld || !okNew {
				return true
			}
			if oldRule.Generation != newRule.Generation {
				return true
			}
			return meta.IsStatusConditionTrue(oldRule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) !=
				meta.IsStatusConditionTrue(newRule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) ||
				ipv4LoadedOnSomeNode(oldRule) != ipv4LoadedOnSomeNode(newRule)
		},
	}
}

// vpcRuleRequests returns a reconcile request for every NetworkService whose VPC
// is obj's observed VPC, the only rules whose backends obj can be. An
// attachment with no observed VPC is no rule's candidate and maps to nothing.
func vpcRuleRequests(ctx context.Context, c client.Client, obj client.Object) []ctrlreconcile.Request {
	attachment, ok := obj.(*cloudv1alpha1.VPCAttachment)
	if !ok || attachment.Status.VPC == "" {
		return nil
	}
	return vpcRulesRequests(ctx, c, attachment.Status.VPC)
}

// vpcRulesRequests returns a reconcile request for every NetworkService whose
// VPC is vpc.
func vpcRulesRequests(ctx context.Context, c client.Client, vpc string) []ctrlreconcile.Request {
	list := &bgpv1alpha1.NetworkServiceList{}
	if err := c.List(ctx, list); err != nil {
		log.FromContext(ctx).Error(err, "list NetworkServices for change", "vpc", vpc)
		return nil
	}
	var reqs []ctrlreconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.VPCRef != vpc {
			continue
		}
		reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return reqs
}

// bindingRuleRequests maps a generated binding written for this node to its
// rule. Other nodes' bindings and hand-written ones map to nothing.
func (r *NetworkServiceBindingReconciler) bindingRuleRequests(obj client.Object) []ctrlreconcile.Request {
	labels := obj.GetLabels()
	if labels[bindingManagedByLabel] != bindingManagedByValue ||
		labels[bindingNodeLabel] != gatewayNodeLabelValue(r.NodeName) {
		return nil
	}
	key, ok := ruleKeyFromLabels(obj)
	if !ok {
		return nil
	}
	return []ctrlreconcile.Request{{NamespacedName: key}}
}
