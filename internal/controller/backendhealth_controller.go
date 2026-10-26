// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/healthprobe"
)

// BackendProber is the probe loop BackendHealthReconciler drives, satisfied
// by *healthprobe.Prober.
type BackendProber interface {
	Ensure(owner, id string, target healthprobe.Target, seed *healthprobe.Decision) healthprobe.Decision
	Release(owner string)
}

// BackendHealthReconciler publishes the health of every backend on its node
// whose NetworkService has a healthCheck. It runs in galactic-router on every
// node, next to the reconcilers that write and program the same
// ServiceVIPBindings.
//
// For each generated binding on its node it finds the VPCAttachment holding
// the binding's backend address, probes that backend through Prober, and
// writes the decision to the binding's status.health. Every binding of one
// backend shares one probe loop and carries the same decision. status.health
// is written only when the decision changes, with a merge patch of that field
// alone, so it never rewrites the Bound condition ServiceVIPBindingReconciler
// sets. This reconciler is the only writer of the field.
//
// A probe loop starts from the binding's published decision when it describes
// the same attachment and port, so a restarted galactic-router changes no
// gateway's table. A different attachment holding the address, a different
// port or different timing starts the backend over from Unknown. A rule with
// no healthCheck gets no probes, and its bindings' status.health is cleared.
type BackendHealthReconciler struct {
	client.Client
	NodeName string

	// Dial sends one probe; nil means healthprobe.Dial.
	Dial healthprobe.DialFunc

	// Prober overrides the probe loop, for tests. Nil means SetupWithManager
	// builds one around Dial.
	Prober BackendProber

	events chan event.GenericEvent
}

// Reconcile converges one binding's probe and status.health.
func (r *BackendHealthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	owner := req.String()
	binding := &bgpv1alpha1.ServiceVIPBinding{}
	if err := r.Get(ctx, req.NamespacedName, binding); err != nil {
		if apierrors.IsNotFound(err) {
			r.Prober.Release(owner)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get ServiceVIPBinding %s: %w", req.NamespacedName, err)
	}
	if !r.ownsBinding(binding) || !binding.DeletionTimestamp.IsZero() {
		r.Prober.Release(owner)
		return ctrl.Result{}, nil
	}

	rule := &bgpv1alpha1.NetworkService{}
	ruleKey, _ := ruleKeyFromLabels(binding)
	err := r.Get(ctx, ruleKey, rule)
	switch {
	case apierrors.IsNotFound(err):
		// Garbage collection is about to remove the binding.
		r.Prober.Release(owner)
		return ctrl.Result{}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get NetworkService for ServiceVIPBinding %s: %w", req.NamespacedName, err)
	}
	if rule.Spec.HealthCheck == nil {
		r.Prober.Release(owner)
		return ctrl.Result{}, r.publish(ctx, binding, nil)
	}

	attachment, err := r.backendAttachment(ctx, rule.Spec.VPCRef, binding.Spec.BackendAddress)
	if err != nil {
		return ctrl.Result{}, err
	}
	if attachment == nil {
		// No attachment on this node holds the address any more, so the
		// binding writer is about to delete the binding. A decision already
		// published names the old attachment, which readers check.
		r.Prober.Release(owner)
		return ctrl.Result{}, nil
	}

	target, err := healthTarget(rule, attachment, binding)
	if err != nil {
		// Only an address the API server already validated reaches here, so
		// this is not worth a retry.
		log.FromContext(ctx).Error(err, "skip health probe", "serviceVIPBinding", req.NamespacedName)
		r.Prober.Release(owner)
		return ctrl.Result{}, nil
	}
	id := healthTargetID(attachment.UID, target)
	decision := r.Prober.Ensure(owner, id, target, seedDecision(binding.Status.Health, attachment.UID, target.Port))
	return ctrl.Result{}, r.publish(ctx, binding, &bgpv1alpha1.ServiceVIPBindingHealth{
		State:              bgpv1alpha1.BackendHealthState(decision.State),
		Reason:             decision.Reason,
		Message:            truncateMessage(decision.Message),
		AttachmentUID:      attachment.UID,
		Port:               int32(target.Port),
		LastTransitionTime: metav1.NewTime(decision.Since.Truncate(time.Second)),
	})
}

// ownsBinding reports whether binding is a generated binding written for this
// node.
func (r *BackendHealthReconciler) ownsBinding(binding *bgpv1alpha1.ServiceVIPBinding) bool {
	return binding.Labels[bindingManagedByLabel] == bindingManagedByValue &&
		binding.Labels[bindingNodeLabel] == gatewayNodeLabelValue(r.NodeName) &&
		binding.Labels[networkRuleLabel] != "" &&
		binding.Spec.TargetRef.Name == r.NodeName
}

// backendAttachment returns the VPCAttachment on this node in vpc that holds
// address, or nil when none does.
func (r *BackendHealthReconciler) backendAttachment(
	ctx context.Context, vpc, address string,
) (*cloudv1alpha1.VPCAttachment, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return nil, nil //nolint:nilerr // an unparsable address belongs to no attachment
	}
	attachments, err := listVPCAttachmentsInVPC(ctx, r.Client, vpc)
	if err != nil {
		return nil, err
	}
	for _, a := range attachments {
		if a.Status.Node == r.NodeName && slices.Contains(attachmentIPv6Addresses(a), addr) {
			return a, nil
		}
	}
	return nil, nil
}

// publish writes health to binding's status.health when it differs from what
// the binding holds, nil clearing the field.
func (r *BackendHealthReconciler) publish(
	ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding, health *bgpv1alpha1.ServiceVIPBindingHealth,
) error {
	if healthEqual(binding.Status.Health, health) {
		return nil
	}
	base := binding.DeepCopy()
	binding.Status.Health = health
	if err := r.Status().Patch(ctx, binding, client.MergeFrom(base)); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("patch status.health of ServiceVIPBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}
	return nil
}

// healthEqual reports whether two published decisions are the same.
func healthEqual(a, b *bgpv1alpha1.ServiceVIPBindingHealth) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.State == b.State && a.Reason == b.Reason && a.Message == b.Message &&
		a.AttachmentUID == b.AttachmentUID && a.Port == b.Port &&
		a.LastTransitionTime.Equal(&b.LastTransitionTime)
}

// maxHealthMessage is status.health.message's maximum length in the CRD.
const maxHealthMessage = 1024

// truncateMessage keeps a probe error within status.health.message's limit.
func truncateMessage(msg string) string {
	if len(msg) <= maxHealthMessage {
		return msg
	}
	return msg[:maxHealthMessage]
}

// ruleHealthCheckPort returns the port rule's health check probes: its
// healthCheck.port, or its backendPort when that is unset. rule must have a
// healthCheck.
func ruleHealthCheckPort(rule *bgpv1alpha1.NetworkService) int32 {
	if rule.Spec.HealthCheck.Port != 0 {
		return rule.Spec.HealthCheck.Port
	}
	return rule.Spec.BackendPort
}

// healthTarget returns the probe target for binding's backend, held by
// attachment, under rule's healthCheck. Fields the API server defaults are
// read as their defaults if a client left them zero anyway.
func healthTarget(
	rule *bgpv1alpha1.NetworkService, attachment *cloudv1alpha1.VPCAttachment, binding *bgpv1alpha1.ServiceVIPBinding,
) (healthprobe.Target, error) {
	addr, err := netip.ParseAddr(binding.Spec.BackendAddress)
	if err != nil {
		return healthprobe.Target{}, fmt.Errorf("backendAddress %q: %w", binding.Spec.BackendAddress, err)
	}
	port := ruleHealthCheckPort(rule)
	if port < 1 || port > 65535 {
		return healthprobe.Target{}, fmt.Errorf("health check port %d is outside 1-65535", port)
	}
	hc := rule.Spec.HealthCheck
	orDefault := func(v, def int32) int32 {
		if v < 1 {
			return def
		}
		return v
	}
	return healthprobe.Target{
		Interface: attachment.Status.HostInterface,
		Addr:      addr,
		Port:      uint16(port),
		Config: healthprobe.Config{
			Interval:           time.Duration(orDefault(hc.IntervalSeconds, 5)) * time.Second,
			Timeout:            time.Duration(orDefault(hc.TimeoutSeconds, 2)) * time.Second,
			UnhealthyThreshold: int(orDefault(hc.UnhealthyThreshold, 3)),
			HealthyThreshold:   int(orDefault(hc.HealthyThreshold, 3)),
		},
	}, nil
}

// healthTargetID names target's probe loop. Everything that should start a
// backend's decision over is part of it: the attachment, the interface, the
// address, the port and the timing.
func healthTargetID(uid types.UID, t healthprobe.Target) string {
	return fmt.Sprintf("%s|%s|%s|%d|%s|%s|%d|%d", uid, t.Interface, t.Addr, t.Port,
		t.Config.Interval, t.Config.Timeout, t.Config.UnhealthyThreshold, t.Config.HealthyThreshold)
}

// seedDecision returns published as a starting decision when it describes the
// backend held by uid on port, and nil otherwise.
func seedDecision(published *bgpv1alpha1.ServiceVIPBindingHealth, uid types.UID, port uint16) *healthprobe.Decision {
	if published == nil || published.AttachmentUID != uid || published.Port != int32(port) {
		return nil
	}
	return &healthprobe.Decision{
		State:   healthprobe.State(published.State),
		Reason:  published.Reason,
		Message: published.Message,
		Since:   published.LastTransitionTime.Time,
	}
}

// SetupWithManager registers the reconciler, and the probe loop when Prober
// is nil, with the manager. The probe loops stop with the manager.
func (r *BackendHealthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.events = make(chan event.GenericEvent, 1024)
	if r.Prober == nil {
		dial := r.Dial
		if dial == nil {
			dial = healthprobe.Dial
		}
		ctx, cancel := context.WithCancel(context.Background())
		if err := mgr.Add(manager.RunnableFunc(func(stop context.Context) error {
			<-stop.Done()
			cancel()
			return nil
		})); err != nil {
			cancel()
			return fmt.Errorf("register backend health probe loops: %w", err)
		}
		r.Prober = healthprobe.NewProber(ctx, dial, func(owner string) { r.enqueue(ctx, owner) })
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.ServiceVIPBinding{}, builder.WithPredicates(predicate.NewPredicateFuncs(r.isNodeBinding))).
		// A rule gaining, losing or changing its healthCheck changes what its
		// bindings on this node probe.
		Watches(&bgpv1alpha1.NetworkService{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return r.ruleBindingRequests(ctx, obj)
			}),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// A new attachment holding a backend's address, or a new host-side
		// interface, starts the backend's probe over.
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return r.attachmentBindingRequests(ctx, obj)
			}),
			builder.WithPredicates(attachmentProbeTargetChanged()),
		).
		// A probe loop's decision changed.
		WatchesRawSource(source.Channel(r.events, &handler.EnqueueRequestForObject{})).
		Named("backend-health").
		Complete(r)
}

// enqueue asks for a reconcile of the binding named owner, "namespace/name".
func (r *BackendHealthReconciler) enqueue(ctx context.Context, owner string) {
	namespace, name, ok := strings.Cut(owner, "/")
	if !ok {
		return
	}
	select {
	case r.events <- event.GenericEvent{Object: &bgpv1alpha1.ServiceVIPBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
	}}:
	case <-ctx.Done():
	}
}

// isNodeBinding passes generated bindings written for this node.
func (r *BackendHealthReconciler) isNodeBinding(obj client.Object) bool {
	labels := obj.GetLabels()
	return labels[bindingManagedByLabel] == bindingManagedByValue &&
		labels[bindingNodeLabel] == gatewayNodeLabelValue(r.NodeName)
}

// nodeBindings lists the generated bindings written for this node, in
// namespace when it is not empty.
func (r *BackendHealthReconciler) nodeBindings(
	ctx context.Context, namespace string, extra client.MatchingLabels,
) ([]bgpv1alpha1.ServiceVIPBinding, error) {
	labels := client.MatchingLabels{
		bindingManagedByLabel: bindingManagedByValue,
		bindingNodeLabel:      gatewayNodeLabelValue(r.NodeName),
	}
	for k, v := range extra {
		labels[k] = v
	}
	opts := []client.ListOption{labels}
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := r.List(ctx, list, opts...); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// ruleBindingRequests maps a NetworkService to its bindings on this node.
func (r *BackendHealthReconciler) ruleBindingRequests(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
	bindings, err := r.nodeBindings(ctx, "", client.MatchingLabels{networkRuleLabel: obj.GetName()})
	if err != nil {
		log.FromContext(ctx).Error(err, "list ServiceVIPBindings for NetworkService change", "networkService", obj.GetName())
		return nil
	}
	key := client.ObjectKeyFromObject(obj)
	matched := bindings[:0]
	for i := range bindings {
		if k, ok := ruleKeyFromLabels(&bindings[i]); ok && k == key {
			matched = append(matched, bindings[i])
		}
	}
	return bindingRequests(matched)
}

// attachmentBindingRequests maps a VPCAttachment on this node to this node's
// bindings for any of its addresses.
func (r *BackendHealthReconciler) attachmentBindingRequests(
	ctx context.Context, obj client.Object,
) []ctrlreconcile.Request {
	attachment, ok := obj.(*cloudv1alpha1.VPCAttachment)
	if !ok || attachment.Status.Node != r.NodeName {
		return nil
	}
	addrs := attachmentIPv6Addresses(attachment)
	if len(addrs) == 0 {
		return nil
	}
	bindings, err := r.nodeBindings(ctx, "", nil)
	if err != nil {
		log.FromContext(ctx).Error(err, "list ServiceVIPBindings for VPCAttachment change",
			"vpcAttachment", client.ObjectKeyFromObject(obj))
		return nil
	}
	var matched []bgpv1alpha1.ServiceVIPBinding
	for _, b := range bindings {
		addr, err := netip.ParseAddr(b.Spec.BackendAddress)
		if err == nil && slices.Contains(addrs, addr) {
			matched = append(matched, b)
		}
	}
	return bindingRequests(matched)
}

func bindingRequests(bindings []bgpv1alpha1.ServiceVIPBinding) []ctrlreconcile.Request {
	reqs := make([]ctrlreconcile.Request, 0, len(bindings))
	for i := range bindings {
		reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(&bindings[i])})
	}
	return reqs
}

// attachmentProbeTargetChanged passes VPCAttachment events that can change a
// backend's probe target: every create, delete and generic event, and an
// update of the node, addresses or host-side interface.
func attachmentProbeTargetChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldAtt, okOld := e.ObjectOld.(*cloudv1alpha1.VPCAttachment)
			newAtt, okNew := e.ObjectNew.(*cloudv1alpha1.VPCAttachment)
			if !okOld || !okNew {
				return true
			}
			return oldAtt.Status.Node != newAtt.Status.Node ||
				oldAtt.Status.HostInterface != newAtt.Status.HostInterface ||
				!slices.Equal(oldAtt.Spec.Interface.Addresses, newAtt.Spec.Interface.Addresses)
		},
	}
}
