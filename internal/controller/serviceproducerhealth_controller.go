// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
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
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/healthprobe"
	"go.datum.net/galactic/internal/serviceroute"
)

// ServiceProducerHealthReconciler probes the producers on its node of every
// ServiceEndpoint whose distribution is Spread, and publishes their decisions
// in this node's ServiceEndpointProducerReport for the endpoint. It runs in
// galactic-router on every node, next to ServiceRoutePolicyReconciler, which
// reads those decisions to keep new flows off Unhealthy producers.
//
// Each node writes only its own report, so the size of any one object is
// bounded by the producers of one node, whatever the number of nodes. Each
// producer has one probe loop, started from the decision already published
// for the same attachment and port, so a restarted galactic-router changes no
// producer set. A producer with no IPv6 address cannot be probed and is
// published as Unknown. The node renews its entries every
// ServiceEndpointProducerReportRenewInterval, so other nodes stop routing on
// them once it is down or its galactic-router stops, and it removes any
// entries it still holds in the endpoint's status.producers.
type ServiceProducerHealthReconciler struct {
	client.Client
	NodeName string

	// Dial sends one probe; nil means healthprobe.Dial.
	Dial healthprobe.DialFunc

	// Prober overrides the probe loop, for tests. Nil means SetupWithManager
	// builds one around Dial.
	Prober BackendProber

	// Metrics counts this node's producers by state; nil disables it.
	Metrics *serviceroute.Metrics

	events chan event.GenericEvent

	mu sync.Mutex
	// owners holds each endpoint's probe owners, and states each owner's
	// last published state.
	owners map[types.NamespacedName]map[string]bool
	states map[string]networkv1alpha1.BackendHealthState
}

// Reconcile converges one endpoint's probes and this node's entries in its
// status.producers.
func (r *ServiceProducerHealthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	endpoint := &networkv1alpha1.ServiceEndpoint{}
	if err := r.Get(ctx, req.NamespacedName, endpoint); err != nil {
		if apierrors.IsNotFound(err) {
			r.releaseExcept(req.NamespacedName, nil)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get ServiceEndpoint %s: %w", req.NamespacedName, err)
	}
	if endpoint.Spec.Distribution != networkv1alpha1.ServiceEndpointDistributionSpread ||
		endpoint.Spec.HealthCheck == nil || !endpoint.DeletionTimestamp.IsZero() {
		r.releaseExcept(req.NamespacedName, nil)
		return r.publish(ctx, endpoint, nil, time.Now())
	}
	report, err := r.ownReport(ctx, endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}

	list := &cloudv1alpha1.VPCAttachmentList{}
	if err := r.List(ctx, list); err != nil {
		return ctrl.Result{}, fmt.Errorf("list VPCAttachments: %w", err)
	}
	attachments := make([]*cloudv1alpha1.VPCAttachment, 0, len(list.Items))
	for i := range list.Items {
		attachments = append(attachments, &list.Items[i])
	}
	producers, err := serviceroute.Producers(endpoint, attachments)
	if err != nil {
		// The policy controller reports an invalid endpoint; there is
		// nothing to probe.
		r.releaseExcept(req.NamespacedName, nil)
		return r.publish(ctx, endpoint, nil, time.Now())
	}

	// Decisions this node published before, in the endpoint's status by a
	// router that predates reports, or in its report, seed the probes.
	published := make(map[types.NamespacedName]networkv1alpha1.ServiceEndpointProducerStatus)
	for _, entry := range endpoint.Status.Producers {
		if entry.Node == r.NodeName {
			published[types.NamespacedName{Namespace: entry.Namespace, Name: entry.Name}] = entry
		}
	}
	if report != nil {
		for _, entry := range report.Spec.Producers {
			published[types.NamespacedName{Namespace: entry.Namespace, Name: entry.Name}] = entry
		}
	}
	port := producerHealthCheckPort(endpoint)
	wanted := make(map[string]bool)
	var entries []networkv1alpha1.ServiceEndpointProducerStatus
	for _, producer := range producers {
		if producer.Status.Node != r.NodeName {
			continue
		}
		key := types.NamespacedName{Namespace: producer.Namespace, Name: producer.Name}
		entry := networkv1alpha1.ServiceEndpointProducerStatus{
			Namespace: producer.Namespace, Name: producer.Name, AttachmentUID: producer.UID,
			Node: r.NodeName, Port: port,
		}
		target, ok := producerHealthTarget(endpoint, producer)
		if !ok {
			entry.State = networkv1alpha1.BackendHealthUnknown
			entry.Reason = healthprobe.ReasonProbeUnavailable
			entry.Message = "attachment has no IPv6 address to probe"
			entry.LastTransitionTime = keepTransition(published[key], entry, metav1.Now())
			entries = append(entries, entry)
			continue
		}
		owner := producerProbeOwner(req.NamespacedName, key)
		wanted[owner] = true
		decision := r.Prober.Ensure(owner, healthTargetID(producer.UID, target), target,
			seedProducerDecision(published[key], producer.UID, port))
		entry.State = networkv1alpha1.BackendHealthState(decision.State)
		entry.Reason = decision.Reason
		entry.Message = truncateMessage(decision.Message)
		entry.LastTransitionTime = metav1.NewTime(decision.Since.Truncate(time.Second))
		entries = append(entries, entry)
	}
	r.track(req.NamespacedName, wanted, entries)
	// A node with producers reconciles every renew interval, so it sweeps
	// regularly; one without has nothing to renew and does not.
	if len(entries) != 0 {
		if err := r.sweepReports(ctx, endpoint, time.Now()); err != nil {
			return ctrl.Result{}, err
		}
	}
	return r.publish(ctx, endpoint, entries, time.Now())
}

// producerHealthCheckPort returns the port endpoint's healthCheck probes: its
// port, or the endpoint's port when that is unset.
func producerHealthCheckPort(endpoint *networkv1alpha1.ServiceEndpoint) int32 {
	if endpoint.Spec.HealthCheck.Port != 0 {
		return endpoint.Spec.HealthCheck.Port
	}
	return endpoint.Spec.Port
}

// producerHealthTarget returns the probe target of producer under endpoint's
// healthCheck: the attachment's first IPv6 interface address, or its pod
// subnet's address, over its host-side interface. It reports false when the
// attachment has neither. Fields the API server defaults are read as their
// defaults if a client left them zero anyway.
func producerHealthTarget(
	endpoint *networkv1alpha1.ServiceEndpoint, producer *cloudv1alpha1.VPCAttachment,
) (healthprobe.Target, bool) {
	var addr netip.Addr
	if addrs := attachmentIPv6Addresses(producer); len(addrs) != 0 {
		addr = addrs[0]
	} else if ip, _, err := net.ParseCIDR(producer.Status.PodSubnet); err == nil && ip.To4() == nil {
		addr, _ = netip.AddrFromSlice(ip.To16())
	}
	port := producerHealthCheckPort(endpoint)
	if !addr.IsValid() || port < 1 || port > 65535 {
		return healthprobe.Target{}, false
	}
	hc := endpoint.Spec.HealthCheck
	orDefault := func(v, def int32) int32 {
		if v < 1 {
			return def
		}
		return v
	}
	return healthprobe.Target{
		Interface: producer.Status.HostInterface,
		Addr:      addr,
		Port:      uint16(port),
		Config: healthprobe.Config{
			Interval:           time.Duration(orDefault(hc.IntervalSeconds, 5)) * time.Second,
			Timeout:            time.Duration(orDefault(hc.TimeoutSeconds, 2)) * time.Second,
			UnhealthyThreshold: int(orDefault(hc.UnhealthyThreshold, 3)),
			HealthyThreshold:   int(orDefault(hc.HealthyThreshold, 3)),
		},
	}, true
}

// seedProducerDecision returns published as a starting decision when it
// describes the producer held by uid on port, and nil otherwise.
func seedProducerDecision(published networkv1alpha1.ServiceEndpointProducerStatus, uid types.UID,
	port int32,
) *healthprobe.Decision {
	if published.AttachmentUID != uid || published.Port != port || published.State == "" {
		return nil
	}
	return &healthprobe.Decision{
		State:   healthprobe.State(published.State),
		Reason:  published.Reason,
		Message: published.Message,
		Since:   published.LastTransitionTime.Time,
	}
}

// keepTransition returns the published entry's transition time when it holds
// the same decision for the same attachment, and now otherwise.
func keepTransition(published, entry networkv1alpha1.ServiceEndpointProducerStatus, now metav1.Time) metav1.Time {
	if published.AttachmentUID == entry.AttachmentUID && published.State == entry.State &&
		published.Reason == entry.Reason {
		return published.LastTransitionTime
	}
	return metav1.NewTime(now.Truncate(time.Second))
}

// producerProbeOwner names one producer's probe loop. Its first part,
// "namespace/name" of the endpoint, is what enqueue reconciles.
func producerProbeOwner(endpoint, producer types.NamespacedName) string {
	return endpoint.String() + "|" + producer.String()
}

// releaseExcept stops every probe of endpoint whose owner is not in keep.
func (r *ServiceProducerHealthReconciler) releaseExcept(endpoint types.NamespacedName, keep map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owners == nil {
		r.owners = make(map[types.NamespacedName]map[string]bool)
		r.states = make(map[string]networkv1alpha1.BackendHealthState)
	}
	for owner := range r.owners[endpoint] {
		if !keep[owner] {
			r.Prober.Release(owner)
			delete(r.owners[endpoint], owner)
		}
	}
	if len(r.owners[endpoint]) == 0 {
		delete(r.owners, endpoint)
	}
	r.recordStatesLocked(endpoint, nil)
}

// track releases endpoint's probes that are no longer wanted, records the
// probes that are, and updates the state counts from entries.
func (r *ServiceProducerHealthReconciler) track(endpoint types.NamespacedName, wanted map[string]bool,
	entries []networkv1alpha1.ServiceEndpointProducerStatus,
) {
	r.releaseExcept(endpoint, wanted)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(wanted) != 0 {
		if r.owners[endpoint] == nil {
			r.owners[endpoint] = make(map[string]bool, len(wanted))
		}
		for owner := range wanted {
			r.owners[endpoint][owner] = true
		}
	}
	r.recordStatesLocked(endpoint, entries)
}

// recordStatesLocked replaces endpoint's producer states with entries and
// exports the node's counts.
func (r *ServiceProducerHealthReconciler) recordStatesLocked(endpoint types.NamespacedName,
	entries []networkv1alpha1.ServiceEndpointProducerStatus,
) {
	prefix := endpoint.String() + "|"
	for key := range r.states {
		if strings.HasPrefix(key, prefix) {
			delete(r.states, key)
		}
	}
	for _, entry := range entries {
		r.states[producerProbeOwner(endpoint, types.NamespacedName{Namespace: entry.Namespace, Name: entry.Name})] =
			entry.State
	}
	counts := make(map[string]int)
	for _, state := range r.states {
		counts[string(state)]++
	}
	r.Metrics.SetProducers(counts)
}

// ownReport returns this node's report for endpoint, or nil when there is
// none. A report left by an earlier endpoint of the same name is deleted and
// reported as none, since its endpointUID cannot change.
func (r *ServiceProducerHealthReconciler) ownReport(ctx context.Context,
	endpoint *networkv1alpha1.ServiceEndpoint,
) (*networkv1alpha1.ServiceEndpointProducerReport, error) {
	report := &networkv1alpha1.ServiceEndpointProducerReport{}
	key := types.NamespacedName{Namespace: endpoint.Namespace, Name: producerReportName(endpoint.Name, r.NodeName)}
	if err := r.Get(ctx, key, report); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get ServiceEndpointProducerReport %s: %w", key, err)
	}
	if report.Spec.EndpointUID == endpoint.UID && report.Spec.Node == r.NodeName {
		return report, nil
	}
	if err := r.deleteReport(ctx, report, false); err != nil {
		return nil, err
	}
	return nil, nil
}

// sweepReports deletes endpoint's reports from other nodes whose newest entry
// was last renewed more than ServiceEndpointProducerReportRetention before
// now, because their node is gone. A report with no renewed entry counts from
// its creation.
func (r *ServiceProducerHealthReconciler) sweepReports(ctx context.Context,
	endpoint *networkv1alpha1.ServiceEndpoint, now time.Time,
) error {
	list := &networkv1alpha1.ServiceEndpointProducerReportList{}
	if err := r.List(ctx, list, client.InNamespace(endpoint.Namespace)); err != nil {
		return fmt.Errorf("list ServiceEndpointProducerReports in %s: %w", endpoint.Namespace, err)
	}
	for i := range list.Items {
		report := &list.Items[i]
		if report.Spec.EndpointName != endpoint.Name || report.Spec.Node == r.NodeName {
			continue
		}
		var last time.Time
		for _, entry := range report.Spec.Producers {
			if entry.RenewTime != nil && entry.RenewTime.After(last) {
				last = entry.RenewTime.Time
			}
		}
		if last.IsZero() {
			last = report.CreationTimestamp.Time
		}
		if now.Sub(last) <= networkv1alpha1.ServiceEndpointProducerReportRetention {
			continue
		}
		if err := r.deleteReport(ctx, report, true); err != nil {
			return err
		}
	}
	return nil
}

// deleteReport deletes report, and succeeds when it is already gone. With
// unchanged, it deletes the report only as read and also succeeds when it has
// changed since, so a node that renewed another node's report in between
// keeps it; this node's own report is deleted whatever its version.
func (r *ServiceProducerHealthReconciler) deleteReport(ctx context.Context,
	report *networkv1alpha1.ServiceEndpointProducerReport, unchanged bool,
) error {
	preconditions := client.Preconditions{UID: &report.UID}
	if unchanged {
		preconditions.ResourceVersion = &report.ResourceVersion
	}
	err := r.Delete(ctx, report, preconditions)
	if err == nil || apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	return fmt.Errorf("delete ServiceEndpointProducerReport %s/%s: %w", report.Namespace, report.Name, err)
}

// publish makes entries, each renewed at now, this node's report for
// endpoint, unless the report already holds them and all were renewed within
// the renew interval. With no entries it deletes the report. It then removes
// this node's entries from the endpoint's status.producers, only once the
// report holds their replacements, so readers never lose a decision in
// between. It requeues for the next renewal while entries is not empty.
func (r *ServiceProducerHealthReconciler) publish(ctx context.Context, endpoint *networkv1alpha1.ServiceEndpoint,
	entries []networkv1alpha1.ServiceEndpointProducerStatus, now time.Time,
) (ctrl.Result, error) {
	report, err := r.ownReport(ctx, endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(entries) == 0 {
		if report != nil {
			if err := r.deleteReport(ctx, report, false); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, r.clearStatusEntries(ctx, endpoint)
	}
	var current []networkv1alpha1.ServiceEndpointProducerStatus
	if report != nil {
		current = append(current, report.Spec.Producers...)
	}
	sortProducerEntries(current)
	sortProducerEntries(entries)
	renewIn := networkv1alpha1.ServiceEndpointProducerReportRenewInterval
	if producerEntriesEqual(current, entries) {
		if age, ok := oldestRenewal(current, now); ok && age < renewIn {
			return ctrl.Result{RequeueAfter: max(renewIn-age, time.Second)}, r.clearStatusEntries(ctx, endpoint)
		}
	}
	renewed := metav1.NewTime(now.Truncate(time.Second))
	for i := range entries {
		entries[i].RenewTime = &renewed
	}
	name := producerReportName(endpoint.Name, r.NodeName)
	body, err := applyBody("ServiceEndpointProducerReport", endpoint.Namespace, name,
		[]metav1.OwnerReference{{
			APIVersion: networkv1alpha1.GroupVersion.String(), Kind: "ServiceEndpoint",
			Name: endpoint.Name, UID: endpoint.UID,
		}},
		"spec", networkv1alpha1.ServiceEndpointProducerReportSpec{
			EndpointName: endpoint.Name, EndpointUID: endpoint.UID, Node: r.NodeName, Producers: entries,
		})
	if err != nil {
		return ctrl.Result{}, err
	}
	obj := &networkv1alpha1.ServiceEndpointProducerReport{}
	obj.Name, obj.Namespace = name, endpoint.Namespace
	if err := r.Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, body),
		client.FieldOwner(nodeFieldOwner(r.NodeName)), client.ForceOwnership); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply ServiceEndpointProducerReport %s/%s: %w",
			endpoint.Namespace, name, err)
	}
	return ctrl.Result{RequeueAfter: renewIn}, r.clearStatusEntries(ctx, endpoint)
}

// clearStatusEntries removes the entries this node holds in endpoint's
// status.producers, written by a galactic-router that predates reports, by
// applying an empty list under the field manager that wrote them.
func (r *ServiceProducerHealthReconciler) clearStatusEntries(ctx context.Context,
	endpoint *networkv1alpha1.ServiceEndpoint,
) error {
	held := false
	for _, entry := range endpoint.Status.Producers {
		held = held || entry.Node == r.NodeName
	}
	if !held {
		return nil
	}
	body, err := statusProducersApplyBody(endpoint.Namespace, endpoint.Name, nil)
	if err != nil {
		return err
	}
	obj := &networkv1alpha1.ServiceEndpoint{}
	obj.Name, obj.Namespace = endpoint.Name, endpoint.Namespace
	err = r.Status().Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, body),
		client.FieldOwner(nodeFieldOwner(r.NodeName)), client.ForceOwnership)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("remove status.producers entries of ServiceEndpoint %s/%s: %w",
			endpoint.Namespace, endpoint.Name, err)
	}
	return nil
}

// applyBody returns a server-side apply body for the galactic API object of
// kind called name in namespace, with owners and with value as its field.
func applyBody(kind, namespace, name string, owners []metav1.OwnerReference, field string, value any) ([]byte, error) {
	meta := map[string]any{"name": name, "namespace": namespace}
	if len(owners) != 0 {
		meta["ownerReferences"] = owners
	}
	return json.Marshal(map[string]any{
		"apiVersion": networkv1alpha1.GroupVersion.String(), "kind": kind, "metadata": meta, field: value,
	})
}

// statusProducersApplyBody returns a server-side apply body that sets the
// status.producers of the named ServiceEndpoint to entries.
func statusProducersApplyBody(namespace, name string,
	entries []networkv1alpha1.ServiceEndpointProducerStatus,
) ([]byte, error) {
	if entries == nil {
		entries = []networkv1alpha1.ServiceEndpointProducerStatus{}
	}
	return applyBody("ServiceEndpoint", namespace, name, nil, "status", map[string]any{"producers": entries})
}

// producerReportName names node's report for the endpoint called endpoint: the
// endpoint name, cut to fit, and a hash of both names, so two nodes or two
// endpoints never share a report.
func producerReportName(endpoint, node string) string {
	sum := sha256.Sum256([]byte(endpoint + "\x00" + node))
	prefix := strings.TrimRight(endpoint[:min(len(endpoint), 253-17)], ".-")
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

// oldestRenewal returns the age at now of the least recently renewed entry,
// and false when an entry was never renewed.
func oldestRenewal(entries []networkv1alpha1.ServiceEndpointProducerStatus, now time.Time) (time.Duration, bool) {
	var oldest time.Duration
	for _, entry := range entries {
		if entry.RenewTime == nil {
			return 0, false
		}
		oldest = max(oldest, now.Sub(entry.RenewTime.Time))
	}
	return oldest, true
}

func sortProducerEntries(entries []networkv1alpha1.ServiceEndpointProducerStatus) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Namespace != entries[j].Namespace {
			return entries[i].Namespace < entries[j].Namespace
		}
		return entries[i].Name < entries[j].Name
	})
}

func producerEntriesEqual(a, b []networkv1alpha1.ServiceEndpointProducerStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Namespace != y.Namespace || x.Name != y.Name || x.AttachmentUID != y.AttachmentUID ||
			x.Node != y.Node || x.Port != y.Port || x.State != y.State || x.Reason != y.Reason ||
			x.Message != y.Message || !x.LastTransitionTime.Equal(&y.LastTransitionTime) {
			return false
		}
	}
	return true
}

// SetupWithManager registers the reconciler, and the probe loop when Prober
// is nil, with the manager. The probe loops stop with the manager.
func (r *ServiceProducerHealthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.events = make(chan event.GenericEvent, 1024)
	r.owners = make(map[types.NamespacedName]map[string]bool)
	r.states = make(map[string]networkv1alpha1.BackendHealthState)
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
			return fmt.Errorf("register service producer probe loops: %w", err)
		}
		r.Prober = healthprobe.NewProber(ctx, dial, func(owner string) { r.enqueue(ctx, owner) })
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Status writes, this node's included, change no probe.
		For(&networkv1alpha1.ServiceEndpoint{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A producer arriving on, leaving or changing on this node changes
		// what it probes.
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(r.spreadEndpoints),
			builder.WithPredicates(r.attachmentOnNode())).
		// A probe loop's decision changed.
		WatchesRawSource(source.Channel(r.events, &handler.EnqueueRequestForObject{})).
		Named("service-producer-health").
		Complete(r)
}

// enqueue asks for a reconcile of the endpoint whose probe owner changed.
func (r *ServiceProducerHealthReconciler) enqueue(ctx context.Context, owner string) {
	endpoint, _, _ := strings.Cut(owner, "|")
	namespace, name, ok := strings.Cut(endpoint, "/")
	if !ok {
		return
	}
	select {
	case r.events <- event.GenericEvent{Object: &networkv1alpha1.ServiceEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
	}}:
	case <-ctx.Done():
	}
}

// spreadEndpoints maps any attachment event to every Spread endpoint.
func (r *ServiceProducerHealthReconciler) spreadEndpoints(
	ctx context.Context, _ client.Object,
) []ctrlreconcile.Request {
	list := &networkv1alpha1.ServiceEndpointList{}
	if err := r.List(ctx, list); err != nil {
		log.FromContext(ctx).Error(err, "list ServiceEndpoints for VPCAttachment change")
		return nil
	}
	var reqs []ctrlreconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.Distribution == networkv1alpha1.ServiceEndpointDistributionSpread {
			reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return reqs
}

// attachmentOnNode passes events of attachments that are, or were, on this
// node.
func (r *ServiceProducerHealthReconciler) attachmentOnNode() predicate.Predicate {
	onNode := func(obj client.Object) bool {
		attachment, ok := obj.(*cloudv1alpha1.VPCAttachment)
		return ok && attachment.Status.Node == r.NodeName
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return onNode(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return onNode(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return onNode(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return onNode(e.ObjectOld) || onNode(e.ObjectNew)
		},
	}
}

// nodeFieldOwner is this node's server-side apply field manager, within the
// 128-byte limit for any node name.
func nodeFieldOwner(node string) string {
	owner := "galactic-router/" + node
	if len(owner) <= 128 {
		return owner
	}
	sum := sha256.Sum256([]byte(node))
	return "galactic-router/" + node[:64] + "-" + hex.EncodeToString(sum[:8])
}
