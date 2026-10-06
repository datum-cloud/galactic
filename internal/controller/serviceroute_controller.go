// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/serviceroute"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const reconcileResultError = "error"

// ServiceRoutePolicyReconciler resolves service policies against local Cloud
// API attachments and programs the resulting stateful eBPF forwarding policy
// directly on this node. It intentionally does not create child Kubernetes
// resources or Linux routes.
type ServiceRoutePolicyReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	NodeName     string
	BGPNamespace string
	Programmer   serviceroute.RouteProgrammer
	Metrics      *serviceroute.Metrics

	mu      sync.Mutex
	Applied map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent
}

const serviceRouteMapResyncInterval = 30 * time.Second

type serviceRouteStartupSyncError struct {
	err   error
	retry bool
}

type serviceRoutePolicyCleanupError struct{ err error }

func (e *serviceRoutePolicyCleanupError) Error() string { return e.err.Error() }
func (e *serviceRoutePolicyCleanupError) Unwrap() error { return e.err }

func isServiceRoutePolicyCleanupError(err error) bool {
	var cleanupErr *serviceRoutePolicyCleanupError
	return errors.As(err, &cleanupErr)
}

func (e *serviceRouteStartupSyncError) Error() string { return e.err.Error() }
func (e *serviceRouteStartupSyncError) Unwrap() error { return e.err }

func startupSyncError(err error, retry bool) error {
	if err == nil {
		return nil
	}
	return &serviceRouteStartupSyncError{err: err, retry: retry}
}

func startupSyncNeedsRetry(err error) bool {
	var syncErr *serviceRouteStartupSyncError
	return !errors.As(err, &syncErr) || syncErr.retry
}

// Reconcile resolves one policy and replaces the local routes previously
// programmed for that policy.
func (r *ServiceRoutePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	resultLabel := "success"
	defer func() { r.Metrics.ObserveReconcile(resultLabel, time.Since(start)) }()
	logger := log.FromContext(ctx).WithValues("policy", req.String(), "node", r.NodeName)

	r.mu.Lock()
	defer r.mu.Unlock()

	policy := &networkv1alpha1.ServiceRoutePolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			err := r.removePolicyLocked(req.NamespacedName)
			if err != nil {
				resultLabel = reconcileResultError
				logger.Error(err, "remove eBPF policy for deleted ServiceRoutePolicy")
			}
			return ctrl.Result{}, err
		}
		resultLabel = reconcileResultError
		logger.Error(err, "get ServiceRoutePolicy")
		return ctrl.Result{}, err
	}
	endpoint := &networkv1alpha1.ServiceEndpoint{}
	endpointKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Spec.ServiceRef.Name}
	if err := r.Get(ctx, endpointKey, endpoint); err != nil {
		if apierrors.IsNotFound(err) {
			joined := errors.Join(
				r.replacePolicyLocked(req.NamespacedName, nil),
				r.setAccepted(ctx, policy, metav1.ConditionFalse, "EndpointNotFound", "referenced ServiceEndpoint does not exist"),
			)
			if joined != nil {
				resultLabel = reconcileResultError
				logger.Error(joined, "revoke eBPF policy for missing ServiceEndpoint")
			}
			return ctrl.Result{}, joined
		}
		resultLabel = reconcileResultError
		logger.Error(err, "get ServiceEndpoint", "endpoint", policy.Spec.ServiceRef.Name)
		return ctrl.Result{}, fmt.Errorf("get ServiceEndpoint %s/%s: %w", policy.Namespace, policy.Spec.ServiceRef.Name, err)
	}
	attachments := &cloudv1alpha1.VPCAttachmentList{}
	if err := r.List(ctx, attachments); err != nil {
		resultLabel = reconcileResultError
		logger.Error(err, "list VPCAttachments")
		return ctrl.Result{}, fmt.Errorf("list VPCAttachments: %w", err)
	}
	all := make([]*cloudv1alpha1.VPCAttachment, 0, len(attachments.Items))
	for i := range attachments.Items {
		all = append(all, &attachments.Items[i])
	}
	intents, err := serviceroute.Compile(policy, endpoint, all, r.NodeName, r.sidResolver(ctx))
	if err != nil {
		var dependencyErr *serviceroute.DependencyNotReadyError
		if errors.As(err, &dependencyErr) {
			// Accepted describes the shared policy contract. SID readiness is a
			// node-local dependency, so publishing Invalid here would race with
			// uninvolved nodes that correctly compile no local intents. Revoke
			// this node's stale state and return the error for controller-runtime
			// to retry while leaving the policy accepted cluster-wide.
			joined := errors.Join(
				err,
				r.removePolicyLocked(req.NamespacedName),
				r.setAccepted(ctx, policy, metav1.ConditionTrue, "Accepted", "policy is valid"),
			)
			resultLabel = reconcileResultError
			logger.Error(joined, "resolve service routing dependency", "endpoint", endpoint.Name)
			return ctrl.Result{}, joined
		}
		joined := errors.Join(
			err,
			r.removePolicyLocked(req.NamespacedName),
			r.setAccepted(ctx, policy, metav1.ConditionFalse, "Invalid", err.Error()),
		)
		resultLabel = reconcileResultError
		logger.Error(joined, "compile service eBPF policy", "endpoint", endpoint.Name)
		return ctrl.Result{}, joined
	}
	if len(intents) != 0 {
		// The datapath loader may replace an incompatible pinned map while this
		// controller process stays alive. Initialize detects the map identity
		// change and reconstructs all desired state before an unchanged intent
		// is otherwise skipped by replacePolicy.
		if err := r.Programmer.Initialize(); err != nil {
			resultLabel = reconcileResultError
			logger.Error(err, "refresh service route maps", "endpoint", endpoint.Name)
			return ctrl.Result{}, fmt.Errorf("refresh service route maps: %w", err)
		}
	}
	logger.Info("compiled service eBPF policy", "endpoint", endpoint.Name, "attachments", len(intents))
	if err := r.replacePolicyLocked(req.NamespacedName, intents); err != nil {
		resultLabel = reconcileResultError
		logger.Error(err, "program service eBPF policy", "endpoint", endpoint.Name)
		return ctrl.Result{}, err
	}
	if err := r.setAccepted(ctx, policy, metav1.ConditionTrue, "Accepted", "policy is valid"); err != nil {
		resultLabel = reconcileResultError
		logger.Error(err, "update ServiceRoutePolicy acceptance status")
		return ctrl.Result{}, err
	}
	requeue := ctrl.Result{}
	if len(intents) != 0 {
		requeue.RequeueAfter = serviceRouteMapResyncInterval
	}
	return requeue, nil
}

func (r *ServiceRoutePolicyReconciler) setAccepted(
	ctx context.Context,
	policy *networkv1alpha1.ServiceRoutePolicy,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	before := policy.Status.DeepCopy()
	policy.Status.ObservedGeneration = policy.Generation
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               networkv1alpha1.ConditionTypeServiceRouteAccepted,
		Status:             status,
		ObservedGeneration: policy.Generation,
		Reason:             reason,
		Message:            message,
	})
	if reflect.DeepEqual(before, &policy.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, policy); err != nil {
		return fmt.Errorf("update ServiceRoutePolicy status: %w", err)
	}
	return nil
}

// SetupWithManager watches policies, endpoints, and attachments. Events from
// either backing API requeue matching policies so status.node moves and service
// endpoint changes converge without child resources.
func (r *ServiceRoutePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return nil
		}
		return r.runStartupSync(ctx)
	})); err != nil {
		return fmt.Errorf("add initial service route policy map sync: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkv1alpha1.ServiceRoutePolicy{}).
		Watches(&networkv1alpha1.ServiceEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.endpointPolicies)).
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(r.attachmentPolicies)).
		Watches(&networkv1alpha1.BGPRouter{}, handler.EnqueueRequestsFromMapFunc(r.routingDependencyPolicies)).
		Watches(&networkv1alpha1.BGPVRFInstance{}, handler.EnqueueRequestsFromMapFunc(r.routingDependencyPolicies)).
		Complete(r)
}

func (r *ServiceRoutePolicyReconciler) runStartupSync(ctx context.Context) error {
	for {
		err := r.syncAllPolicies(ctx)
		if err == nil {
			return nil
		}
		log.FromContext(ctx).Error(err, "initial service route policy map adoption and sweep")
		if !startupSyncNeedsRetry(err) {
			// The complete snapshot was finalized and policy forwarding was
			// enabled. Per-policy errors are retried by their ordinary
			// reconciles; globally gating the datapath again would disrupt all
			// successfully established services.
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// syncAllPolicies adopts a complete cache-synchronized desired set before
// sweeping stale policy entries. The reconciler mutex spans compilation,
// programming, and the sweep so an ordinary reconcile cannot reintroduce an
// object from a snapshot older than the one being finalized.
func (r *ServiceRoutePolicyReconciler) syncAllPolicies(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	policies := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, policies); err != nil {
		return startupSyncError(fmt.Errorf("list ServiceRoutePolicies for startup sync: %w", err), true)
	}
	attachments := &cloudv1alpha1.VPCAttachmentList{}
	if err := r.List(ctx, attachments); err != nil {
		return startupSyncError(fmt.Errorf("list VPCAttachments for startup sync: %w", err), true)
	}
	allAttachments := make([]*cloudv1alpha1.VPCAttachment, 0, len(attachments.Items))
	for index := range attachments.Items {
		allAttachments = append(allAttachments, &attachments.Items[index])
	}

	type compiledPolicy struct {
		key     types.NamespacedName
		intents []serviceroute.RouteIntent
	}
	compiled := make([]compiledPolicy, 0, len(policies.Items))
	currentPolicies := make(map[types.NamespacedName]struct{}, len(policies.Items))
	for index := range policies.Items {
		policy := &policies.Items[index]
		key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
		currentPolicies[key] = struct{}{}
		endpoint := &networkv1alpha1.ServiceEndpoint{}
		endpointKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Spec.ServiceRef.Name}
		if err := r.Get(ctx, endpointKey, endpoint); err != nil {
			if apierrors.IsNotFound(err) {
				compiled = append(compiled, compiledPolicy{key: key})
				continue
			}
			return startupSyncError(fmt.Errorf("get ServiceEndpoint %s for startup sync: %w", endpointKey, err), true)
		}
		intents, err := serviceroute.Compile(policy, endpoint, allAttachments, r.NodeName, r.sidResolver(ctx))
		if err != nil {
			// Invalid policies and node-local dependencies that are not ready
			// both fail closed in the startup snapshot. Ordinary reconciliation
			// publishes their precise status and retries dependency failures.
			compiled = append(compiled, compiledPolicy{key: key})
			continue
		}
		compiled = append(compiled, compiledPolicy{key: key, intents: intents})
	}
	sort.Slice(compiled, func(i, j int) bool { return compiled[i].key.String() < compiled[j].key.String() })

	if err := r.Programmer.Initialize(); err != nil {
		return startupSyncError(fmt.Errorf("initialize service route maps for startup sync: %w", err), true)
	}
	var removed []types.NamespacedName
	for key := range r.Applied {
		if _, exists := currentPolicies[key]; !exists {
			removed = append(removed, key)
		}
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].String() < removed[j].String() })
	var syncErrs []error
	cleanupFailed := false
	for _, key := range removed {
		if err := r.removePolicyLocked(key); err != nil {
			cleanupFailed = cleanupFailed || isServiceRoutePolicyCleanupError(err)
			syncErrs = append(syncErrs,
				fmt.Errorf("remove obsolete service route policy %s during startup sync: %w", key, err))
		}
	}
	for _, policy := range compiled {
		if err := r.replacePolicyLocked(policy.key, policy.intents); err != nil {
			cleanupFailed = cleanupFailed || isServiceRoutePolicyCleanupError(err)
			syncErrs = append(syncErrs,
				fmt.Errorf("apply service route policy %s during startup sync: %w", policy.key, err))
			// A permanently broken policy must not keep its previous desired
			// references alive and thereby exempt them from the stale sweep.
			// Remove any intents established before the failure and continue
			// adopting independent policies.
			if removeErr := r.removePolicyLocked(policy.key); removeErr != nil {
				cleanupFailed = true
				syncErrs = append(syncErrs,
					fmt.Errorf("fail closed service route policy %s during startup sync: %w", policy.key, removeErr))
			}
		}
	}
	if cleanupFailed {
		// Finalize enables service policy after sweeping against the
		// programmer's retained desired references. A failed rollback or
		// removal can leave an authorization reference in that snapshot, so
		// keep the global gate closed and retry cleanup instead.
		return startupSyncError(errors.Join(syncErrs...), true)
	}
	finalized := true
	if err := r.Programmer.Finalize(); err != nil {
		finalized = false
		syncErrs = append(syncErrs, fmt.Errorf("sweep stale service route policy maps: %w", err))
	}
	return startupSyncError(errors.Join(syncErrs...), !finalized)
}

func (r *ServiceRoutePolicyReconciler) endpointPolicies(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.policiesForEndpoint(ctx, obj.GetNamespace(), obj.GetName())
}

func (r *ServiceRoutePolicyReconciler) attachmentPolicies(ctx context.Context, _ client.Object) []ctrl.Request {
	return r.allPolicies(ctx)
}

func (r *ServiceRoutePolicyReconciler) routingDependencyPolicies(ctx context.Context, _ client.Object) []ctrl.Request {
	return r.allPolicies(ctx)
}

// sidResolver derives an attachment's End.DT46 SID from the same BGPRouter and
// BGPVRFInstance identities the CNI publish path used. It deliberately does not
// resolve by address containment: a guest-managed attachment may advertise no
// prefix, and tenant address spaces may overlap.
func (r *ServiceRoutePolicyReconciler) sidResolver(ctx context.Context) serviceroute.SIDResolver {
	cache := make(map[string]net.IP)
	return func(attachment *cloudv1alpha1.VPCAttachment) (net.IP, error) {
		identity := attachment.Status.VPC + "|" + attachment.Status.Node
		if sid, ok := cache[identity]; ok {
			return append(net.IP(nil), sid...), nil
		}
		namespace := r.BGPNamespace
		if namespace == "" {
			namespace = config.DefaultNamespace
		}
		vrf := &networkv1alpha1.BGPVRFInstance{}
		vrfKey := types.NamespacedName{
			Namespace: namespace,
			Name:      crdnames.BGPVRFInstanceName(attachment.Status.VPC, attachment.Status.Node),
		}
		if err := r.Get(ctx, vrfKey, vrf); err != nil {
			return nil, fmt.Errorf("get BGPVRFInstance %s: %w", vrfKey, err)
		}
		if vrf.Spec.RouterRef == nil || vrf.Spec.RouterRef.Name == "" {
			return nil, fmt.Errorf("BGPVRFInstance %s does not have an explicit routerRef", vrfKey)
		}
		routerKey := types.NamespacedName{Namespace: namespace, Name: vrf.Spec.RouterRef.Name}
		router := &networkv1alpha1.BGPRouter{}
		if err := r.Get(ctx, routerKey, router); err != nil {
			return nil, fmt.Errorf("get BGPRouter %s: %w", routerKey, err)
		}
		if router.Spec.TargetRef.Name != attachment.Status.Node {
			return nil, fmt.Errorf("BGPRouter %s targets node %q, not attachment node %q",
				routerKey, router.Spec.TargetRef.Name, attachment.Status.Node)
		}
		sid, err := srv6.ComputeSID(router.Spec.SRv6Locator, router.Spec.NodeID, vrf.Spec.VRFID,
			networkv1alpha1.SRv6FunctionEndDT46)
		if err != nil {
			return nil, fmt.Errorf("compute attachment SID from BGPRouter %s and BGPVRFInstance %s: %w",
				routerKey, vrfKey, err)
		}
		resolved := net.IP(sid.AsSlice())
		cache[identity] = append(net.IP(nil), resolved...)
		return resolved, nil
	}
}

func (r *ServiceRoutePolicyReconciler) policiesForEndpoint(ctx context.Context, namespace, name string) []ctrl.Request {
	list := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0)
	for _, policy := range list.Items {
		if policy.Spec.ServiceRef.Name == name {
			requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: policy.Namespace,
				Name:      policy.Name,
			}})
		}
	}
	return requests
}

func (r *ServiceRoutePolicyReconciler) allPolicies(ctx context.Context) []ctrl.Request {
	list := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, list); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(list.Items))
	for _, policy := range list.Items {
		requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{
			Namespace: policy.Namespace,
			Name:      policy.Name,
		}})
	}
	return requests
}

func (r *ServiceRoutePolicyReconciler) replacePolicy(
	key types.NamespacedName,
	intents []serviceroute.RouteIntent,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.replacePolicyLocked(key, intents)
}

func (r *ServiceRoutePolicyReconciler) replacePolicyLocked(
	key types.NamespacedName,
	intents []serviceroute.RouteIntent,
) error {
	defer r.updateProgrammedGauge()
	if r.Applied == nil {
		r.Applied = make(map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent)
	}
	current := r.Applied[key]
	if current == nil {
		current = make(map[types.NamespacedName]serviceroute.RouteIntent)
		r.Applied[key] = current
	}
	desired := make(map[types.NamespacedName]serviceroute.RouteIntent, len(intents))
	for _, intent := range intents {
		desired[intent.Attachment] = intent
	}

	// Revoke obsolete or changed intents first. Each successful operation is
	// reflected in Applied immediately, so a later failure leaves an accurate,
	// retryable snapshot rather than leaking untracked kernel state.
	for attachment, existing := range current {
		next, ok := desired[attachment]
		if ok && reflect.DeepEqual(existing, next) {
			continue
		}
		if err := r.Programmer.Remove(existing); err != nil {
			r.Metrics.ObserveOperation("remove", err)
			return &serviceRoutePolicyCleanupError{err: err}
		}
		r.Metrics.ObserveOperation("remove", nil)
		delete(current, attachment)
	}
	for attachment, intent := range desired {
		if existing, ok := current[attachment]; ok && reflect.DeepEqual(existing, intent) {
			continue
		}
		if err := r.Programmer.Apply(intent); err != nil {
			r.Metrics.ObserveOperation("apply", err)
			if cleanupErr := r.Programmer.Cleanup(intent); cleanupErr != nil {
				return errors.Join(err, &serviceRoutePolicyCleanupError{err: cleanupErr})
			}
			return err
		}
		r.Metrics.ObserveOperation("apply", nil)
		current[attachment] = intent
	}
	if len(current) == 0 {
		delete(r.Applied, key)
	}
	return nil
}

func (r *ServiceRoutePolicyReconciler) removePolicy(key types.NamespacedName) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.removePolicyLocked(key)
}

func (r *ServiceRoutePolicyReconciler) removePolicyLocked(key types.NamespacedName) error {
	defer r.updateProgrammedGauge()
	current := r.Applied[key]
	for attachment, intent := range current {
		if err := r.Programmer.Remove(intent); err != nil {
			r.Metrics.ObserveOperation("remove", err)
			return &serviceRoutePolicyCleanupError{err: err}
		}
		r.Metrics.ObserveOperation("remove", nil)
		delete(current, attachment)
	}
	delete(r.Applied, key)
	return nil
}

func (r *ServiceRoutePolicyReconciler) updateProgrammedGauge() {
	count := 0
	for _, intents := range r.Applied {
		count += len(intents)
	}
	r.Metrics.SetProgrammedRoutes(count)
}
