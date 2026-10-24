// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attachment is the control-plane half of the Galactic Edge
// attachment lifecycle, run by galactic-controller --role=cell: it admits
// each EdgeAttachment, allocates its address, drains it when its authority
// ends, and holds it with a finalizer until its node has released the host
// state. The node half, which programs and releases that state, is
// internal/edge/agent.
//
// Every decision is made from uncached reads of the attachment, its
// EdgeService, EdgeInstance, Pod, VPC and EdgeProvider, so a cache that lags
// a revocation or a replaced pod never admits or allocates. Missing tenant
// state refuses the attachment; it is never filled in from defaults.
package attachment

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
	"go.datum.net/galactic/internal/edge/diag"
)

// Condition reasons the reconciler sets beyond admission's own.
const (
	ReasonAdmitted         = "Admitted"
	ReasonPending          = "Pending"
	ReasonAllocated        = "Allocated"
	ReasonInstanceMissing  = "InstanceNotFound"
	ReasonPodMissing       = "PodNotFound"
	ReasonVPCUnavailable   = "VPCUnavailable"
	ReasonNoClientPool     = "NoClientPool"
	ReasonPoolOutsideVPC   = "PoolOutsideVPC"
	ReasonPoolConflict     = "PoolConflict"
	ReasonPoolExhausted    = "PoolExhausted"
	ReasonAddressConflict  = "AddressConflict"
	ReasonPlacementChanged = "PlacementChanged"
)

// Timing of retries the reconciler schedules itself. Watches on every input
// trigger the usual path; these only bound how long a missed event delays it.
const (
	refusedRetry   = time.Minute
	transientRetry = 2 * time.Second
	releaseRecheck = time.Minute
)

// defaultDrain is the drain window when the service sets none, or is gone.
const defaultDrain = 30 * time.Second

// Reconciler admits, allocates and drains EdgeAttachments.
type Reconciler struct {
	// Client writes status and the finalizer.
	Client client.Client
	// APIReader reads every input uncached.
	APIReader client.Reader
	// Authority holds the cell's providers and grants and ends an admitted
	// authorization when its grant or provider no longer admits it.
	Authority *admission.Authority
	// MaxSkew is the cell's maximum wall-clock error; a grant stops admitting
	// MaxSkew before its validUntil. It must be the Authority's.
	MaxSkew time.Duration
	// Now is the wall clock. Nil means time.Now.
	Now func() time.Time
	// Diag records attachments refused admission or allocation, and admitted
	// attachments whose authority ended.
	Diag *diag.Recorder

	mu    sync.Mutex
	auths map[types.NamespacedName]*admission.Authorization
	// ended carries the attachments whose authorization ended, so they are
	// reconciled at once rather than at the next unrelated event.
	ended chan event.GenericEvent
	// stopped closes with the manager, releasing waiters on ended.
	stopped <-chan struct{}
}

// refusal is why an attachment cannot be admitted or allocated now.
// A transient refusal is retried without draining an admitted attachment.
type refusal struct {
	reason, message string
	transient       bool
}

func refuse(reason, format string, args ...any) *refusal {
	return &refusal{reason: reason, message: fmt.Sprintf(format, args...)}
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile implements reconcile.Reconciler.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var att galacticv1alpha1.EdgeAttachment
	if err := r.APIReader.Get(ctx, req.NamespacedName, &att); err != nil {
		if apierrors.IsNotFound(err) {
			r.forget(req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !att.DeletionTimestamp.IsZero() {
		return r.finish(ctx, &att)
	}
	if controllerutil.AddFinalizer(&att, galacticv1alpha1.EdgeAttachmentFinalizer) {
		if err := r.Client.Update(ctx, &att); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer to %s: %w", req.NamespacedName, err)
		}
	}
	if meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentDraining) {
		return r.drain(ctx, &att)
	}

	svc, node, vpc, ref, err := r.admit(ctx, &att)
	if err != nil {
		return ctrl.Result{}, err
	}
	if ref == nil {
		ref, err = r.allocate(ctx, &att, svc, node, vpc)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	if ref == nil {
		return ctrl.Result{}, nil
	}
	held := meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted) ||
		att.Status.Address != ""
	switch {
	case held && !ref.transient:
		return r.startDrain(ctx, &att, svc, ref)
	case held:
		// Keep the admitted state: only a definite refusal revokes it.
		return ctrl.Result{RequeueAfter: transientRetry}, nil
	}
	cond, stage := galacticv1alpha1.EdgeAttachmentAdmitted, diag.StageAdmission
	if ref.reason == ReasonPoolExhausted {
		cond, stage = galacticv1alpha1.EdgeAttachmentAllocated, diag.StageAllocation
	}
	// A transient refusal writes its reason too, and may share it with a
	// later definite one, so a new message also counts as a new failure.
	entered := diag.EnteredFailure(att.Status.Conditions, cond, ref.reason)
	if prev := meta.FindStatusCondition(att.Status.Conditions, cond); prev != nil && prev.Message != ref.message {
		entered = true
	}
	if err := r.setStatus(ctx, &att, func(s *galacticv1alpha1.EdgeAttachmentStatus) {
		setCondition(s, cond, metav1.ConditionFalse, ref.reason, ref.message)
	}); err != nil {
		return ctrl.Result{}, err
	}
	if entered && !ref.transient {
		r.Diag.Failure(&att, stage, ref.reason, ref.message, correlation(&att, svc))
	}
	if ref.transient {
		return ctrl.Result{RequeueAfter: transientRetry}, nil
	}
	return ctrl.Result{RequeueAfter: refusedRetry}, nil
}

// admit decides the attachment from fresh reads. It returns the service, the
// node and VPC identifier the attachment is admitted for, or the refusal.
func (r *Reconciler) admit(ctx context.Context, att *galacticv1alpha1.EdgeAttachment,
) (*galacticv1alpha1.EdgeService, string, string, *refusal, error) {
	ref := att.Spec.ServiceRef
	var svc galacticv1alpha1.EdgeService
	switch err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &svc); {
	case apierrors.IsNotFound(err):
		return nil, "", "", refuse(string(admission.GrantRevoked),
			"EdgeService %s/%s no longer exists", ref.Namespace, ref.Name), nil
	case err != nil:
		return nil, "", "", nil, err
	case string(svc.UID) != ref.UID:
		return nil, "", "", refuse(string(admission.GrantRevoked),
			"EdgeService %s/%s was replaced", ref.Namespace, ref.Name), nil
	case svc.Spec.ProviderRef != att.Spec.ProviderRef:
		return &svc, "", "", refuse(string(admission.ProviderNotGranted),
			"EdgeService %s/%s grants provider %q, not %q", ref.Namespace, ref.Name,
			svc.Spec.ProviderRef.Name, att.Spec.ProviderRef.Name), nil
	}

	var inst galacticv1alpha1.EdgeInstance
	instKey := client.ObjectKey{Namespace: att.Namespace, Name: att.Spec.InstanceRef.Name}
	switch err := r.APIReader.Get(ctx, instKey, &inst); {
	case apierrors.IsNotFound(err):
		return &svc, "", "", refuse(ReasonInstanceMissing, "EdgeInstance %s does not exist", att.Spec.InstanceRef.Name), nil
	case err != nil:
		return nil, "", "", nil, err
	case inst.Spec.ProviderRef != att.Spec.ProviderRef:
		return &svc, "", "", refuse(string(admission.IdentityMismatch),
			"EdgeInstance %s runs provider %q, not %q", inst.Name, inst.Spec.ProviderRef.Name, att.Spec.ProviderRef.Name), nil
	case inst.Spec.PodUID != att.Spec.PodUID:
		return &svc, "", "", refuse(string(admission.IdentityMismatch),
			"EdgeInstance %s is pod %s, not %s", inst.Name, inst.Spec.PodUID, att.Spec.PodUID), nil
	}

	var pod corev1.Pod
	switch err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: att.Namespace, Name: inst.Spec.PodName}, &pod); {
	case apierrors.IsNotFound(err):
		return &svc, "", "", refuse(ReasonPodMissing, "pod %s does not exist", inst.Spec.PodName), nil
	case err != nil:
		return nil, "", "", nil, err
	case string(pod.UID) != inst.Spec.PodUID || !pod.DeletionTimestamp.IsZero() ||
		pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed:
		return &svc, "", "", refuse(ReasonPodMissing, "pod %s with UID %s is no longer running",
			inst.Spec.PodName, inst.Spec.PodUID), nil
	case pod.Spec.NodeName == "" || pod.Spec.NodeName != inst.Spec.NodeName:
		return &svc, "", "", refuse(string(admission.IdentityMismatch),
			"EdgeInstance %s names node %q, but its pod runs on %q", inst.Name, inst.Spec.NodeName, pod.Spec.NodeName), nil
	}

	vpcID, ref2, err := checkVPC(ctx, r.APIReader, &svc)
	if err != nil || ref2 != nil {
		return &svc, "", "", ref2, err
	}

	var provider galacticv1alpha1.EdgeProvider
	providers := map[string]admission.Provider{}
	switch err := r.APIReader.Get(ctx, client.ObjectKey{Name: svc.Spec.ProviderRef.Name}, &provider); {
	case err == nil && provider.DeletionTimestamp.IsZero():
		providers[provider.Name] = admission.ProviderFromAPI(&provider)
	case err != nil && !apierrors.IsNotFound(err):
		return nil, "", "", nil, err
	}
	grant, err := admission.GrantFromAPI(&svc)
	if err != nil {
		return &svc, "", "", refuse(string(admission.InvalidRequest), "%v", err), nil
	}
	sa := pod.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	req := admission.Request{
		Identity: admission.Identity{
			ServiceAccount: admission.ServiceAccount{Namespace: att.Namespace, Name: sa},
			PodUID:         string(pod.UID),
		},
		PodUID:          att.Spec.PodUID,
		Provider:        svc.Spec.ProviderRef.Name,
		ContractVersion: att.Spec.ContractVersion,
		Grant:           admission.GrantRef{UID: grant.UID, Generation: grant.Generation},
		VPC:             svc.Spec.VPCRef.UID,
	}
	// An attachment references no provider configuration of its own.
	if p, ok := providers[req.Provider]; ok {
		req.ConfigGroup, req.ConfigKind = p.ConfigGroup, p.ConfigKind
	}
	for _, c := range att.Spec.Capabilities {
		req.Capabilities = append(req.Capabilities, admission.Capability{Name: c.Name, Version: c.Version})
	}
	fresh := admission.Admit(providers, map[string]admission.Grant{grant.UID: grant}, req, r.now(), r.MaxSkew)
	if !fresh.Admitted {
		return &svc, "", "", refuse(string(fresh.Reason), "%s", fresh.Message), nil
	}
	if ref := r.track(att, req); ref != nil {
		return &svc, "", "", ref, nil
	}
	return &svc, pod.Spec.NodeName, vpcID, nil, nil
}

// checkVPC returns the base62 identifier of the service's VPC once its
// client pool is usable, inside the VPC and overlapping no earlier service's
// pool in the same VPC, and its granted prefixes overlap no earlier service's
// in the same VPC.
func checkVPC(ctx context.Context, reader client.Reader, svc *galacticv1alpha1.EdgeService) (string, *refusal, error) {
	var vpc cloudv1alpha1.VPC
	switch err := reader.Get(ctx, client.ObjectKey{Namespace: svc.Namespace, Name: svc.Spec.VPCRef.Name}, &vpc); {
	case apierrors.IsNotFound(err):
		return "", refuse(ReasonVPCUnavailable, "VPC %s does not exist", svc.Spec.VPCRef.Name), nil
	case err != nil:
		return "", nil, err
	case string(vpc.UID) != svc.Spec.VPCRef.UID:
		return "", refuse(ReasonVPCUnavailable, "VPC %s is not the granted VPC %s",
			svc.Spec.VPCRef.Name, svc.Spec.VPCRef.UID), nil
	case vpc.Status.VPC == "":
		ref := refuse(ReasonVPCUnavailable, "VPC %s has no fabric identifier yet", vpc.Name)
		ref.transient = true
		return "", ref, nil
	}
	if svc.Spec.ClientPool == "" {
		return "", refuse(ReasonNoClientPool, "EdgeService %s has no client pool", svc.Name), nil
	}
	pool, err := parsePool(svc.Spec.ClientPool)
	if err != nil {
		return "", refuse(ReasonNoClientPool, "%v", err), nil
	}
	var nets []netip.Prefix
	for _, n := range vpc.Spec.Networks {
		if p, err := netip.ParsePrefix(string(n)); err == nil {
			nets = append(nets, p.Masked())
		}
	}
	if !insideAny(pool, nets) {
		return "", refuse(ReasonPoolOutsideVPC, "client pool %s is outside VPC %s", pool, vpc.Name), nil
	}
	var others galacticv1alpha1.EdgeServiceList
	if err := reader.List(ctx, &others, client.InNamespace(svc.Namespace)); err != nil {
		return "", nil, err
	}
	for i := range others.Items {
		o := &others.Items[i]
		if o.UID == svc.UID || o.Spec.VPCRef.UID != svc.Spec.VPCRef.UID || o.Spec.ClientPool == "" {
			continue
		}
		// The older service keeps its pool, so creating an overlapping one
		// never revokes attachments already admitted.
		if !admission.Earlier(o, svc) {
			continue
		}
		if p, err := parsePool(o.Spec.ClientPool); err == nil && overlaps(p, pool) {
			return "", refuse(ReasonPoolConflict, "client pool %s overlaps EdgeService %s's %s", pool, o.Name, p), nil
		}
	}
	if o, mine, theirs := admission.GrantConflict(svc, others.Items); o != nil {
		return "", refuse(string(admission.PrefixConflict), "granted prefix %s overlaps EdgeService %s's %s",
			mine, o.Name, theirs), nil
	}
	return vpc.Status.VPC, nil, nil
}

// track keeps one Authority authorization per attachment, decided on the
// service generation the attachment was just admitted under. The Authority
// is fed by informers and may lag the fresh reads; a refusal from it is
// therefore transient, retried until it catches up.
func (r *Reconciler) track(att *galacticv1alpha1.EdgeAttachment, req admission.Request) *refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := client.ObjectKeyFromObject(att)
	if z, ok := r.auths[key]; ok {
		select {
		case <-z.Done():
		default:
			if z.Grant() == req.Grant && z.Identity() == req.Identity {
				return nil
			}
		}
		r.Authority.Release(z)
		delete(r.auths, key)
	}
	d := r.Authority.Admit(req)
	if !d.Admitted {
		ref := refuse(string(d.Reason), "%s", d.Message)
		ref.transient = true
		return ref
	}
	if r.auths == nil {
		r.auths = map[types.NamespacedName]*admission.Authorization{}
	}
	r.auths[key] = d.Authorization
	go r.watch(d.Authorization, att.Namespace, att.Name)
	return nil
}

// watch requeues the attachment when its authorization ends.
func (r *Reconciler) watch(z *admission.Authorization, namespace, name string) {
	select {
	case <-z.Done():
	case <-r.stopped:
		return
	}
	obj := &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	select {
	case r.ended <- event.GenericEvent{Object: obj}:
	case <-r.stopped:
	}
}

func (r *Reconciler) forget(key types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if z, ok := r.auths[key]; ok {
		r.Authority.Release(z)
		delete(r.auths, key)
	}
}

// allocate records an address for the attachment in its service's
// allocations, with the service's resourceVersion as precondition, then in
// the attachment's status. A record already naming the attachment is reused,
// so a write whose reply was lost is not allocated twice.
func (r *Reconciler) allocate(ctx context.Context, att *galacticv1alpha1.EdgeAttachment,
	svc *galacticv1alpha1.EdgeService, node, vpc string) (*refusal, error) {
	if s := att.Status; (s.NodeName != "" && s.NodeName != node) || (s.VPC != "" && s.VPC != vpc) {
		return refuse(ReasonPlacementChanged, "attachment is on node %q in VPC %q, now node %q in VPC %q",
			s.NodeName, s.VPC, node, vpc), nil
	}
	pool, err := parsePool(svc.Spec.ClientPool)
	if err != nil {
		return refuse(ReasonNoClientPool, "%v", err), nil
	}
	key := client.ObjectKeyFromObject(svc)
	uid := string(att.UID)
	var addr string
	var ref *refusal
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ref = nil
		var cur galacticv1alpha1.EdgeService
		if err := r.APIReader.Get(ctx, key, &cur); err != nil {
			return err
		}
		if string(cur.UID) != string(svc.UID) {
			ref = refuse(string(admission.GrantRevoked), "EdgeService %s was replaced", key)
			return nil
		}
		if a, ok := allocationFor(cur.Status.Allocations, uid); ok {
			addr = a
			return nil
		}
		allocations := cur.Status.Allocations
		want := att.Status.Address
		if want == "" {
			var err error
			if allocations, err = r.liveAllocations(ctx, allocations); err != nil {
				return err
			}
			routed, err := r.routedPrefixes(ctx, &cur)
			if err != nil {
				return err
			}
			next, err := nextFree(pool, allocations, routed)
			if errors.Is(err, errPoolExhausted) {
				ref = refuse(ReasonPoolExhausted, "client pool %s has no free address", pool)
				return nil
			}
			want = next.String()
		} else {
			// The attachment holds an address its service no longer
			// records. Re-record it only if nobody else holds it.
			for _, a := range cur.Status.Allocations {
				if a.Address == want {
					ref = refuse(ReasonAddressConflict, "address %s is held by %s", want, a.Attachment)
					return nil
				}
			}
		}
		cur.Status.Allocations = withAllocation(allocations, want,
			att.Namespace+"/"+att.Name, uid)
		if err := r.Client.Status().Update(ctx, &cur); err != nil {
			return err
		}
		addr = want
		return nil
	})
	if err != nil || ref != nil {
		return ref, err
	}
	return nil, r.setStatus(ctx, att, func(s *galacticv1alpha1.EdgeAttachmentStatus) {
		s.NodeName, s.VPC, s.Address = node, vpc, addr
		setCondition(s, galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionTrue, ReasonAdmitted,
			fmt.Sprintf("admitted under EdgeService generation %d", svc.Generation))
		setCondition(s, galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, ReasonAllocated,
			fmt.Sprintf("address %s on node %s", addr, node))
	})
}

// routedPrefixes returns every prefix in the service's VPC's EdgeRouteIndex,
// read uncached: those of accepted routes and of routes whose holder may
// still forward. An allocation can still race a route accepted after this
// read; the route controller then revokes the route, since it refuses any
// route that covers another attachment's address.
func (r *Reconciler) routedPrefixes(ctx context.Context, svc *galacticv1alpha1.EdgeService) ([]netip.Prefix, error) {
	var idx galacticv1alpha1.EdgeRouteIndex
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: svc.Namespace, Name: svc.Spec.VPCRef.UID}, &idx)
	switch {
	case apierrors.IsNotFound(err):
		return nil, nil
	case err != nil:
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(idx.Spec.Routes))
	for _, e := range idx.Spec.Routes {
		if p, err := netip.ParsePrefix(e.Prefix); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// liveAllocations returns allocations less those whose attachment no longer
// exists, reading each recorded attachment uncached. An allocation outlives
// its attachment only when the attachment's finalizer was removed by hand;
// its node releases the orphaned link on its own, and until then a new
// holder of the address fails to program rather than sharing it. An entry
// whose attachment name cannot be parsed is kept.
func (r *Reconciler) liveAllocations(ctx context.Context, allocations []galacticv1alpha1.EdgeAllocation,
) ([]galacticv1alpha1.EdgeAllocation, error) {
	live := make([]galacticv1alpha1.EdgeAllocation, 0, len(allocations))
	for _, a := range allocations {
		ns, name, ok := strings.Cut(a.Attachment, "/")
		if !ok {
			live = append(live, a)
			continue
		}
		var att galacticv1alpha1.EdgeAttachment
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &att)
		switch {
		case apierrors.IsNotFound(err):
		case err != nil:
			return nil, err
		case string(att.UID) == a.AttachmentUID:
			live = append(live, a)
		}
	}
	return live, nil
}

// startDrain ends an admitted attachment's authority: it stops admitting it
// and schedules its deletion after the service's drain window.
func (r *Reconciler) startDrain(ctx context.Context, att *galacticv1alpha1.EdgeAttachment,
	svc *galacticv1alpha1.EdgeService, ref *refusal) (ctrl.Result, error) {
	r.forget(client.ObjectKeyFromObject(att))
	window := defaultDrain
	if svc != nil && string(svc.UID) == att.Spec.ServiceRef.UID && svc.Spec.DrainSeconds != nil {
		window = time.Duration(*svc.Spec.DrainSeconds) * time.Second
	}
	deadline := metav1.NewTime(r.now().Add(window).Truncate(time.Second))
	if err := r.setStatus(ctx, att, func(s *galacticv1alpha1.EdgeAttachmentStatus) {
		s.DrainDeadline = &deadline
		setCondition(s, galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionFalse, ref.reason, ref.message)
		setCondition(s, galacticv1alpha1.EdgeAttachmentDraining, metav1.ConditionTrue, ref.reason,
			fmt.Sprintf("released at %s: %s", deadline.UTC().Format(time.RFC3339), ref.message))
	}); err != nil {
		return ctrl.Result{}, err
	}
	r.Diag.Failure(att, diag.StageAdmission, ref.reason,
		fmt.Sprintf("authority ended, draining until %s: %s", deadline.UTC().Format(time.RFC3339), ref.message),
		correlation(att, svc))
	return r.drain(ctx, att)
}

// drain deletes a draining attachment once its deadline has passed.
func (r *Reconciler) drain(ctx context.Context, att *galacticv1alpha1.EdgeAttachment) (ctrl.Result, error) {
	r.forget(client.ObjectKeyFromObject(att))
	if att.Status.DrainDeadline != nil {
		if wait := att.Status.DrainDeadline.Sub(r.now()); wait > 0 {
			return ctrl.Result{RequeueAfter: wait}, nil
		}
	}
	err := r.Client.Delete(ctx, att, client.Preconditions{UID: &att.UID})
	return ctrl.Result{}, client.IgnoreNotFound(err)
}

// finish removes a deleted attachment's allocation and finalizer once its
// node has released its host state, or once that node no longer exists.
func (r *Reconciler) finish(ctx context.Context, att *galacticv1alpha1.EdgeAttachment) (ctrl.Result, error) {
	r.forget(client.ObjectKeyFromObject(att))
	if !controllerutil.ContainsFinalizer(att, galacticv1alpha1.EdgeAttachmentFinalizer) {
		return ctrl.Result{}, nil
	}
	if att.Status.Address != "" &&
		!meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReleased) {
		var node corev1.Node
		err := r.APIReader.Get(ctx, client.ObjectKey{Name: att.Status.NodeName}, &node)
		if err == nil {
			return ctrl.Result{RequeueAfter: releaseRecheck}, nil
		}
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	if err := r.free(ctx, att); err != nil {
		return ctrl.Result{}, err
	}
	before := att.DeepCopy()
	controllerutil.RemoveFinalizer(att, galacticv1alpha1.EdgeAttachmentFinalizer)
	err := r.Client.Patch(ctx, att, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
	return ctrl.Result{}, client.IgnoreNotFound(err)
}

// free removes the attachment's allocation from its service, if both remain.
func (r *Reconciler) free(ctx context.Context, att *galacticv1alpha1.EdgeAttachment) error {
	ref := att.Spec.ServiceRef
	key := client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var svc galacticv1alpha1.EdgeService
		if err := r.APIReader.Get(ctx, key, &svc); err != nil {
			return client.IgnoreNotFound(err)
		}
		if string(svc.UID) != ref.UID {
			return nil
		}
		if _, ok := allocationFor(svc.Status.Allocations, string(att.UID)); !ok {
			return nil
		}
		svc.Status.Allocations = withoutAllocation(svc.Status.Allocations, string(att.UID))
		return r.Client.Status().Update(ctx, &svc)
	})
}

// setStatus applies mutate to the attachment's status and writes it with the
// read resourceVersion as precondition, so the node's and the provider's
// conditions are never overwritten with an older view.
func (r *Reconciler) setStatus(ctx context.Context, att *galacticv1alpha1.EdgeAttachment,
	mutate func(*galacticv1alpha1.EdgeAttachmentStatus)) error {
	before := att.DeepCopy()
	mutate(&att.Status)
	if equalStatus(before.Status, att.Status) {
		return nil
	}
	err := r.Client.Status().Patch(ctx, att, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
	if err != nil {
		return fmt.Errorf("update EdgeAttachment %s/%s status: %w", att.Namespace, att.Name, err)
	}
	return nil
}

// correlation is att's correlation, with the generation of svc when svc is
// the service att names.
func correlation(att *galacticv1alpha1.EdgeAttachment, svc *galacticv1alpha1.EdgeService) diag.Correlation {
	c := diag.ForAttachment(att)
	if svc != nil && string(svc.UID) == att.Spec.ServiceRef.UID {
		c.ServiceGeneration = svc.Generation
	}
	return c
}

func setCondition(s *galacticv1alpha1.EdgeAttachmentStatus, t string, status metav1.ConditionStatus,
	reason, message string) {
	meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: t, Status: status, Reason: reason, Message: message})
}

func equalStatus(a, b galacticv1alpha1.EdgeAttachmentStatus) bool {
	if a.NodeName != b.NodeName || a.VPC != b.VPC || a.Address != b.Address ||
		!a.DrainDeadline.Equal(b.DrainDeadline) || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for _, c := range a.Conditions {
		d := meta.FindStatusCondition(b.Conditions, c.Type)
		if d == nil || d.Status != c.Status || d.Reason != c.Reason || d.Message != c.Message {
			return false
		}
	}
	return true
}
