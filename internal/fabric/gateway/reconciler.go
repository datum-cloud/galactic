// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gateway is the fabric-api cell gateway: a leader-elected controller
// that executes FabricQuery objects for its own site and cluster by fanning
// them out to the cell's fabric-api sidecars, an operator debug service, and
// the cell janitor that expires orphaned queries.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/query"
)

// errorReserveBytes is the room kept per selected node for an error entry
// when dividing the object budget.
const errorReserveBytes = 512

// jsonPerProtoByte estimates how much larger a result is as JSON in the
// object than as protobuf on the wire; the node allowance is divided by it.
const jsonPerProtoByte = 3

// minNodeAllowance is the smallest per-node response budget handed out.
const minNodeAllowance = 1024

// Reconciler executes FabricQuery objects for one site and cluster.
type Reconciler struct {
	// Client reads FabricQuery objects from the cache and writes status.
	Client client.Client
	// APIReader reads FabricQuery objects uncached when persisting status,
	// so a retry sees the latest version.
	APIReader client.Reader
	// Site and ClusterName select which queries this cell executes.
	Site        string
	ClusterName string
	Discoverer  *Discoverer
	Runner      *Runner
	// Pool, when set, drops connections to pods that left the cell.
	Pool *Pool
	// Ceilings bounds every query's budgets for this cell.
	Ceilings query.Budgets
	// MaxInFlight bounds concurrent executions; more wait for a requeue.
	MaxInFlight int
	Metrics     *Metrics
	// Now returns the current time; nil selects time.Now.
	Now func() time.Time

	mu      sync.Mutex
	base    context.Context
	running map[types.UID]runEntry
	wg      sync.WaitGroup
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the controller and the runnable whose context
// bounds every execution: it starts when this replica becomes leader and
// ends with leadership.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	ready := make(chan struct{})
	if err := mgr.Add(leaderRunnable(func(ctx context.Context) error {
		r.Start(ctx)
		close(ready)
		<-ctx.Done()
		r.Wait()
		return nil
	})); err != nil {
		return err
	}
	mine := predicate.NewPredicateFuncs(func(o client.Object) bool {
		fq, ok := o.(*fabricapi.FabricQuery)
		return ok && fq.Spec.Site == r.Site && fq.Spec.ClusterName == r.ClusterName
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("fabricquery").
		For(&fabricapi.FabricQuery{}, builder.WithPredicates(mine)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 8}).
		Complete(reconcilerWaiting{r: r, ready: ready})
}

// runEntry is one running execution.
type runEntry struct {
	key    types.NamespacedName
	cancel context.CancelFunc
}

// Start sets the context that bounds every execution. Executions stop when
// it ends.
func (r *Reconciler) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.base = ctx
	if r.running == nil {
		r.running = map[types.UID]runEntry{}
	}
	if r.MaxInFlight <= 0 {
		r.MaxInFlight = 256
	}
}

// Wait blocks until every running execution has finished.
func (r *Reconciler) Wait() { r.wg.Wait() }

// leaderRunnable is a manager runnable that needs leader election.
type leaderRunnable func(ctx context.Context) error

func (f leaderRunnable) Start(ctx context.Context) error { return f(ctx) }
func (leaderRunnable) NeedLeaderElection() bool          { return true }

// reconcilerWaiting holds reconciles until the execution context exists.
type reconcilerWaiting struct {
	r     *Reconciler
	ready chan struct{}
}

func (w reconcilerWaiting) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	select {
	case <-w.ready:
	case <-ctx.Done():
		return ctrl.Result{}, ctx.Err()
	}
	return w.r.Reconcile(ctx, req)
}

// Reconcile starts execution of a new or interrupted query, finishes one
// that cannot run, or cancels one that was deleted. A query whose Complete
// condition is True is never touched again.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var fq fabricapi.FabricQuery
	if err := r.Client.Get(ctx, req.NamespacedName, &fq); err != nil {
		if apierrors.IsNotFound(err) {
			r.cancelByName(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if fq.DeletionTimestamp != nil {
		r.cancel(fq.UID)
		return ctrl.Result{}, nil
	}
	if fq.Spec.Site != r.Site || fq.Spec.ClusterName != r.ClusterName || terminal(&fq) || r.isRunning(fq.UID) {
		return ctrl.Result{}, nil
	}
	log := slog.With("fabricQuery", req.String(), "requestID", fq.Spec.RequestID)
	now := r.now()
	if fq.Status.StartTime == nil && r.Metrics != nil {
		r.Metrics.stageLatency.WithLabelValues("receipt").Observe(now.Sub(fq.CreationTimestamp.Time).Seconds())
	}

	q, budgets, code, err := r.validate(&fq, now)
	if err != nil {
		log.Info("rejecting fabric query", "code", code, "error", err)
		return ctrl.Result{}, r.finishWithout(ctx, &fq, fabricapi.ReasonRejected, false,
			string(code)+": "+errcode.Message(err))
	}
	if !now.Before(fq.Spec.ExpiresAt.Time) {
		accepted := meta.IsStatusConditionTrue(fq.Status.Conditions, fabricapi.ConditionAccepted)
		log.Info("fabric query expired before execution")
		return ctrl.Result{}, r.finishWithout(ctx, &fq, fabricapi.ReasonDeadlineExceeded, accepted,
			"the request expired before this cell executed it")
	}

	r.mu.Lock()
	inFlight := len(r.running)
	r.mu.Unlock()
	if inFlight >= r.MaxInFlight {
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	// Resume an interrupted execution on its fixed snapshot, or take a new
	// one.
	var nodes []Node
	attempt := fq.Status.Attempt + 1
	if fq.Status.StartTime != nil && fq.Status.ObservedGeneration == fq.Generation && len(fq.Status.Nodes) > 0 {
		nodes = nodesFromStatus(fq.Status.Nodes)
		log.Info("resuming interrupted fabric query", "attempt", attempt)
	} else {
		nodes, err = r.Discoverer.Snapshot(ctx, fq.Spec.NodeSelector, budgets.MaxNodes)
		if err != nil {
			return ctrl.Result{}, err
		}
		if r.Pool != nil {
			r.Pool.Retain(append([]Node(nil), nodes...))
		}
	}
	if countSelected(nodes) == 0 {
		return ctrl.Result{}, r.finishNoNodes(ctx, &fq, nodes)
	}

	start := metav1.NewTime(now)
	fq.Status.RequestID = fq.Spec.RequestID
	fq.Status.ProducerCluster = r.ClusterName
	fq.Status.ObservedGeneration = fq.Generation
	fq.Status.Attempt = attempt
	if fq.Status.StartTime == nil {
		fq.Status.StartTime = &start
	}
	fq.Status.Nodes = nodesToStatus(nodes)
	fq.Status.Coverage = coverage(nodes, nil)
	r.setConditions(&fq, metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionFalse, fabricapi.ReasonRunning,
		fmt.Sprintf("executing on %d nodes", countSelected(nodes)))
	if err := r.Client.Status().Update(ctx, &fq); err != nil {
		r.countWrite("start", err)
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	r.countWrite("start", nil)

	allowance := r.nodeAllowance(&fq, budgets, countSelected(nodes))
	wire := &fabricv1.Budgets{
		MaxResponseBytes:      uint32(allowance),
		MaxPrefixes:           uint32(budgets.MaxPrefixes),
		MaxPathsPerPrefix:     uint32(budgets.MaxPathsPerPrefix),
		MaxCommunitiesPerPath: uint32(budgets.MaxCommunitiesPerPath),
	}
	r.launch(&fq, q, nodes, wire, budgets, attempt)
	return ctrl.Result{}, nil
}

// validate re-checks the spec at this trust boundary and returns the
// canonical query and clamped budgets.
func (r *Reconciler) validate(
	fq *fabricapi.FabricQuery, now time.Time,
) (query.Query, query.Budgets, errcode.Code, error) {
	in := QueryFromSpec(fq.Spec.Query)
	q, err := query.Canonicalize(in)
	if err != nil {
		return query.Query{}, query.Budgets{}, errcode.Of(errcode.FromError(err)), err
	}
	if q != in {
		return query.Query{}, query.Budgets{}, errcode.InvalidQuery, errors.New("query is not canonical")
	}
	if q.Type.Probe() {
		if _, err := query.ResolvedProbe(q); err != nil {
			return query.Query{}, query.Budgets{}, errcode.InvalidQuery, err
		}
	}
	if fq.Spec.ExpiresAt.Sub(fq.CreationTimestamp.Time) > query.MaxRequestLifetime+time.Minute ||
		fq.Spec.ExpiresAt.Sub(now) > query.MaxRequestLifetime+time.Minute {
		return query.Query{}, query.Budgets{}, errcode.InvalidQuery,
			fmt.Errorf("expiresAt is further away than the %s request lifetime", query.MaxRequestLifetime)
	}
	b := BudgetsFromSpec(fq.Spec.Budgets)
	c := r.Ceilings.Clamp()
	b = query.Budgets{
		MaxNodes:              min(b.MaxNodes, c.MaxNodes),
		MaxNodeResponseBytes:  min(b.MaxNodeResponseBytes, c.MaxNodeResponseBytes),
		MaxObjectBytes:        min(b.MaxObjectBytes, c.MaxObjectBytes),
		MaxPrefixes:           min(b.MaxPrefixes, c.MaxPrefixes),
		MaxPathsPerPrefix:     min(b.MaxPathsPerPrefix, c.MaxPathsPerPrefix),
		MaxCommunitiesPerPath: min(b.MaxCommunitiesPerPath, c.MaxCommunitiesPerPath),
	}
	return q, b, "", nil
}

// nodeAllowance divides what is left of the object budget, after the object
// with its start marker and an error entry per node, among the selected
// nodes, converted from JSON to protobuf bytes.
func (r *Reconciler) nodeAllowance(fq *fabricapi.FabricQuery, b query.Budgets, selected int) int {
	overhead := objectSize(fq) + selected*errorReserveBytes
	perNode := (b.MaxObjectBytes - overhead) / max(selected, 1) / jsonPerProtoByte
	return max(min(perNode, b.MaxNodeResponseBytes), minNodeAllowance)
}

func objectSize(fq *fabricapi.FabricQuery) int {
	b, err := json.Marshal(fq)
	if err != nil {
		return 0
	}
	return len(b)
}

// launch runs the execution in the background under the leader's context, so
// a deletion can cancel it and a lost leadership stops it.
func (r *Reconciler) launch(fq *fabricapi.FabricQuery, q query.Query, nodes []Node, wire *fabricv1.Budgets,
	budgets query.Budgets, attempt int32) {
	r.mu.Lock()
	ctx, cancel := context.WithDeadline(r.base, fq.Spec.ExpiresAt.Time)
	key := client.ObjectKeyFromObject(fq)
	r.running[fq.UID] = runEntry{key: key, cancel: cancel}
	r.mu.Unlock()
	uid := fq.UID
	created := fq.CreationTimestamp.Time
	spec := fq.Spec
	r.wg.Add(1)
	if r.Metrics != nil {
		r.Metrics.inFlight.Inc()
	}
	go func() {
		defer r.wg.Done()
		defer func() {
			cancel()
			r.mu.Lock()
			delete(r.running, uid)
			r.mu.Unlock()
			if r.Metrics != nil {
				r.Metrics.inFlight.Dec()
			}
		}()
		log := slog.With("fabricQuery", key.String(), "requestID", spec.RequestID, "attempt", attempt)
		started := r.now()
		outcomes := r.Runner.Run(ctx, spec.Source.Namespace+"/"+spec.Source.Cluster, spec.RequestID,
			q, nodes, wire, spec.ExpiresAt.Time)
		if r.Metrics != nil {
			r.Metrics.stageLatency.WithLabelValues("execution").Observe(r.now().Sub(started).Seconds())
		}
		if r.base.Err() != nil {
			log.Info("leadership lost during execution; the next leader resumes it")
			return
		}
		if err := r.persist(key, uid, attempt, q, nodes, outcomes, budgets, created); err != nil {
			log.Error("could not persist fabric query result", "error", err)
			return
		}
		log.Info("fabric query complete", "nodes", len(outcomes), "duration", r.now().Sub(started))
	}()
}

// persist writes the terminal status, retrying optimistic conflicts against
// the latest object without rerunning any RPC. It stops if the object is
// gone, already terminal, or belongs to another attempt.
func (r *Reconciler) persist(key client.ObjectKey, uid types.UID, attempt int32, q query.Query, nodes []Node,
	outcomes []Outcome, b query.Budgets, created time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var lastErr error
	for try := range 6 {
		if try > 0 {
			time.Sleep(time.Duration(try*try) * 100 * time.Millisecond)
		}
		var latest fabricapi.FabricQuery
		if err := r.APIReader.Get(ctx, key, &latest); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			lastErr = err
			continue
		}
		if latest.UID != uid || terminal(&latest) || latest.Status.Attempt != attempt {
			return nil
		}
		reason := r.terminalStatus(&latest, nodes, outcomes, b)
		err := r.Client.Status().Update(ctx, &latest)
		r.countWrite("terminal", err)
		if err == nil {
			if r.Metrics != nil {
				r.Metrics.queries.WithLabelValues(string(q.Type), reason).Inc()
				r.Metrics.statusBytes.Observe(float64(objectSize(&latest)))
				r.Metrics.stageLatency.WithLabelValues("completion").Observe(r.now().Sub(created).Seconds())
				for _, o := range outcomes {
					r.Metrics.nodes.WithLabelValues(outcomeLabel(o)).Inc()
				}
				for _, n := range nodes {
					if !n.Selected {
						r.Metrics.nodes.WithLabelValues(n.OmittedReason).Inc()
					}
				}
			}
			return nil
		}
		lastErr = err
		if !apierrors.IsConflict(err) {
			continue
		}
	}
	return lastErr
}

func outcomeLabel(o Outcome) string {
	if o.Err != nil {
		return string(errcode.Of(o.Err))
	}
	return "OK"
}

// terminalStatus fills fq's status with the bounded terminal result and
// returns the terminal reason.
func (r *Reconciler) terminalStatus(
	fq *fabricapi.FabricQuery, nodes []Node, outcomes []Outcome, b query.Budgets,
) string {
	now := r.now()
	expired := !now.Before(fq.Spec.ExpiresAt.Time)
	obs := make([]fabricapi.NodeObservation, 0, len(outcomes))
	succeeded, timedOut, truncated := 0, false, false
	for _, o := range outcomes {
		if o.Err != nil {
			code := errcode.Of(o.Err)
			timedOut = timedOut || code == errcode.Timeout
			obs = append(obs, fabricapi.NodeObservation{
				Node:         o.Node.Name,
				ErrorCode:    string(code),
				ErrorMessage: errcode.Message(o.Err),
			})
			continue
		}
		succeeded++
		no := observationFromProto(o.Node.Name, o.Observation)
		truncated = truncated || no.Truncated
		obs = append(obs, no)
	}
	fq.Status.Observations = obs
	fq.Status.Coverage = coverage(nodes, outcomes)
	if shrinkToBudget(fq, b.MaxObjectBytes) {
		truncated = true
		if r.Metrics != nil {
			r.Metrics.truncated.Inc()
		}
	}
	// Re-count after shrinking, which can turn a success into an error.
	succeeded = int(fq.Status.Coverage.Successful)
	missing := int(fq.Status.Coverage.Failed) > 0
	omitted := hasRealOmissions(nodes)
	completion := metav1.NewTime(now)
	fq.Status.CompletionTime = &completion

	var reason, msg string
	failed := metav1.ConditionFalse
	switch {
	case (expired || timedOut) && missing:
		reason = fabricapi.ReasonDeadlineExceeded
		msg = fmt.Sprintf("%d of %d nodes answered before the request expired", succeeded, len(outcomes))
		if succeeded == 0 {
			failed = metav1.ConditionTrue
		}
	case succeeded == 0:
		reason, failed = fabricapi.ReasonExecutionFailed, metav1.ConditionTrue
		msg = fmt.Sprintf("none of %d nodes produced an answer", len(outcomes))
	case missing || omitted || truncated:
		reason = fabricapi.ReasonPartialResults
		msg = fmt.Sprintf("%d of %d expected nodes answered; truncated=%v", succeeded, fq.Status.Coverage.Expected, truncated)
	default:
		reason = fabricapi.ReasonSucceeded
		msg = fmt.Sprintf("all %d nodes answered", succeeded)
	}
	r.setConditions(fq, metav1.ConditionTrue, metav1.ConditionTrue, failed, reason, msg)
	return reason
}

// shrinkToBudget trims the largest observations until the object fits
// maxBytes, reporting whether it changed anything. It removes route
// prefixes, then summary peers, then traceroute hops, from whichever
// observation is largest, and as a last resort replaces that observation's
// result with a ResponseTooLarge error.
func shrinkToBudget(fq *fabricapi.FabricQuery, maxBytes int) bool {
	changed := false
	for objectSize(fq) > maxBytes {
		changed = true
		i := largestObservation(fq.Status.Observations)
		if i < 0 {
			return changed
		}
		o := &fq.Status.Observations[i]
		o.Truncated = true
		switch {
		case o.Routes != nil && len(o.Routes.Prefixes) > 1:
			o.Routes.Prefixes = o.Routes.Prefixes[:len(o.Routes.Prefixes)-1]
		case o.Summary != nil && len(o.Summary.Peers) > 0:
			o.Summary.Peers = o.Summary.Peers[:len(o.Summary.Peers)-1]
		case o.Traceroute != nil && len(o.Traceroute.Hops) > 1:
			o.Traceroute.Hops = o.Traceroute.Hops[:len(o.Traceroute.Hops)-1]
		default:
			*o = fabricapi.NodeObservation{Node: o.Node, SampleTime: o.SampleTime, ErrorCode: string(errcode.ResponseTooLarge),
				ErrorMessage: "the node's answer did not fit the object budget"}
			fq.Status.Coverage.Successful--
			fq.Status.Coverage.Failed++
		}
	}
	return changed
}

func largestObservation(obs []fabricapi.NodeObservation) int {
	best, size := -1, 0
	for i := range obs {
		if obs[i].ErrorCode != "" {
			continue
		}
		b, _ := json.Marshal(obs[i])
		if len(b) > size {
			best, size = i, len(b)
		}
	}
	return best
}

// finishWithout writes a terminal status for a query that never executed.
func (r *Reconciler) finishWithout(
	ctx context.Context, fq *fabricapi.FabricQuery, reason string, accepted bool, msg string,
) error {
	now := metav1.NewTime(r.now())
	fq.Status.RequestID = fq.Spec.RequestID
	fq.Status.ProducerCluster = r.ClusterName
	fq.Status.ObservedGeneration = fq.Generation
	fq.Status.CompletionTime = &now
	acc := metav1.ConditionFalse
	if accepted {
		acc = metav1.ConditionTrue
	}
	r.setConditions(fq, acc, metav1.ConditionTrue, metav1.ConditionTrue, reason, msg)
	err := r.Client.Status().Update(ctx, fq)
	r.countWrite("terminal", err)
	if err == nil && r.Metrics != nil {
		r.Metrics.queries.WithLabelValues(string(fq.Spec.Query.Type), reason).Inc()
	}
	return client.IgnoreNotFound(err)
}

func (r *Reconciler) finishNoNodes(ctx context.Context, fq *fabricapi.FabricQuery, nodes []Node) error {
	fq.Status.Nodes = nodesToStatus(nodes)
	fq.Status.Coverage = coverage(nodes, nil)
	return r.finishWithout(ctx, fq, fabricapi.ReasonNoNodesAvailable, true,
		fmt.Sprintf("no eligible fabric-api node in this cell (%d discovered)", len(nodes)))
}

func (r *Reconciler) setConditions(
	fq *fabricapi.FabricQuery, accepted, complete, failed metav1.ConditionStatus, reason, msg string,
) {
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	acceptedReason := reason
	if accepted == metav1.ConditionTrue && (reason == fabricapi.ReasonRejected || reason == fabricapi.ReasonPending) {
		acceptedReason = fabricapi.ReasonRunning
	}
	for _, c := range []metav1.Condition{
		{Type: fabricapi.ConditionAccepted, Status: accepted, Reason: acceptedReason, Message: msg},
		{Type: fabricapi.ConditionComplete, Status: complete, Reason: reason, Message: msg},
		{Type: fabricapi.ConditionFailed, Status: failed, Reason: reason, Message: msg},
	} {
		c.ObservedGeneration = fq.Generation
		meta.SetStatusCondition(&fq.Status.Conditions, c)
	}
}

func (r *Reconciler) countWrite(kind string, err error) {
	if r.Metrics == nil {
		return
	}
	outcome := "ok"
	switch {
	case apierrors.IsConflict(err):
		outcome = "conflict"
	case err != nil:
		outcome = "error"
	}
	r.Metrics.statusWrites.WithLabelValues(kind, outcome).Inc()
}

func (r *Reconciler) isRunning(uid types.UID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.running[uid]
	return ok
}

func (r *Reconciler) cancel(uid types.UID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.running[uid]; ok {
		e.cancel()
	}
}

// cancelByName cancels the execution of a deleted object.
func (r *Reconciler) cancelByName(key types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.running {
		if e.key == key {
			e.cancel()
		}
	}
}

func terminal(fq *fabricapi.FabricQuery) bool {
	return meta.IsStatusConditionTrue(fq.Status.Conditions, fabricapi.ConditionComplete)
}

func countSelected(nodes []Node) int {
	n := 0
	for _, x := range nodes {
		if x.Selected {
			n++
		}
	}
	return n
}

// hasRealOmissions reports omitted nodes that represent missing coverage. A
// duplicate pod on a node that is otherwise covered is not one.
func hasRealOmissions(nodes []Node) bool {
	for _, n := range nodes {
		if !n.Selected && n.OmittedReason != OmitDuplicatePod {
			return true
		}
	}
	return false
}

// coverage accounts for every discovered node. Duplicate pods do not count
// as separate expected nodes.
func coverage(nodes []Node, outcomes []Outcome) fabricapi.Coverage {
	var c fabricapi.Coverage
	for _, n := range nodes {
		if n.OmittedReason == OmitDuplicatePod {
			continue
		}
		c.Expected++
		if !n.Selected {
			c.Omitted++
		}
	}
	for _, o := range outcomes {
		if o.Err != nil {
			c.Failed++
		} else {
			c.Successful++
		}
	}
	return c
}

// maxStatusNodes is the CRD's bound on status.nodes.
const maxStatusNodes = 64

// nodesToStatus renders the snapshot for status, one entry per node name,
// selected nodes first so they always fit the list bound; omitted nodes past
// the bound are counted in coverage but not listed.
func nodesToStatus(nodes []Node) []fabricapi.NodeTarget {
	ordered := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		if n.Selected {
			ordered = append(ordered, n)
		}
	}
	for _, n := range nodes {
		if !n.Selected {
			ordered = append(ordered, n)
		}
	}
	out := make([]fabricapi.NodeTarget, 0, min(len(nodes), maxStatusNodes))
	seen := map[string]bool{}
	for _, n := range ordered {
		if len(out) == maxStatusNodes {
			break
		}
		// The status list is keyed by node name; a duplicate pod is
		// recorded only through the selected pod's entry.
		if seen[n.Name] {
			continue
		}
		seen[n.Name] = true
		out = append(out, fabricapi.NodeTarget{
			Name: n.Name, Pod: n.Pod, PodUID: n.PodUID, HostIP: n.HostIP, CertificatePod: n.IdentityPod,
			Selected: n.Selected, OmittedReason: n.OmittedReason,
		})
	}
	return out
}

func nodesFromStatus(targets []fabricapi.NodeTarget) []Node {
	out := make([]Node, 0, len(targets))
	for _, t := range targets {
		out = append(out, Node{
			Name: t.Name, Pod: t.Pod, PodUID: t.PodUID, HostIP: t.HostIP, Port: DefaultPort,
			IdentityPod: t.CertificatePod, IdentityPods: []string{t.CertificatePod},
			Selected: t.Selected, OmittedReason: t.OmittedReason,
		})
	}
	return out
}
