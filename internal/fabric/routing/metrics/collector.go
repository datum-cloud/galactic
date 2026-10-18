// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics exports the fabric routing fleet's state as Prometheus
// metrics: each FabricRouterDeployment's source, epochs, heartbeat,
// conditions and staged candidate, each outstanding
// FabricReleaseAuthorization, and each fabric router's compile result. It
// reads the manager's cache at scrape time, so a deleted object's series go
// with it, and exports only while its replica leads, so a standby replica
// never duplicates the fleet's series.
//
// Revision names are never labels. Every series is one deployment, one
// router, one outstanding release, or a count by phase.
package metrics

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	prefix = "galactic_fabric_routing_"

	labelNamespace = "namespace"

	// defaultTimeout bounds the cache reads of one scrape.
	defaultTimeout = 5 * time.Second
)

// deploymentConditions are the condition types exported per deployment.
// The agent writes no others; the fixed set keeps the series bounded.
var deploymentConditions = []string{
	networkv1alpha1.FabricConditionAccepted,
	networkv1alpha1.FabricConditionStaged,
	networkv1alpha1.FabricConditionProgrammed,
	networkv1alpha1.FabricConditionReady,
	networkv1alpha1.FabricConditionDegraded,
	networkv1alpha1.FabricConditionRecoveryConflict,
	networkv1alpha1.FabricConditionBootstrapping,
}

var (
	deploymentLabels = []string{labelNamespace, "deployment", "node"}

	deploymentInfo = prometheus.NewDesc(prefix+"deployment_info",
		"1 for each FabricRouterDeployment: its node, the source its spec asks for and the source the node agent "+
			"reports honouring (empty until it reports).",
		append(deploymentLabels, "source", "effective_source"), nil)
	activationEpoch = prometheus.NewDesc(prefix+"deployment_activation_epoch",
		"The deployment's spec.activationEpoch: the newest promotion.", deploymentLabels, nil)
	appliedEpoch = prometheus.NewDesc(prefix+"deployment_applied_epoch",
		"The last epoch the node agent committed, from status.appliedEpoch.", deploymentLabels, nil)
	lastEpoch = prometheus.NewDesc(prefix+"deployment_last_epoch",
		"The newest epoch the node agent journaled, labelled with the stage it reached.",
		append(deploymentLabels, "stage"), nil)
	heartbeat = prometheus.NewDesc(prefix+"deployment_heartbeat_timestamp_seconds",
		"When the node agent last reported, from status.heartbeatTime. Absent until it first reports.",
		deploymentLabels, nil)
	bootAuthorized = prometheus.NewDesc(prefix+"deployment_boot_authorized_until_timestamp_seconds",
		"When the committed configuration stops being restorable at boot without the API.", deploymentLabels, nil)
	condition = prometheus.NewDesc(prefix+"deployment_condition",
		"1 for each condition the node agent reports, with its status and reason.",
		append(deploymentLabels, "type", "status", "reason"), nil)
	staged = prometheus.NewDesc(prefix+"deployment_staged",
		"1 while the node agent reports a validated candidate, labelled with what applying it would disturb.",
		append(deploymentLabels, "class"), nil)
	stagedLines = prometheus.NewDesc(prefix+"deployment_staged_lines",
		"Lines applying the staged candidate would add or remove.", append(deploymentLabels, "change"), nil)
	candidateDiffers = prometheus.NewDesc(prefix+"deployment_candidate_differs",
		"1 when the deployment's candidate revision is not its active revision, so a release would change it.",
		deploymentLabels, nil)

	releases = prometheus.NewDesc(prefix+"releases",
		"FabricReleaseAuthorizations by routing domain, phase and whether a failed one's recovery was verified.",
		[]string{labelNamespace, "routing_domain", "phase", "recovery_verified"}, nil)
	releaseOutstanding = prometheus.NewDesc(prefix+"release_outstanding",
		"1 for each release still blocking its routing domain: Pending, Started, Unknown, or Failed without "+
			"verified recovery.",
		[]string{labelNamespace, "release", "routing_domain", "type", "phase"}, nil)

	routerAccepted = prometheus.NewDesc(prefix+"router_accepted",
		"1 when a fabric router's latest inputs compiled into a revision, 0 when the controller refused them; "+
			"reason is the Accepted condition's.",
		[]string{labelNamespace, "router", "node", "reason"}, nil)

	collectSuccess = prometheus.NewDesc(prefix+"collect_success",
		"1 when this scrape read every object of the kind from the cache, 0 when the read failed and the "+
			"kind's series are missing from it.",
		[]string{"kind"}, nil)
)

// Kinds the collector reads, as its collect_success series name them.
const (
	kindRouterClasses = "bgprouterclasses"
	kindRouters       = "bgprouters"
	kindDeployments   = "fabricrouterdeployments"
	kindReleases      = "fabricreleaseauthorizations"
)

// Collector reads the fleet from a cache-backed reader at scrape time.
// Register it with a Prometheus registry and add it to the manager, which
// starts it once the replica leads.
type Collector struct {
	// Reader is the manager's cache-backed client.
	Reader client.Reader
	// Rollout exports deployments and releases, which only the rollout
	// manager creates.
	Rollout bool
	// Timeout bounds the cache reads of one scrape. Zero selects 5s.
	Timeout time.Duration

	leading atomic.Bool
}

// Start marks the replica as leading until ctx ends. The manager calls it
// only once the replica wins the leader election.
func (c *Collector) Start(ctx context.Context) error {
	c.leading.Store(true)
	<-ctx.Done()
	c.leading.Store(false)
	return nil
}

// NeedLeaderElection reports that only the leader exports the fleet.
func (c *Collector) NeedLeaderElection() bool { return true }

// Describe sends every descriptor the collector can emit.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		deploymentInfo, activationEpoch, appliedEpoch, lastEpoch, heartbeat, bootAuthorized, condition, staged,
		stagedLines, candidateDiffers, releases, releaseOutstanding, routerAccepted, collectSuccess,
	} {
		ch <- d
	}
}

// Collect emits the fleet's current state. A list that fails is logged,
// its series are left out of this scrape and its kind's collect_success is
// 0, so one unreadable kind never fails the scrape of the controller's
// other metrics and is still seen.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if !c.leading.Load() {
		return
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c.collectRouters(ctx, ch)
	if !c.Rollout {
		return
	}
	var deps networkv1alpha1.FabricRouterDeploymentList
	if list(ctx, ch, c.Reader, &deps, kindDeployments) {
		for i := range deps.Items {
			collectDeployment(ch, &deps.Items[i])
		}
	}
	var auths networkv1alpha1.FabricReleaseAuthorizationList
	if list(ctx, ch, c.Reader, &auths, kindReleases) {
		collectReleases(ch, auths.Items)
	}
}

// list reads every object of kind into into, emits whether it could, and
// reports whether it did.
func list(ctx context.Context, ch chan<- prometheus.Metric, r client.Reader, into client.ObjectList, kind string) bool {
	err := r.List(ctx, into)
	ok := 1.0
	if err != nil {
		ok = 0
		slog.Warn("could not list objects for fabric routing metrics", "kind", kind, "error", err)
	}
	ch <- prometheus.MustNewConstMetric(collectSuccess, prometheus.GaugeValue, ok, kind)
	return err == nil
}

func collectDeployment(ch chan<- prometheus.Metric, d *networkv1alpha1.FabricRouterDeployment) {
	ls := []string{d.Namespace, d.Name, d.Spec.Target.NodeName}
	gauge := func(desc *prometheus.Desc, v float64, extra ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, append(ls[:3:3], extra...)...)
	}
	st := &d.Status
	gauge(deploymentInfo, 1, string(d.Spec.Source), string(st.EffectiveSource))
	gauge(activationEpoch, float64(d.Spec.ActivationEpoch))
	gauge(appliedEpoch, float64(st.AppliedEpoch))
	if len(st.Epochs) > 0 {
		// Newest first, as the agent writes them.
		gauge(lastEpoch, float64(st.Epochs[0].Epoch), string(st.Epochs[0].Stage))
	}
	if st.HeartbeatTime != nil {
		gauge(heartbeat, seconds(st.HeartbeatTime))
	}
	if st.BootAuthorizedUntil != nil {
		gauge(bootAuthorized, seconds(st.BootAuthorizedUntil))
	}
	for _, t := range deploymentConditions {
		if cond := meta.FindStatusCondition(st.Conditions, t); cond != nil {
			gauge(condition, 1, t, string(cond.Status), cond.Reason)
		}
	}
	if s := st.Staged; s != nil {
		gauge(staged, 1, string(s.Class))
		gauge(stagedLines, float64(s.LinesAdded), "added")
		gauge(stagedLines, float64(s.LinesRemoved), "removed")
	}
	differs := 0.0
	if cand := d.Spec.CandidateRevisionRef; cand != nil &&
		(d.Spec.ActiveRevisionRef == nil || d.Spec.ActiveRevisionRef.Name != cand.Name) {
		differs = 1
	}
	gauge(candidateDiffers, differs)
}

func collectReleases(ch chan<- prometheus.Metric, items []networkv1alpha1.FabricReleaseAuthorization) {
	type key struct{ namespace, domain, phase, verified string }
	counts := map[key]int{}
	for i := range items {
		a := &items[i]
		phase := a.Status.Phase
		if phase == "" {
			// The controller has not looked at it yet: it waits to start.
			phase = networkv1alpha1.FabricReleasePhasePending
		}
		counts[key{a.Namespace, a.Spec.RoutingDomain, string(phase), strconv.FormatBool(a.Status.RecoveryVerified)}]++
		if a.Status.Outstanding() {
			ch <- prometheus.MustNewConstMetric(releaseOutstanding, prometheus.GaugeValue, 1,
				a.Namespace, a.Name, a.Spec.RoutingDomain, string(a.Spec.Type), string(phase))
		}
	}
	for k, n := range counts {
		ch <- prometheus.MustNewConstMetric(releases, prometheus.GaugeValue, float64(n),
			k.namespace, k.domain, k.phase, k.verified)
	}
}

// collectRouters emits the compile result of every router whose class
// names the fabric router controller. Routers are not read when no class
// does.
func (c *Collector) collectRouters(ctx context.Context, ch chan<- prometheus.Metric) {
	var classes networkv1alpha1.BGPRouterClassList
	if !list(ctx, ch, c.Reader, &classes, kindRouterClasses) {
		return
	}
	fabric := map[string]bool{}
	for _, cl := range classes.Items {
		if cl.Spec.ControllerName == networkv1alpha1.FabricRouterControllerName {
			fabric[cl.Name] = true
		}
	}
	if len(fabric) == 0 {
		return
	}
	var routers networkv1alpha1.BGPRouterList
	if !list(ctx, ch, c.Reader, &routers, kindRouters) {
		return
	}
	for i := range routers.Items {
		r := &routers.Items[i]
		if r.Spec.RouterClassName == nil || !fabric[*r.Spec.RouterClassName] {
			continue
		}
		cond := meta.FindStatusCondition(r.Status.Conditions, networkv1alpha1.ConditionTypeAccepted)
		if cond == nil {
			continue
		}
		v := 0.0
		if cond.Status == metav1.ConditionTrue {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(routerAccepted, prometheus.GaugeValue, v,
			r.Namespace, r.Name, r.Spec.TargetRef.Name, cond.Reason)
	}
}

func seconds(t *metav1.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}
