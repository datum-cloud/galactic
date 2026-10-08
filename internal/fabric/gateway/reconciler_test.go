// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
	"go.datum.net/galactic/internal/fabric/errcode"
)

// Fixture identifiers shared by the gateway tests.
const (
	testProject = "project-a"
	testSite    = "dfw"
	testCluster = "dfw-edge-1"
	testNodeB   = "edge-b"
	testFamily  = "IPv4"
)

// fakeNodes answers Execute per node name.
type fakeNodes struct {
	mu      sync.Mutex
	calls   map[string]int
	answer  func(node string, req *fabricv1.ExecuteRequest) (*fabricv1.Observation, error)
	blocked chan struct{}
}

func (f *fakeNodes) Client(n Node) (fabricv1.FabricServiceClient, error) {
	return &fakeClient{f: f, node: n.Name}, nil
}

func (f *fakeNodes) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, c := range f.calls {
		total += c
	}
	return total
}

type fakeClient struct {
	f    *fakeNodes
	node string
}

func (c *fakeClient) Execute(
	ctx context.Context, req *fabricv1.ExecuteRequest, _ ...grpc.CallOption,
) (*fabricv1.ExecuteResponse, error) {
	c.f.mu.Lock()
	if c.f.calls == nil {
		c.f.calls = map[string]int{}
	}
	c.f.calls[c.node]++
	blocked := c.f.blocked
	c.f.mu.Unlock()
	if blocked != nil {
		select {
		case <-blocked:
		case <-ctx.Done():
			return nil, errcode.Status(errcode.Timeout, "blocked")
		}
	}
	if req.GetNode() != c.node {
		return nil, errcode.Status(errcode.WrongNode, "wrong node")
	}
	obs, err := c.f.answer(c.node, req)
	if err != nil {
		return nil, err
	}
	return &fabricv1.ExecuteResponse{Observation: obs}, nil
}

func (c *fakeClient) Info(context.Context, *fabricv1.InfoRequest, ...grpc.CallOption) (*fabricv1.InfoResponse, error) {
	return &fabricv1.InfoResponse{Node: c.node}, nil
}

func summaryAnswer(node string, _ *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
	return &fabricv1.Observation{
		Node: node, RouterId: "10.255.0.1", Asn: 65000, SampleTime: timestamppb.Now(),
		Result: &fabricv1.Observation_Summary{Summary: &fabricv1.SummaryResult{
			RouterId: "10.255.0.1", Asn: 65000, TotalPeers: 1,
			Peers: []*fabricv1.Peer{{Address: "10.1.11.1", State: "Established", Established: true}},
		}},
	}, nil
}

func fabricPod(name, node string, mod func(*corev1.Pod)) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: DefaultNamespace, UID: types.UID("uid-" + name),
			Labels: map[string]string{"app.kubernetes.io/name": "fabric-router"}},
		Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{
			{Name: "frr"},
			{Name: ContainerName, Ports: []corev1.ContainerPort{{Name: PortName, ContainerPort: 9344}}},
		}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, HostIP: "10.1.10.1", ContainerStatuses: []corev1.ContainerStatus{
			{Name: ContainerName, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
		}},
	}
	if mod != nil {
		mod(p)
	}
	return p
}

func newQuery(name string, mod func(*fabricapi.FabricQuery)) *fabricapi.FabricQuery {
	fq := &fabricapi.FabricQuery{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testProject, UID: types.UID("fq-" + name), Generation: 1,
			CreationTimestamp: metav1.Now()},
		Spec: fabricapi.FabricQuerySpec{
			RequestID:   "req-" + name,
			Source:      fabricapi.PublicQueryReference{UID: "pub-1", Cluster: testProject, Namespace: "default", Name: name},
			Query:       fabricapi.QuerySpec{Type: "BGPSummary", AddressFamily: testFamily},
			Site:        testSite,
			ClusterName: testCluster,
			ExpiresAt:   metav1.NewTime(time.Now().Add(time.Minute)),
		},
	}
	if mod != nil {
		mod(fq)
	}
	return fq
}

type harness struct {
	r     *Reconciler
	c     client.Client
	nodes *fakeNodes
}

func newHarness(t *testing.T, objs []client.Object, funcs *interceptor.Funcs) *harness {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := fabricapi.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	b := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&fabricapi.FabricQuery{}).WithObjects(objs...)
	if funcs != nil {
		b = b.WithInterceptorFuncs(*funcs)
	}
	c := b.Build()
	nodes := &fakeNodes{answer: summaryAnswer}
	sel, _ := labels.Parse(DefaultPodSelector)
	r := &Reconciler{
		Client: c, APIReader: c, Site: testSite, ClusterName: testCluster,
		Discoverer: &Discoverer{Reader: c, Namespace: DefaultNamespace, Selector: sel},
		Runner:     &Runner{Clients: nodes, Executor: NewExecutor(8, 2, 64)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); r.Wait() })
	r.Start(ctx)
	return &harness{r: r, c: c, nodes: nodes}
}

func (h *harness) reconcile(t *testing.T, name string) ctrl.Result {
	t.Helper()
	res, err := h.r.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testProject, Name: name}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return res
}

func (h *harness) get(t *testing.T, name string) *fabricapi.FabricQuery {
	t.Helper()
	var fq fabricapi.FabricQuery
	if err := h.c.Get(context.Background(), types.NamespacedName{Namespace: testProject, Name: name}, &fq); err != nil {
		t.Fatal(err)
	}
	return &fq
}

// waitTerminal reconciles until the query is complete.
func (h *harness) waitTerminal(t *testing.T, name string) *fabricapi.FabricQuery {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		fq := h.get(t, name)
		if terminal(fq) {
			return fq
		}
		if time.Now().After(deadline) {
			t.Fatalf("query never completed: %+v", fq.Status.Conditions)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func condition(fq *fabricapi.FabricQuery, typ string) metav1.Condition {
	c := meta.FindStatusCondition(fq.Status.Conditions, typ)
	if c == nil {
		return metav1.Condition{}
	}
	return *c
}

func wantOutcome(t *testing.T, fq *fabricapi.FabricQuery, accepted, failed metav1.ConditionStatus, reason string) {
	t.Helper()
	acc := condition(fq, fabricapi.ConditionAccepted)
	comp := condition(fq, fabricapi.ConditionComplete)
	fail := condition(fq, fabricapi.ConditionFailed)
	if acc.Status != accepted || comp.Status != metav1.ConditionTrue || fail.Status != failed || comp.Reason != reason {
		t.Fatalf("conditions accepted=%s complete=%s/%s failed=%s, want accepted=%s complete=True/%s failed=%s",
			acc.Status, comp.Status, comp.Reason, fail.Status, accepted, reason, failed)
	}
	if fq.Status.CompletionTime == nil || fq.Status.RequestID != fq.Spec.RequestID ||
		fq.Status.ProducerCluster != testCluster {
		t.Fatalf("terminal status missing completion/correlation: %+v", fq.Status)
	}
	for _, c := range fq.Status.Conditions {
		if c.ObservedGeneration != fq.Generation {
			t.Errorf("condition %s observedGeneration %d", c.Type, c.ObservedGeneration)
		}
	}
}

func TestReconcileSucceeded(t *testing.T) {
	h := newHarness(t, []client.Object{
		newQuery("q1", nil),
		fabricPod("fr-a", "edge-a", nil),
		fabricPod("fr-b", testNodeB, nil),
	}, nil)
	h.reconcile(t, "q1")
	fq := h.waitTerminal(t, "q1")
	wantOutcome(t, fq, metav1.ConditionTrue, metav1.ConditionFalse, fabricapi.ReasonSucceeded)
	if len(fq.Status.Observations) != 2 || fq.Status.Observations[0].Node != "edge-a" ||
		fq.Status.Observations[0].Summary == nil {
		t.Fatalf("observations = %+v", fq.Status.Observations)
	}
	if c := fq.Status.Coverage; c.Expected != 2 || c.Successful != 2 || c.Failed != 0 || c.Omitted != 0 {
		t.Errorf("coverage = %+v", c)
	}
	if fq.Status.Attempt != 1 || fq.Status.StartTime == nil || len(fq.Status.Nodes) != 2 {
		t.Errorf("start marker = %+v", fq.Status)
	}

	// A terminal query is never executed again.
	calls := h.nodes.count()
	h.reconcile(t, "q1")
	time.Sleep(20 * time.Millisecond)
	if h.nodes.count() != calls {
		t.Error("a complete query was executed again")
	}
}

func TestReconcilePartialAndOmitted(t *testing.T) {
	h := newHarness(t, []client.Object{
		newQuery("q", nil),
		fabricPod("fr-a", "edge-a", nil),
		fabricPod("fr-b", testNodeB, nil),
		fabricPod("fr-c", "edge-c", func(p *corev1.Pod) { p.Status.ContainerStatuses = nil }),
		fabricPod("fr-d", "edge-d", func(p *corev1.Pod) { p.Spec.Containers = p.Spec.Containers[:1] }), // no sidecar
	}, nil)
	h.nodes.answer = func(node string, req *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		if node == testNodeB {
			return nil, errcode.Status(errcode.FRRUnavailable, "bgpd restarting")
		}
		return summaryAnswer(node, req)
	}
	h.reconcile(t, "q")
	fq := h.waitTerminal(t, "q")
	wantOutcome(t, fq, metav1.ConditionTrue, metav1.ConditionFalse, fabricapi.ReasonPartialResults)
	if c := fq.Status.Coverage; c.Expected != 3 || c.Successful != 1 || c.Failed != 1 || c.Omitted != 1 {
		t.Errorf("coverage = %+v", c)
	}
	if fq.Status.Observations[1].ErrorCode != string(errcode.FRRUnavailable) {
		t.Errorf("edge-b = %+v", fq.Status.Observations[1])
	}
	var omitted fabricapi.NodeTarget
	for _, n := range fq.Status.Nodes {
		if n.Name == "edge-c" {
			omitted = n
		}
	}
	if omitted.Selected || omitted.OmittedReason != OmitSidecarNotReady {
		t.Errorf("edge-c = %+v", omitted)
	}
}

func TestReconcileExecutionFailed(t *testing.T) {
	h := newHarness(t, []client.Object{newQuery("q", nil), fabricPod("fr-a", "edge-a", nil)}, nil)
	h.nodes.answer = func(string, *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		return nil, errcode.Status(errcode.FRRVersionUnsupported, "11.0")
	}
	h.reconcile(t, "q")
	wantOutcome(t, h.waitTerminal(t, "q"), metav1.ConditionTrue, metav1.ConditionTrue, fabricapi.ReasonExecutionFailed)
}

func TestReconcileNoNodes(t *testing.T) {
	h := newHarness(t, []client.Object{newQuery("q", nil),
		fabricPod("fr-a", "edge-a", func(p *corev1.Pod) { p.Status.Phase = corev1.PodPending })}, nil)
	h.reconcile(t, "q")
	fq := h.get(t, "q")
	wantOutcome(t, fq, metav1.ConditionTrue, metav1.ConditionTrue, fabricapi.ReasonNoNodesAvailable)
	if fq.Status.Coverage.Omitted != 1 || h.nodes.count() != 0 {
		t.Errorf("coverage = %+v calls = %d", fq.Status.Coverage, h.nodes.count())
	}
}

func TestReconcileRejected(t *testing.T) {
	h := newHarness(t, []client.Object{
		newQuery("noncanon", func(fq *fabricapi.FabricQuery) {
			fq.Spec.Query = fabricapi.QuerySpec{Type: "Community", Target: "065001:100", AddressFamily: testFamily}
		}),
		newQuery("hostname", func(fq *fabricapi.FabricQuery) {
			fq.Spec.Query = fabricapi.QuerySpec{Type: "Ping", Target: "example.com", AddressFamily: testFamily}
		}),
		newQuery("toolong", func(fq *fabricapi.FabricQuery) {
			fq.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(time.Hour))
		}),
		fabricPod("fr-a", "edge-a", nil),
	}, nil)
	for _, name := range []string{"noncanon", "hostname", "toolong"} {
		h.reconcile(t, name)
		fq := h.get(t, name)
		wantOutcome(t, fq, metav1.ConditionFalse, metav1.ConditionTrue, fabricapi.ReasonRejected)
		if !strings.HasPrefix(condition(fq, fabricapi.ConditionComplete).Message, string(errcode.InvalidQuery)) {
			t.Errorf("%s: message = %q", name, condition(fq, fabricapi.ConditionComplete).Message)
		}
	}
	if h.nodes.count() != 0 {
		t.Error("a rejected query reached a node")
	}
}

func TestReconcileExpiredBeforeStart(t *testing.T) {
	h := newHarness(t, []client.Object{
		newQuery("q", func(fq *fabricapi.FabricQuery) { fq.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(-time.Second)) }),
		fabricPod("fr-a", "edge-a", nil),
	}, nil)
	h.reconcile(t, "q")
	wantOutcome(t, h.get(t, "q"), metav1.ConditionFalse, metav1.ConditionTrue, fabricapi.ReasonDeadlineExceeded)
	if h.nodes.count() != 0 {
		t.Error("an expired query reached a node")
	}
}

func TestReconcileDeadlineDuringExecution(t *testing.T) {
	h := newHarness(t, []client.Object{
		newQuery("q", func(fq *fabricapi.FabricQuery) {
			fq.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(2 * time.Second))
		}),
		fabricPod("fr-a", "edge-a", nil),
		fabricPod("fr-b", testNodeB, nil),
	}, nil)
	h.nodes.answer = func(node string, req *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		if node == testNodeB {
			time.Sleep(4 * time.Second)
			return nil, errcode.Status(errcode.Timeout, "late")
		}
		return summaryAnswer(node, req)
	}
	h.reconcile(t, "q")
	fq := h.waitTerminal(t, "q")
	wantOutcome(t, fq, metav1.ConditionTrue, metav1.ConditionFalse, fabricapi.ReasonDeadlineExceeded)
	if fq.Status.Coverage.Successful != 1 || fq.Status.Coverage.Failed != 1 {
		t.Errorf("coverage = %+v", fq.Status.Coverage)
	}
}

func TestReconcileResumesOnFixedSnapshot(t *testing.T) {
	start := metav1.Now().Rfc3339Copy()
	q := newQuery("q", func(fq *fabricapi.FabricQuery) {
		fq.Status = fabricapi.FabricQueryStatus{
			RequestID: fq.Spec.RequestID, ProducerCluster: testCluster, ObservedGeneration: 1, Attempt: 1, StartTime: &start,
			Nodes: []fabricapi.NodeTarget{
				{Name: "edge-a", Pod: "fr-a", PodUID: "uid-fr-a", HostIP: "10.1.10.1", Selected: true},
			},
		}
	})
	// edge-b appeared after the first attempt started; the resumed attempt
	// must not add it.
	h := newHarness(t, []client.Object{q, fabricPod("fr-a", "edge-a", nil), fabricPod("fr-b", testNodeB, nil)}, nil)
	var ids []string
	var mu sync.Mutex
	h.nodes.answer = func(node string, req *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		mu.Lock()
		ids = append(ids, req.GetRequestId())
		mu.Unlock()
		return summaryAnswer(node, req)
	}
	h.reconcile(t, "q")
	fq := h.waitTerminal(t, "q")
	if fq.Status.Attempt != 2 || len(fq.Status.Observations) != 1 || !start.Equal(fq.Status.StartTime) {
		t.Fatalf("resumed status = %+v", fq.Status)
	}
	if len(ids) != 1 || ids[0] != "req-q" {
		t.Errorf("resumed with request IDs %v; the same ID lets nodes suppress repeats", ids)
	}
}

func TestReconcileRetriesStatusConflictWithoutRerunning(t *testing.T) {
	var conflicts atomic.Int32
	funcs := &interceptor.Funcs{
		SubResourceUpdate: func(
			ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption,
		) error {
			fq := obj.(*fabricapi.FabricQuery)
			if terminal(fq) && conflicts.Add(1) <= 2 {
				gr := schema.GroupResource{Group: "network.datumapis.com", Resource: "fabricqueries"}
				return apierrors.NewConflict(gr, fq.Name, nil)
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	}
	h := newHarness(t, []client.Object{newQuery("q", nil), fabricPod("fr-a", "edge-a", nil)}, funcs)
	h.reconcile(t, "q")
	fq := h.waitTerminal(t, "q")
	wantOutcome(t, fq, metav1.ConditionTrue, metav1.ConditionFalse, fabricapi.ReasonSucceeded)
	if conflicts.Load() < 3 || h.nodes.count() != 1 {
		t.Errorf("conflicts = %d, node calls = %d; want retries without rerunning", conflicts.Load(), h.nodes.count())
	}
}

func TestReconcileDeletionCancels(t *testing.T) {
	h := newHarness(t, []client.Object{newQuery("q", nil), fabricPod("fr-a", "edge-a", nil)}, nil)
	h.nodes.blocked = make(chan struct{})
	h.reconcile(t, "q")
	deadline := time.Now().Add(5 * time.Second)
	for h.nodes.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never called the node")
		}
		time.Sleep(time.Millisecond)
	}
	if err := h.c.Delete(context.Background(), newQuery("q", nil)); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t, "q")
	done := make(chan struct{})
	go func() { h.r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deletion did not cancel the execution")
	}
}

func TestReconcileIgnoresOtherCells(t *testing.T) {
	h := newHarness(t, []client.Object{
		newQuery("q", func(fq *fabricapi.FabricQuery) { fq.Spec.ClusterName = "sjc-edge-1" }),
		fabricPod("fr-a", "edge-a", nil),
	}, nil)
	h.reconcile(t, "q")
	if fq := h.get(t, "q"); len(fq.Status.Conditions) != 0 || h.nodes.count() != 0 {
		t.Errorf("another cell's query was touched: %+v", fq.Status)
	}
}

func TestShrinkToObjectBudget(t *testing.T) {
	h := newHarness(t, []client.Object{
		newQuery("q", func(fq *fabricapi.FabricQuery) {
			fq.Spec.Budgets.MaxObjectBytes = 8 << 10
			fq.Spec.Query = fabricapi.QuerySpec{Type: "RouteLookup", Target: "198.51.100.0/24", AddressFamily: testFamily}
		}),
		fabricPod("fr-a", "edge-a", nil), fabricPod("fr-b", testNodeB, nil),
	}, nil)
	h.nodes.answer = func(node string, _ *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		// Ignore the allowance and answer far over budget.
		prefixes := make([]*fabricv1.PrefixObservation, 0, 60)
		for i := range 60 {
			prefixes = append(prefixes, &fabricv1.PrefixObservation{
				Prefix: "198.51.100.0/24", TotalPaths: 1, Paths: []*fabricv1.Path{{
					Best: true, AsPath: strings.Repeat("65001 ", 20), Communities: []string{"65001:1", "65001:2", "65001:3"},
					PeerAddress: "10.1.11.1", PeerHostname: "transit-router-" + string(rune('a'+i%26)),
				}},
			})
		}
		m := uint32(60)
		return &fabricv1.Observation{Node: node, Matched: &m, MatchedIsExact: true,
			Result: &fabricv1.Observation_Routes{Routes: &fabricv1.RouteResult{Prefixes: prefixes}}}, nil
	}
	h.reconcile(t, "q")
	fq := h.waitTerminal(t, "q")
	b, _ := json.Marshal(fq)
	if len(b) > 8<<10 {
		t.Fatalf("object is %d bytes, over the 8 KiB budget", len(b))
	}
	wantOutcome(t, fq, metav1.ConditionTrue, metav1.ConditionFalse, fabricapi.ReasonPartialResults)
	for _, o := range fq.Status.Observations {
		if o.ErrorCode == "" && (!o.Truncated || o.Matched == nil || *o.Matched != 60) {
			t.Errorf("shaped observation %s: truncated=%v matched=%v", o.Node, o.Truncated, o.Matched)
		}
	}
}

func TestNodesToStatusFitsCRDBound(t *testing.T) {
	nodes := make([]Node, 0, 80)
	for i := range 80 {
		n := Node{Name: "node-" + strconv.Itoa(i), Pod: "pod-" + strconv.Itoa(i)}
		// Selected nodes come last in discovery order, to prove they are
		// kept ahead of omitted ones.
		if i >= 48 {
			n.Selected = true
		} else {
			n.OmittedReason = OmitPodNotRunning
		}
		nodes = append(nodes, n)
	}
	out := nodesToStatus(nodes)
	if len(out) != maxStatusNodes {
		t.Fatalf("listed %d nodes, want the CRD bound %d", len(out), maxStatusNodes)
	}
	selected := 0
	for _, n := range out {
		if n.Selected {
			selected++
		}
	}
	if selected != 32 {
		t.Errorf("listed %d selected nodes, want all 32", selected)
	}
	if c := coverage(nodes, nil); c.Expected != 80 || c.Omitted != 48 {
		t.Errorf("coverage = %+v; it must count every discovered node", c)
	}
}

func certsPod(name, node string, created time.Time, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: DefaultNamespace, CreationTimestamp: metav1.NewTime(created),
			Labels: map[string]string{"app.kubernetes.io/name": "fabric-api-certs"}},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: phase},
	}
}

const certsANew = "certs-a-new"

func TestDiscoveryIdentityFromCertsPods(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	now := time.Now()
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		fabricPod("fr-a", "edge-a", nil), fabricPod("fr-b", "edge-b", nil), fabricPod("fr-c", "edge-c", nil),
		certsPod("certs-a-old", "edge-a", now.Add(-time.Hour), corev1.PodRunning),
		certsPod(certsANew, "edge-a", now, corev1.PodRunning),
		certsPod("certs-b", "edge-b", now, corev1.PodPending),
	).Build()
	sel, _ := labels.Parse(DefaultPodSelector)
	certsSel, _ := labels.Parse(DefaultCertsSelector)
	d := &Discoverer{Reader: c, Namespace: DefaultNamespace, Selector: sel, CertsSelector: certsSel}
	nodes, err := d.Snapshot(t.Context(), nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Node{}
	for _, n := range nodes {
		got[n.Name] = n
	}
	if a := got["edge-a"]; !a.Selected || a.IdentityPod != certsANew ||
		!slices.Equal(a.IdentityPods, []string{certsANew, "certs-a-old"}) {
		t.Errorf("edge-a = %+v; want the newest running certs pod first, then the one it replaces", a)
	}
	for _, name := range []string{"edge-b", "edge-c"} {
		if n := got[name]; n.Selected || n.OmittedReason != OmitNoCertificate {
			t.Errorf("%s = %+v; want omitted with %s", name, n, OmitNoCertificate)
		}
	}
	if fq := nodesFromStatus(nodesToStatus(nodes)); fq[0].IdentityPod != certsANew {
		t.Errorf("identity pod lost through status: %+v", fq[0])
	}
}

// Losing leadership mid-execution stops the run without writing a terminal
// result; the next leader resumes it on the same snapshot and request ID.
func TestReconcileLeadershipLossLeavesQueryResumable(t *testing.T) {
	h := newHarness(t, []client.Object{newQuery("q", nil), fabricPod("fr-a", "edge-a", nil)}, nil)
	h.nodes.blocked = make(chan struct{})
	// Replace the harness's leader context with one this test controls.
	leader, lose := context.WithCancel(context.Background())
	h.r.Start(leader)
	h.reconcile(t, "q")
	deadline := time.Now().Add(5 * time.Second)
	for h.nodes.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never called the node")
		}
		time.Sleep(time.Millisecond)
	}
	lose()
	h.r.Wait()
	fq := h.get(t, "q")
	if terminal(fq) || fq.Status.Attempt != 1 || fq.Status.StartTime == nil {
		t.Fatalf("after leadership loss: %+v", fq.Status)
	}

	// The next leader resumes it.
	h.nodes.blocked = nil
	next, stop := context.WithCancel(context.Background())
	defer stop()
	h.r.Start(next)
	h.reconcile(t, "q")
	fq = h.waitTerminal(t, "q")
	wantOutcome(t, fq, metav1.ConditionTrue, metav1.ConditionFalse, fabricapi.ReasonSucceeded)
	if fq.Status.Attempt != 2 {
		t.Errorf("attempt = %d, want 2", fq.Status.Attempt)
	}
}
