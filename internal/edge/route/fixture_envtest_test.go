// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/provider"
)

const (
	tenantNS     = "tenant"
	providerNS   = "edge"
	providerName = "connect-ip"
	nodeA        = "edge-1"
	nodeB        = "edge-2"
	vpcID        = "000000abc"

	socketAccess = "SocketAccess"
	grantPrefix  = "fd00:10:0:f::/64"
)

var repoRoot = filepath.Join("..", "..", "..")

// params is the cell's timing; the tests advance the leader's clock by hand.
var params = claim.Params{Duration: 15 * time.Second, MaxDrift: 0.001, Margin: 500 * time.Millisecond,
	MaxSkew: 2 * time.Second}

type manualClock struct {
	mu  sync.Mutex
	now time.Duration
}

func (c *manualClock) read() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now += d
}

// fixture is a real API server with the CRDs, galactic-controller's RBAC and
// the Galactic Edge policies, one tenant VPC granted to one approved
// provider, and the route, index and reaper reconcilers called directly
// with a hand-advanced leader clock and wall clock.
type fixture struct {
	t      *testing.T
	cfg    *rest.Config
	scheme *runtime.Scheme
	admin  client.Client
	vpc    *cloudv1alpha1.VPC
	svc    *galacticv1alpha1.EdgeService
	clock  *manualClock
	wall   time.Time
	routes *Reconciler
	index  *IndexReconciler
	reaper *InstanceReaper
}

func startAPI(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(repoRoot, "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = te.Stop() })
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, cfg: cfg, scheme: scheme, admin: admin, clock: &manualClock{now: time.Hour},
		wall: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	for _, n := range []string{"galactic-system", tenantNS, providerNS} {
		f.create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	for _, path := range []string{
		filepath.Join(repoRoot, "config", "galactic-controller", "serviceaccount.yaml"),
		filepath.Join(repoRoot, "config", "galactic-controller", "rbac.yaml"),
		filepath.Join(repoRoot, "config", "galactic-edge", "controller-rbac.yaml"),
		filepath.Join(repoRoot, "config", "galactic-edge", "rbac.yaml"),
		filepath.Join(repoRoot, "config", "galactic-edge", "policies.yaml"),
	} {
		f.apply(path)
	}
	f.vpc = &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: tenantNS},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd00:10::/48"}},
	}
	f.create(f.vpc)
	p := &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: providerName},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			ContractVersions: []string{"v1alpha1"},
			Capabilities: []galacticv1alpha1.EdgeCapability{
				{Name: socketAccess, Version: "v1"}, {Name: PrefixReachability, Version: "v1"},
			},
			ServiceAccounts: []galacticv1alpha1.ServiceAccountReference{{Namespace: providerNS, Name: providerName}},
			Configuration:   galacticv1alpha1.ConfigurationKind{Group: "connect.example.com", Kind: "Config"},
		},
	}
	f.create(p)
	p.Status.Approved = true
	if err := admin.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	f.svc = &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: tenantNS},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: providerName},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: "prod", UID: string(f.vpc.UID)},
			Capabilities: []string{socketAccess, PrefixReachability},
			Prefixes:     []string{grantPrefix},
			ClientPool:   "fd00:10:0:e::/120",
		},
	}
	f.create(f.svc)
	f.routes = &Reconciler{Client: admin, APIReader: admin, Params: params, Clock: f.clock.read, Now: f.now}
	f.index = &IndexReconciler{Client: admin, APIReader: admin, Params: params, Clock: f.clock.read}
	f.reaper = &InstanceReaper{Client: admin, APIReader: admin, Params: params, Clock: f.clock.read}
	return f
}

func (f *fixture) now() time.Time { return f.wall }

func (f *fixture) apply(path string) {
	f.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, doc := range strings.Split(string(data), "\n---\n") {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
			f.t.Fatal(err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		if err := f.admin.Create(context.Background(), obj); err != nil {
			f.t.Fatalf("apply %s %s: %v", obj.GetKind(), obj.GetName(), err)
		}
	}
}

func (f *fixture) create(obj client.Object) {
	f.t.Helper()
	if err := f.admin.Create(context.Background(), obj); err != nil {
		f.t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

// podHolder is one provider pod with its instance, attachment and lease.
type podHolder struct {
	pod  *corev1.Pod
	inst *galacticv1alpha1.EdgeInstance
	att  *galacticv1alpha1.EdgeAttachment
	// incarnation of the lease: its Lease's UID.
	incarnation string
}

// newHolder creates a provider pod on node, its instance holding its lease
// at epoch 1, and an attachment as core and the node leave it once
// admitted, allocated, programmed and ready.
func (f *fixture) newHolder(name, node, address string) *podHolder {
	f.t.Helper()
	ctx := context.Background()
	h := &podHolder{}
	h.pod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: providerNS},
		Spec: corev1.PodSpec{NodeName: node, ServiceAccountName: providerName,
			Containers: []corev1.Container{{Name: "p", Image: "p"}}},
	}
	f.create(h.pod)
	h.inst = &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: provider.InstanceName(string(h.pod.UID)), Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeInstanceSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerName},
			PodName: name, PodUID: string(h.pod.UID), NodeName: node, BootID: "boot"},
	}
	f.create(h.inst)
	f.setLease(h, 1, 0, false)
	h.att = &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "att-" + name, Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerName},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{
				Namespace: tenantNS, Name: f.svc.Name, UID: string(f.svc.UID),
			},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: h.inst.Name},
			PodUID:          string(h.pod.UID),
			ContractVersion: "v1alpha1",
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: socketAccess, Version: "v1"}},
		},
	}
	f.create(h.att)
	h.att.Status = galacticv1alpha1.EdgeAttachmentStatus{NodeName: node, VPC: vpcID, Address: address}
	for _, c := range []string{galacticv1alpha1.EdgeAttachmentAdmitted, galacticv1alpha1.EdgeAttachmentAllocated,
		galacticv1alpha1.EdgeAttachmentProgrammed, galacticv1alpha1.EdgeAttachmentReady} {
		meta.SetStatusCondition(&h.att.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue, Reason: c})
	}
	if err := f.admin.Status().Update(ctx, h.att); err != nil {
		f.t.Fatal(err)
	}
	return h
}

// leaseHolder is the provider process every fixture lease names.
const leaseHolder = "proc"

// setLease writes the podHolder's lease through the provider's store, as
// its provider process would, creating its Lease on first use.
func (f *fixture) setLease(h *podHolder, epoch, sequence int64, released bool) {
	f.t.Helper()
	ctx := context.Background()
	store := provider.InstanceStore{Client: f.admin, Namespace: providerNS}
	want := claim.Record{Key: h.inst.Name, Holder: leaseHolder, Epoch: uint64(epoch), Sequence: uint64(sequence),
		RenewStart: f.clock.read(), Released: released}
	if h.incarnation == "" {
		r, err := store.Create(ctx, want)
		if err != nil {
			f.t.Fatal(err)
		}
		h.incarnation = r.Incarnation
		return
	}
	for range 5 {
		cur, err := store.Get(ctx, h.inst.Name)
		if err != nil {
			f.t.Fatal(err)
		}
		want.Incarnation, want.Version = cur.Incarnation, cur.Version
		if _, err = store.Update(ctx, want); !errors.Is(err, claim.ErrConflict) {
			if err != nil {
				f.t.Fatal(err)
			}
			return
		}
	}
	f.t.Fatal("lease write kept conflicting")
}

// renew bumps the podHolder's lease sequence.
func (f *fixture) renew(h *podHolder) {
	f.t.Helper()
	l := f.lease(h)
	f.setLease(h, int64(l.Epoch), int64(l.Sequence)+1, false)
}

func (f *fixture) lease(h *podHolder) claim.Record {
	f.t.Helper()
	r, err := provider.InstanceStore{Client: f.admin, Namespace: providerNS}.Get(context.Background(), h.inst.Name)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fixture) newRoute(name, prefix string) {
	f.t.Helper()
	rt := &galacticv1alpha1.EdgeRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeRouteSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerName},
			VPCUID: string(f.vpc.UID), Prefix: prefix, Incarnation: "inc-" + name},
	}
	f.create(rt)
}

func (f *fixture) route(name string) *galacticv1alpha1.EdgeRoute {
	f.t.Helper()
	var rt galacticv1alpha1.EdgeRoute
	err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: providerNS, Name: name}, &rt)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return &rt
}

// claim writes the podHolder's claim on the route at its current lease epoch,
// at the route's next claim epoch.
// A claim, like a provider's, is retried when a concurrent status write
// moved the route's resourceVersion.
func (f *fixture) claim(name string, h *podHolder) {
	f.t.Helper()
	epochOf := int64(f.lease(h).Epoch)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		rt := f.route(name)
		epoch := int64(1)
		if rt.Spec.Claim != nil {
			epoch = rt.Spec.Claim.Epoch + 1
		}
		rt.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{Attachment: h.att.Name, HolderPodUID: string(h.pod.UID),
			HolderInstance: h.inst.Name, InstanceEpoch: epochOf, Epoch: epoch}
		return f.admin.Update(context.Background(), rt)
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) release(name string) {
	f.t.Helper()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		rt := f.route(name)
		rt.Spec.Claim.Released = true
		return f.admin.Update(context.Background(), rt)
	}); err != nil {
		f.t.Fatal(err)
	}
}

// reconcile runs the route reconciler and then the index reconciler until
// neither changes anything more.
func (f *fixture) reconcile(name string) {
	f.t.Helper()
	ctx := context.Background()
	for range 5 {
		routeReq := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: providerNS, Name: name}}
		if _, err := f.routes.Reconcile(ctx, routeReq); err != nil {
			f.t.Fatalf("reconcile route %s: %v", name, err)
		}
		indexReq := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: tenantNS, Name: string(f.vpc.UID)}}
		if _, err := f.index.Reconcile(ctx, indexReq); err != nil {
			f.t.Fatalf("reconcile index: %v", err)
		}
	}
}

func (f *fixture) indexEntries() []galacticv1alpha1.EdgeRouteIndexEntry {
	f.t.Helper()
	var idx galacticv1alpha1.EdgeRouteIndex
	err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: string(f.vpc.UID)}, &idx)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return idx.Spec.Routes
}

// clearRebuilt waits out a new index's quiet period, reconciling route r.
func (f *fixture) clearRebuilt() {
	f.t.Helper()
	f.reconcile("r")
	f.clock.advance(params.TakeoverWait())
	f.reconcile("r")
}

// accepted reports the route's accepted podHolder's attachment and epoch, or
// empty when nothing is accepted.
func (f *fixture) accepted(name string) (string, int64) {
	f.t.Helper()
	rt := f.route(name)
	if rt == nil || rt.Status.Accepted == nil ||
		!meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
		return "", 0
	}
	return rt.Status.Accepted.Attachment, rt.Status.Accepted.Epoch
}

func (f *fixture) expectAccepted(name string, h *podHolder, epoch int64) {
	f.t.Helper()
	att, e := f.accepted(name)
	if att != h.att.Name || e != epoch {
		rt := f.route(name)
		f.t.Fatalf("route %s accepted %q at epoch %d, want %q at %d; conditions %v", name, att, e, h.att.Name, epoch,
			conditions(rt))
	}
}

func (f *fixture) claimReason(name string) string {
	f.t.Helper()
	c := meta.FindStatusCondition(f.route(name).Status.Conditions, galacticv1alpha1.EdgeRouteClaimed)
	if c == nil {
		return ""
	}
	return c.Reason
}

func conditions(rt *galacticv1alpha1.EdgeRoute) string {
	if rt == nil {
		return "<no route>"
	}
	var out []string
	for _, c := range rt.Status.Conditions {
		out = append(out, fmt.Sprintf("%s=%s %s: %s", c.Type, c.Status, c.Reason, c.Message))
	}
	return strings.Join(out, "; ")
}

// closeEpoch records the route's accepted epoch closed, as galactic-edge on
// its node does.
func (f *fixture) closeEpoch(name string) {
	f.t.Helper()
	rt := f.route(name)
	rt.Status.ClosedEpoch = rt.Status.Accepted.Epoch
	if err := f.admin.Status().Update(context.Background(), rt); err != nil {
		f.t.Fatal(err)
	}
}
