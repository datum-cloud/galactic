// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package masque

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
	edgeattachment "go.datum.net/galactic/internal/edge/attachment"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/provider"
	edgeroute "go.datum.net/galactic/internal/edge/route"
	"go.datum.net/galactic/internal/edge/timing"
)

const (
	coreTenantNS   = "tenant"
	coreProviderNS = "edge"
	coreProvider   = "masque"
	coreNode       = "edge-1"
	coreVPCID      = "000000abc"
	nodeNameExtra  = "authentication.kubernetes.io/node-name"
)

var repoRoot = filepath.Join("..", "..", "..")

// shortParams is a one-second lease so that a takeover completes quickly.
var shortParams = claim.Params{Duration: time.Second, MaxDrift: 0.001, Margin: 100 * time.Millisecond,
	MaxSkew: 2 * time.Second}

// coreFixture is a real API server with the CRDs, the shipped
// galactic-controller, galactic-edge and provider RBAC and the Galactic Edge
// admission policies, core's attachment and route controllers running as
// galactic-controller, and a stand-in for galactic-edge on coreNode that
// programs and releases attachments as the node agent would. The adapter
// runs as the provider pod's ServiceAccount with its pod-bound token.
type coreFixture struct {
	t      *testing.T
	cfg    *rest.Config
	scheme *runtime.Scheme
	admin  client.Client
	vpc    *cloudv1alpha1.VPC

	mu    sync.Mutex
	hosts map[string]*os.File
	// grants are the test authority's connectors, keyed by credential.
	grants map[string]Grant
}

func startCore(t *testing.T) *coreFixture {
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
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	f := &coreFixture{t: t, cfg: cfg, scheme: scheme, admin: admin, hosts: map[string]*os.File{},
		grants: map[string]Grant{}}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, h := range f.hosts {
			_ = h.Close()
		}
	})
	for _, ns := range []string{"galactic-system", coreTenantNS, coreProviderNS} {
		f.create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	for _, path := range []string{
		filepath.Join("galactic-controller", "serviceaccount.yaml"),
		filepath.Join("galactic-controller", "rbac.yaml"),
		filepath.Join("galactic-edge", "serviceaccount.yaml"),
		filepath.Join("galactic-edge", "rbac.yaml"),
		filepath.Join("galactic-edge", "controller-rbac.yaml"),
		filepath.Join("galactic-edge", "policies.yaml"),
	} {
		f.apply(filepath.Join(repoRoot, "config", path))
	}
	f.create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: coreNode}})
	f.vpc = &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: testVPCName, Namespace: coreTenantNS},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd00:10::/48"}},
	}
	f.create(f.vpc)
	f.vpc.Status.VPC = coreVPCID
	if err := admin.Status().Update(context.Background(), f.vpc); err != nil {
		t.Fatal(err)
	}
	p := &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: coreProvider},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			ContractVersions: []string{ContractVersion},
			Capabilities: []galacticv1alpha1.EdgeCapability{
				{Name: PacketAccess, Version: "v1"}, {Name: PrefixReachability, Version: "v1"},
			},
			ServiceAccounts: []galacticv1alpha1.ServiceAccountReference{
				{Namespace: coreProviderNS, Name: coreProvider}},
			Configuration: galacticv1alpha1.ConfigurationKind{Group: "masque.example.com", Kind: "Config"},
		},
	}
	f.create(p)
	p.Status.Approved = true
	if err := admin.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	f.startController()
	f.startNode()
	return f
}

func (f *coreFixture) create(obj client.Object) {
	f.t.Helper()
	if err := f.admin.Create(context.Background(), obj); err != nil {
		f.t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

func (f *coreFixture) apply(path string) {
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

// as is a client for user whose token carries extra, holding only the
// permissions RBAC grants it.
func (f *coreFixture) as(user string, groups []string, extra map[string][]string) client.Client {
	f.t.Helper()
	cfg := rest.CopyConfig(f.cfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups, Extra: extra}
	c, err := client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// startController runs core's attachment and route controllers, as
// galactic-controller --edge wires them, on the short lease.
func (f *coreFixture) startController() {
	t := f.t
	as := rest.CopyConfig(f.cfg)
	as.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:galactic-system:galactic-controller",
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:galactic-system", "system:authenticated"},
	}
	mgr, err := ctrl.NewManager(as, ctrl.Options{
		Scheme: f.scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:      cache.Options{ByObject: edgeroute.LeaseCache()},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := edgeattachment.Setup(mgr, &edgeattachment.Reconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(),
		Authority: admission.NewAuthority(shortParams.MaxSkew), MaxSkew: shortParams.MaxSkew,
	}); err != nil {
		t.Fatal(err)
	}
	if err := edgeroute.Setup(mgr, shortParams, timing.BootClock, "galactic-system", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager: %v", err)
		}
	})
}

// startNode runs the node stand-in on coreNode: it programs every
// allocated attachment with a packet device and releases every deleted one,
// as galactic-edge would. The node agent is not under test, so it writes as
// the administrator.
func (f *coreFixture) startNode() {
	node := f.admin
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			f.nodePass(ctx, node)
			time.Sleep(50 * time.Millisecond)
		}
	}()
	f.t.Cleanup(func() {
		cancel()
		<-done
	})
}

func (f *coreFixture) nodePass(ctx context.Context, node client.Client) {
	f.closeGates(ctx, node)
	var list galacticv1alpha1.EdgeAttachmentList
	if err := node.List(ctx, &list, client.InNamespace(coreProviderNS)); err != nil {
		return
	}
	for i := range list.Items {
		att := &list.Items[i]
		if att.Status.NodeName != coreNode {
			continue
		}
		cond := func(t string) bool { return meta.IsStatusConditionTrue(att.Status.Conditions, t) }
		var set string
		switch {
		case att.DeletionTimestamp != nil && !cond(galacticv1alpha1.EdgeAttachmentReleased):
			set = galacticv1alpha1.EdgeAttachmentReleased
		case att.DeletionTimestamp == nil && cond(galacticv1alpha1.EdgeAttachmentAllocated) &&
			!cond(galacticv1alpha1.EdgeAttachmentProgrammed):
			set = galacticv1alpha1.EdgeAttachmentProgrammed
			att.Status.HostLink, att.Status.PacketDevice = "eh-"+att.Spec.ServiceRef.Name, "et-"+att.Spec.ServiceRef.Name
		default:
			continue
		}
		meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{Type: set, Status: metav1.ConditionTrue,
			Reason: set, ObservedGeneration: att.Generation})
		_ = node.Status().Update(ctx, att)
	}
}

// closeGates records the accepted epoch of every route on coreNode closed
// once its claim moved on or was released, as galactic-edge does when it
// closes that epoch's gate.
func (f *coreFixture) closeGates(ctx context.Context, node client.Client) {
	var list galacticv1alpha1.EdgeRouteList
	if err := node.List(ctx, &list, client.InNamespace(coreProviderNS)); err != nil {
		return
	}
	for i := range list.Items {
		rt := &list.Items[i]
		acc, cl := rt.Status.Accepted, rt.Spec.Claim
		if acc == nil || acc.Node != coreNode || rt.Status.ClosedEpoch >= acc.Epoch || cl == nil ||
			(cl.Epoch == acc.Epoch && !cl.Released) {
			continue
		}
		rt.Status.ClosedEpoch = acc.Epoch
		_ = node.Status().Update(ctx, rt)
	}
}

// service creates an EdgeService granting prefixes to the provider with
// capabilities and pool.
func (f *coreFixture) service(name, pool string, capabilities []string,
	prefixes ...string) *galacticv1alpha1.EdgeService {
	f.t.Helper()
	s := &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: coreTenantNS},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: coreProvider},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: f.vpc.Name, UID: string(f.vpc.UID)},
			Capabilities: capabilities, Prefixes: prefixes, ClientPool: pool,
			DrainSeconds: ptr.To(int32(1)),
		},
	}
	f.create(s)
	return s
}

// connector adds a test connector of svc with prefix under credential.
func (f *coreFixture) connector(credential string, svc *galacticv1alpha1.EdgeService, prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[credential] = Grant{
		Connector: credential, Principal: credential, VPC: f.vpc.Name, VPCUID: string(f.vpc.UID),
		VPCID: coreVPCID, Service: ServiceRef{Namespace: svc.Namespace, Name: svc.Name, UID: string(svc.UID)},
		Prefix: netip.MustParsePrefix(prefix),
	}
}

func (f *coreFixture) Authorize(_ context.Context, credential, vpc string) (Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.grants[credential]
	if !ok {
		return Grant{}, connectip.ErrUnauthenticated
	}
	if g.VPC != vpc {
		return Grant{}, connectip.ErrForbidden
	}
	g.NotAfter = time.Now().Add(time.Hour)
	return g, nil
}

// Refresh renews g for another hour while its credential is still granted.
func (f *coreFixture) Refresh(_ context.Context, g Grant) (Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cur := range f.grants {
		if cur.Connector == g.Connector && cur.sameAuthority(&g) {
			g.NotAfter = time.Now().Add(time.Hour)
			return g, nil
		}
	}
	return Grant{}, connectip.ErrForbidden
}

// Retire removes g's connector from the fixture's grants.
func (f *coreFixture) Retire(_ context.Context, g Grant) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for cred, cur := range f.grants {
		if cur.Connector == g.Connector {
			delete(f.grants, cred)
		}
	}
	return nil
}

func (f *coreFixture) open(name string) (*os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if old := f.hosts[name]; old != nil {
		_ = old.Close()
	}
	f.hosts[name] = os.NewFile(uintptr(fds[1]), name+"-host")
	return os.NewFile(uintptr(fds[0]), name), nil
}

func (f *coreFixture) host(name string) *os.File {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hosts[name]
}

// pod creates a provider pod on coreNode.
func (f *coreFixture) pod(name string) *corev1.Pod {
	f.t.Helper()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: coreProviderNS},
		Spec: corev1.PodSpec{NodeName: coreNode, ServiceAccountName: coreProvider,
			Containers: []corev1.Container{{Name: coreProvider, Image: coreProvider}}},
	}
	f.create(p)
	return p
}

// providerClient authenticates as the provider ServiceAccount with a token
// bound to pod.
func (f *coreFixture) providerClient(pod *corev1.Pod) client.Client {
	return f.as("system:serviceaccount:"+coreProviderNS+":"+coreProvider,
		[]string{"system:serviceaccounts", "system:serviceaccounts:" + coreProviderNS, "system:authenticated"},
		map[string][]string{admission.PodUIDExtra: {string(pod.UID)}, nodeNameExtra: {coreNode}})
}

// waitForBinding waits until galactic-controller has bound the provider's
// role and admission policy: a pod-bound write naming another pod is then
// refused by the policy rather than by RBAC.
func (f *coreFixture) waitForBinding(pod *corev1.Pod) {
	f.t.Helper()
	c := f.providerClient(pod)
	eventually(f.t, "the provider binding to be enforced", func() bool {
		probe := provider.NewInstance(coreProviderNS, coreProvider, "probe", "probe-uid", coreNode, "boot")
		err := c.Create(context.Background(), probe)
		if err == nil {
			_ = f.admin.Delete(context.Background(), probe)
			return false
		}
		return strings.Contains(err.Error(), "ValidatingAdmissionPolicy")
	})
}

// adapter returns an adapter of pod authenticating as tokenPod, a new
// process with its own holder ID.
func (f *coreFixture) adapter(pod, tokenPod *corev1.Pod) *Adapter {
	f.t.Helper()
	c := f.providerClient(tokenPod)
	a, err := New(Config{
		Client: c, Provider: coreProvider, Authorizer: f, OpenDevice: f.open,
		Pod: Pod{Namespace: coreProviderNS, Name: pod.Name, UID: string(pod.UID), Node: coreNode, BootID: "boot",
			RunAsUser: 65532, RunAsGroup: 65532},
		Claims: &claim.Instance{ID: rand.Text(), Clock: timing.BootClock, Params: shortParams,
			Store: provider.InstanceStore{Client: c, Namespace: coreProviderNS, Duration: shortParams.Duration}},
		Renew: 300 * time.Millisecond, Poll: 50 * time.Millisecond, Prepare: 20 * time.Second, Idle: time.Hour,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

// run starts a and runs it until the returned function stops it, as a
// process crash would, without shutting down.
func (f *coreFixture) run(a *Adapter) (stop func()) {
	f.t.Helper()
	if err := a.Start(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				f.t.Errorf("adapter: %v", err)
			}
		})
	}
	f.t.Cleanup(stop)
	return stop
}

func (f *coreFixture) admit(a *Adapter, credential string) connectip.Lease {
	f.t.Helper()
	l, err := a.Admit(context.Background(), credential, f.vpc.Name)
	if err != nil {
		f.t.Fatalf("admit %s: %v", credential, err)
	}
	return l
}

func (f *coreFixture) attachment(name string) *galacticv1alpha1.EdgeAttachment {
	f.t.Helper()
	var att galacticv1alpha1.EdgeAttachment
	err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: coreProviderNS, Name: name}, &att)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return &att
}

func (f *coreFixture) route(name string) *galacticv1alpha1.EdgeRoute {
	f.t.Helper()
	var rt galacticv1alpha1.EdgeRoute
	if err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: coreProviderNS, Name: name},
		&rt); err != nil {
		f.t.Fatal(err)
	}
	return &rt
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestAgainstCore runs the adapter as an unprivileged provider pod against
// core's attachment and route controllers and the shipped RBAC and
// admission policies.
func TestAgainstCore(t *testing.T) {
	f := startCore(t)
	pod := f.pod("masque-0")
	shared := f.service("shared", "fd00:10:0:e::/120", Capabilities, "fd00:10:0:1:1::/96", "fd00:10:0:1:2::/96")
	f.connector("c1", shared, "fd00:10:0:1:1::/96")
	f.connector("c2", shared, "fd00:10:0:1:2::/96")
	f.waitForBinding(pod)
	a := f.adapter(pod, pod)
	stop := f.run(a)
	if _, err := a.Admit(context.Background(), "c1", f.vpc.Name); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Admit before the lease is held = %v, want %v", err, ErrUnavailable)
	}
	eventually(t, "the adapter to hold the lease", func() bool { _, ok := a.heldLease(); return ok })

	l2, s2 := f.checkSharedAttachment(t, a)
	t.Run("capability not granted", func(t *testing.T) { f.checkCapabilityNotGranted(t, a) })
	t.Run("grant for another VPC", func(t *testing.T) {
		f.mu.Lock()
		g := f.grants["c2"]
		g.VPCID = "000000xyz"
		f.grants["c2-forged"] = g
		f.mu.Unlock()
		if _, err := a.Admit(context.Background(), "c2-forged", f.vpc.Name); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Admit = %v, want a refusal", err)
		}
		expectLive(t, l2, "a refused request on the same attachment")
	})
	t.Run("forged pod identity", func(t *testing.T) {
		forged := f.adapter(f.pod("masque-1"), pod)
		err := forged.Start(context.Background())
		if err == nil || !strings.Contains(err.Error(), "ValidatingAdmissionPolicy") {
			t.Fatalf("registering another pod's instance = %v, want a policy refusal", err)
		}
	})
	t.Run("stale delete keeps the replacement", func(t *testing.T) { f.checkStaleDelete(t, a) })
	t.Run("service withdrawn drains", func(t *testing.T) {
		svc := f.service("withdrawn", "fd00:10:0:e::300/120", Capabilities, "fd00:10:0:1:5::/96")
		f.connector("c5", svc, "fd00:10:0:1:5::/96")
		l := f.admit(a, "c5")
		defer func() { _ = l.Close() }()
		if err := f.admin.Delete(context.Background(), svc); err != nil {
			t.Fatal(err)
		}
		expectDoneWithin(t, l, 30*time.Second, "withdrawing the service")
		expectLive(t, l2, "withdrawing another service")
	})
	t.Run("one connector's service expires", func(t *testing.T) {
		svc := f.service("expiring", "fd00:10:0:e::400/120", Capabilities, "fd00:10:0:1:6::/96")
		f.connector("c6", svc, "fd00:10:0:1:6::/96")
		l := f.admit(a, "c6")
		defer func() { _ = l.Close() }()
		lease, _ := a.heldLease()
		if err := f.admin.Get(context.Background(), client.ObjectKeyFromObject(svc), svc); err != nil {
			t.Fatal(err)
		}
		svc.Spec.ValidUntil = &metav1.Time{Time: time.Now().Add(-time.Second)}
		if err := f.admin.Update(context.Background(), svc); err != nil {
			t.Fatal(err)
		}
		expectDoneWithin(t, l, 30*time.Second, "the connector's service expiring")
		expectLive(t, l2, "another connector's service expiring")
		if cur, ok := a.heldLease(); !ok || !sameLease(cur, lease) {
			t.Fatal("one connector's service expiring changed the shared instance's lease")
		}
	})
	t.Run("renewing the service keeps forwarding", func(t *testing.T) {
		// The grant authority renews a connector's service by moving its
		// validUntil forward in place. Each renewal is a new generation;
		// the connector keeps its attachment, route and epoch past the
		// first deadline.
		svc := f.service("renewed", "fd00:10:0:e::600/120", Capabilities, "fd00:10:0:1:8::/96")
		renew := func(ahead time.Duration) {
			t.Helper()
			if err := f.admin.Get(context.Background(), client.ObjectKeyFromObject(svc), svc); err != nil {
				t.Fatal(err)
			}
			svc.Spec.ValidUntil = &metav1.Time{Time: time.Now().Add(shortParams.MaxSkew + ahead)}
			if err := f.admin.Update(context.Background(), svc); err != nil {
				t.Fatal(err)
			}
		}
		// Admission takes a few seconds; validUntil carries whole seconds.
		renew(6 * time.Second)
		first, deadline := svc.Generation, svc.Spec.ValidUntil.Time
		f.connector("c8", svc, "fd00:10:0:1:8::/96")
		l := f.admit(a, "c8")
		defer func() { _ = l.Close() }()
		attUID := f.attachment(l.Info().Attachment).UID
		epoch := f.route(l.Info().Claim).Spec.Claim.Epoch
		for time.Now().Before(deadline.Add(2 * time.Second)) {
			time.Sleep(time.Second)
			renew(4 * time.Second)
		}
		expectLive(t, l, "renewing the connector's service")
		att := f.attachment(l.Info().Attachment)
		rt := f.route(l.Info().Claim)
		if svc.Generation <= first+2 || att == nil || att.UID != attUID ||
			!meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted) ||
			rt.Spec.Claim.Released || rt.Spec.Claim.Epoch != epoch ||
			!acceptedFor(rt, l.Info().Attachment, attUID, mustLease(t, a)) {
			t.Fatalf("after renewals to generation %d: attachment %+v, claim %+v", svc.Generation, att, rt.Spec.Claim)
		}
		expectLive(t, l2, "renewing another connector's service")
	})
	t.Run("replacement keeps the claim", func(t *testing.T) {
		svc := f.service("handoff", "fd00:10:0:e::500/120", Capabilities, "fd00:10:0:1:7::/96")
		f.connector("c7", svc, "fd00:10:0:1:7::/96")
		old := f.admit(a, "c7")
		serve(old, nil)
		epoch := f.route(old.Info().Claim).Spec.Claim.Epoch
		l := f.admit(a, "c7")
		defer func() { _ = l.Close() }()
		expectDoneWithin(t, old, time.Second, "the replacement")
		rt := f.route(l.Info().Claim)
		if rt.Spec.Claim.Released || rt.Spec.Claim.Epoch != epoch || !acceptedFor(rt, l.Info().Attachment,
			f.attachment(l.Info().Attachment).UID, mustLease(t, a)) {
			t.Fatalf("claim after the replacement: %+v, want epoch %d accepted throughout", rt.Spec.Claim, epoch)
		}
		expectLive(t, l2, "another connector's replacement")
	})

	// The process dies without shutting down.
	_ = s2.Close()
	_ = l2.Close()
	oldEpoch := f.route(l2.Info().Claim).Spec.Claim.InstanceEpoch
	stop()
	f.checkRestartAndShutdown(t, pod, l2.Info().Attachment, oldEpoch)
}

// checkSharedAttachment admits two connectors of one service, which share
// its attachment, and checks that ending one request leaves the other's
// device, claim and packet stream intact. It returns the remaining request.
func (f *coreFixture) checkSharedAttachment(t *testing.T, a *Adapter) (connectip.Lease, connectip.BackendSession) {
	t.Helper()
	l1, l2 := f.admit(a, "c1"), f.admit(a, "c2")
	if l1.Info().Attachment != l2.Info().Attachment {
		t.Fatalf("connectors of one service use attachments %s and %s", l1.Info().Attachment, l2.Info().Attachment)
	}
	att := f.attachment(l1.Info().Attachment)
	if !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady) {
		t.Fatalf("the provider could not report the attachment Ready: %v", att.Status.Conditions)
	}
	s1, err := a.Open(context.Background(), l1.Info())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := a.Open(context.Background(), l2.Info())
	if err != nil {
		t.Fatal(err)
	}
	host := f.host(att.Status.PacketDevice)
	for _, dst := range []string{"fd00:10:0:1:1::9", "fd00:10:0:1:2::9"} {
		if _, err := host.Write(packet(dst)); err != nil {
			t.Fatal(err)
		}
	}
	expectRead(t, s1, "fd00:10:0:1:1::9")
	expectRead(t, s2, "fd00:10:0:1:2::9")
	_ = s1.Close()
	_ = l1.Close()
	expectLive(t, l2, "closing another connector's request")
	if !f.route(l1.Info().Claim).Spec.Claim.Released {
		t.Fatal("the ended connector's claim was not released")
	}
	if rt := f.route(l2.Info().Claim); rt.Spec.Claim.Released ||
		!meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
		t.Fatalf("ending one connector disturbed another's claim: %+v", rt.Spec.Claim)
	}
	if _, err := host.Write(packet("fd00:10:0:1:2::a")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, s2, "fd00:10:0:1:2::a")
	return l2, s2
}

// checkCapabilityNotGranted requests a connector whose service grants
// PacketAccess but not PrefixReachability: core refuses its route and the
// request fails without a claim left behind.
func (f *coreFixture) checkCapabilityNotGranted(t *testing.T, a *Adapter) {
	svc := f.service("socket-only", "fd00:10:0:e::100/120", []string{PacketAccess}, "fd00:10:0:1:3::/96")
	f.connector("c3", svc, "fd00:10:0:1:3::/96")
	_, err := a.Admit(context.Background(), "c3", f.vpc.Name)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "CapabilityNotGranted") {
		t.Fatalf("Admit = %v, want a refusal for the missing PrefixReachability grant", err)
	}
	var routes galacticv1alpha1.EdgeRouteList
	if err := f.admin.List(context.Background(), &routes); err != nil {
		t.Fatal(err)
	}
	for _, rt := range routes.Items {
		if rt.Spec.Prefix == "fd00:10:0:1:3::/96" &&
			(rt.Status.Accepted != nil || rt.Spec.Claim == nil || !rt.Spec.Claim.Released) {
			t.Fatalf("a refused route is accepted or still claimed: %+v %+v", rt.Spec.Claim, rt.Status.Accepted)
		}
	}
}

// checkStaleDelete replaces an attachment under its name, then runs a
// delete of the old object: the replacement survives.
func (f *coreFixture) checkStaleDelete(t *testing.T, a *Adapter) {
	svc := f.service("replaced", "fd00:10:0:e::200/120", Capabilities, "fd00:10:0:1:4::/96")
	f.connector("c4", svc, "fd00:10:0:1:4::/96")
	l := f.admit(a, "c4")
	name := l.Info().Attachment
	old := f.attachment(name).UID
	_ = l.Close()
	if err := f.admin.Delete(context.Background(), f.attachment(name)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the deleted attachment to be released", func() bool { return f.attachment(name) == nil })
	l = f.admit(a, "c4")
	defer func() { _ = l.Close() }()
	if cur := f.attachment(name); cur == nil || cur.UID == old {
		t.Fatal("the attachment was not replaced")
	}
	stale := &attachment{svc: ServiceRef{Namespace: svc.Namespace, Name: svc.Name, UID: string(svc.UID)},
		name: name, uid: old}
	if err := a.deleteAttachment(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	if cur := f.attachment(name); cur == nil || cur.DeletionTimestamp != nil {
		t.Fatal("a stale delete removed the replacement")
	}
	expectLive(t, l, "a stale delete")
}

// checkRestartAndShutdown starts a successor process of pod after the first
// died: it adopts attachment attName and serves it again only under a lease
// epoch after oldEpoch. Its shutdown then releases the claim, removes the
// attachments and releases the lease.
func (f *coreFixture) checkRestartAndShutdown(t *testing.T, pod *corev1.Pod, attName string, oldEpoch int64) {
	uid := f.attachment(attName).UID
	b := f.adapter(pod, pod)
	stop := f.run(b)
	eventually(t, "the successor to hold the lease", func() bool { _, ok := b.heldLease(); return ok })
	l := f.admit(b, "c2")
	if l.Info().Attachment != attName || f.attachment(attName).UID != uid {
		t.Fatalf("the successor served %s, not the adopted attachment", l.Info().Attachment)
	}
	if rt := f.route(l.Info().Claim); rt.Spec.Claim.InstanceEpoch <= oldEpoch {
		t.Fatalf("the successor forwards under lease epoch %d, not after %d", rt.Spec.Claim.InstanceEpoch, oldEpoch)
	}

	_ = l.Close()
	stop()
	if err := b.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.route(l.Info().Claim).Spec.Claim.Released {
		t.Fatal("shutdown left the claim held")
	}
	eventually(t, "shutdown to remove the attachments", func() bool {
		var list galacticv1alpha1.EdgeAttachmentList
		if err := f.admin.List(context.Background(), &list, client.InNamespace(coreProviderNS)); err != nil {
			t.Fatal(err)
		}
		for _, att := range list.Items {
			if att.Spec.PodUID == string(pod.UID) {
				return false
			}
		}
		return true
	})
	var lease coordinationv1.Lease
	if err := f.admin.Get(context.Background(), types.NamespacedName{Namespace: coreProviderNS,
		Name: provider.InstanceName(string(pod.UID))}, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] != "true" {
		t.Fatal("shutdown left the lease held")
	}
}

func expectDoneWithin(t *testing.T, l connectip.Lease, d time.Duration, what string) {
	t.Helper()
	select {
	case <-l.Done():
	case <-time.After(d):
		t.Fatalf("%s did not end the request", what)
	}
}

func mustLease(t *testing.T, a *Adapter) claim.Lease {
	t.Helper()
	l, ok := a.heldLease()
	if !ok {
		t.Fatal("the adapter holds no lease")
	}
	return l
}
