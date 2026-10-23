// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

const (
	tenantNS   = "tenant"
	providerNS = "edge"
	providerSA = "connect-ip"
	edgeNode   = "edge-1"
	vpcName    = "prod"
	vpcID      = "000000abc"
	poolA      = "fd00:10:0:e::/120"

	socketAccess  = "SocketAccess"
	authenticated = "system:authenticated"
)

var repoRoot = filepath.Join("..", "..", "..")

// fixture is a real API server with the CRDs, the shipped galactic-controller
// RBAC and the Galactic Edge policies installed, and the reconciler running
// as galactic-controller.
type fixture struct {
	t      *testing.T
	cfg    *rest.Config
	scheme *runtime.Scheme
	admin  client.Client
	vpc    *cloudv1alpha1.VPC
}

func startFixture(t *testing.T) *fixture {
	t.Helper()
	f := startAPI(t)
	f.startController()
	return f
}

// startAPI starts the API server and its fixtures without the reconciler.
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
	f := &fixture{t: t, cfg: cfg, scheme: scheme, admin: admin}
	for _, ns := range []string{"galactic-system", tenantNS, providerNS} {
		f.create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	for _, path := range []string{
		filepath.Join(repoRoot, "config", "galactic-controller", "serviceaccount.yaml"),
		filepath.Join(repoRoot, "config", "galactic-controller", "rbac.yaml"),
		filepath.Join(repoRoot, "config", "galactic-edge", "controller-rbac.yaml"),
		filepath.Join(repoRoot, "config", "galactic-edge", "policies.yaml"),
	} {
		applyManifest(t, admin, path)
	}
	f.create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: edgeNode}})
	f.vpc = &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: vpcName, Namespace: tenantNS},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd00:10::/48"}},
	}
	f.create(f.vpc)
	f.vpc.Status.VPC = vpcID
	if err := admin.Status().Update(context.Background(), f.vpc); err != nil {
		t.Fatal(err)
	}
	provider := &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: providerSA},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			ContractVersions: []string{"v1alpha1"},
			Capabilities: []galacticv1alpha1.EdgeCapability{
				{Name: socketAccess, Version: "v1"}, {Name: "PacketAccess", Version: "v1"},
			},
			ServiceAccounts: []galacticv1alpha1.ServiceAccountReference{{Namespace: providerNS, Name: providerSA}},
			Configuration:   galacticv1alpha1.ConfigurationKind{Group: "connect.example.com", Kind: "Config"},
		},
	}
	f.create(provider)
	provider.Status.Approved = true
	if err := admin.Status().Update(context.Background(), provider); err != nil {
		t.Fatal(err)
	}
	return f
}

// startController runs every core reconciler as galactic-controller, with
// exactly the permissions the shipped RBAC grants.
func (f *fixture) startController() {
	f.run(func(mgr ctrl.Manager) error {
		return Setup(mgr, &Reconciler{
			Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(),
			Authority: admission.NewAuthority(2 * time.Second), MaxSkew: 2 * time.Second,
		})
	})
}

// startBindings runs only the provider binding reconciler, as
// galactic-controller.
func (f *fixture) startBindings() {
	f.run((&ProviderBindingReconciler{}).SetupWithManager)
}

// run starts a manager as galactic-controller with what setup registers.
func (f *fixture) run(setup func(ctrl.Manager) error) {
	t := f.t
	as := rest.CopyConfig(f.cfg)
	as.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:galactic-system:galactic-controller",
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:galactic-system", authenticated},
	}
	mgr, err := ctrl.NewManager(as, ctrl.Options{
		Scheme: f.scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		// Every test starts its own manager in this process.
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := setup(mgr); err != nil {
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

func (f *fixture) create(obj client.Object) {
	f.t.Helper()
	if err := f.admin.Create(context.Background(), obj); err != nil {
		f.t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

func (f *fixture) service(name, pool string, drain int32) *galacticv1alpha1.EdgeService {
	f.t.Helper()
	s := &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tenantNS},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: providerSA},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: vpcName, UID: string(f.vpc.UID)},
			Capabilities: []string{socketAccess, "PacketAccess"},
			ClientPool:   pool,
			DrainSeconds: &drain,
		},
	}
	f.create(s)
	return s
}

// laterService creates a service whose creation time is after every
// existing service's, which has one-second resolution.
func (f *fixture) laterService(name, pool string) *galacticv1alpha1.EdgeService {
	f.t.Helper()
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	return f.service(name, pool, 30)
}

// pod creates a provider pod on edgeNode and its EdgeInstance.
func (f *fixture) pod(name string) *corev1.Pod {
	f.t.Helper()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: providerNS},
		Spec: corev1.PodSpec{
			NodeName: edgeNode, ServiceAccountName: providerSA,
			Containers: []corev1.Container{{Name: "provider", Image: "provider"}},
		},
	}
	f.create(p)
	f.create(&galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "inst-" + name, Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeInstanceSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerSA},
			PodName:     name, PodUID: string(p.UID), NodeName: edgeNode,
		},
	})
	return p
}

func attachmentFor(name string, svc *galacticv1alpha1.EdgeService, pod *corev1.Pod) *galacticv1alpha1.EdgeAttachment {
	return &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerSA},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{
				Namespace: svc.Namespace, Name: svc.Name, UID: string(svc.UID),
			},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: "inst-" + pod.Name},
			PodUID:          string(pod.UID),
			ContractVersion: "v1alpha1",
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: socketAccess, Version: "v1"}},
		},
	}
}

func (f *fixture) get(name string) *galacticv1alpha1.EdgeAttachment {
	f.t.Helper()
	var a galacticv1alpha1.EdgeAttachment
	err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: providerNS, Name: name}, &a)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return &a
}

func (f *fixture) allocations(svc *galacticv1alpha1.EdgeService) []galacticv1alpha1.EdgeAllocation {
	f.t.Helper()
	var s galacticv1alpha1.EdgeService
	if err := f.admin.Get(context.Background(), client.ObjectKeyFromObject(svc), &s); err != nil {
		f.t.Fatal(err)
	}
	return s.Status.Allocations
}

func (f *fixture) waitCondition(name, cond string, status metav1.ConditionStatus,
	reason string) *galacticv1alpha1.EdgeAttachment {
	f.t.Helper()
	var got *galacticv1alpha1.EdgeAttachment
	eventually(f.t, fmt.Sprintf("%s %s=%s %s", name, cond, status, reason), func() bool {
		got = f.get(name)
		c := meta.FindStatusCondition(got.Status.Conditions, cond)
		return c != nil && c.Status == status && (reason == "" || c.Reason == reason)
	})
	return got
}

func (f *fixture) waitService(name string, status metav1.ConditionStatus, reason string) {
	f.t.Helper()
	eventually(f.t, fmt.Sprintf("EdgeService %s Admitted=%s %s", name, status, reason), func() bool {
		var s galacticv1alpha1.EdgeService
		if err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: name}, &s); err != nil {
			return false
		}
		c := meta.FindStatusCondition(s.Status.Conditions, ConditionServiceAdmitted)
		return c != nil && c.Status == status && c.Reason == reason
	})
}

// nodeReleases reports Released as galactic-edge on edgeNode would.
func (f *fixture) nodeReleases(name string) {
	f.t.Helper()
	a := f.get(name)
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{
		Type: galacticv1alpha1.EdgeAttachmentReleased, Status: metav1.ConditionTrue, Reason: "Released",
	})
	if err := f.admin.Status().Update(context.Background(), a); err != nil {
		f.t.Fatal(err)
	}
}

func TestAdmitAndAllocate(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	svc := f.service("svc-a", poolA, 30)
	p1, p2 := f.pod("p1"), f.pod("p2")
	f.create(attachmentFor("a1", svc, p1))
	f.create(attachmentFor("a2", svc, p2))

	a1 := f.waitCondition("a1", galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, ReasonAllocated)
	a2 := f.waitCondition("a2", galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, ReasonAllocated)
	if a1.Status.Address == a2.Status.Address {
		t.Fatalf("both attachments hold %s", a1.Status.Address)
	}
	for _, a := range []*galacticv1alpha1.EdgeAttachment{a1, a2} {
		if a.Status.NodeName != edgeNode || a.Status.VPC != vpcID {
			t.Errorf("%s: node %q vpc %q", a.Name, a.Status.NodeName, a.Status.VPC)
		}
		if !strings.HasPrefix(a.Status.Address, "fd00:10:0:e::") || a.Status.Address == "fd00:10:0:e::" {
			t.Errorf("%s: address %s outside the pool or the anycast address", a.Name, a.Status.Address)
		}
		if len(a.Finalizers) != 1 || a.Finalizers[0] != galacticv1alpha1.EdgeAttachmentFinalizer {
			t.Errorf("%s: finalizers %v", a.Name, a.Finalizers)
		}
	}
	if got := f.allocations(svc); len(got) != 2 {
		t.Fatalf("allocations %v, want 2", got)
	}

	// Repeated reconciliation, triggered by a service change, keeps every
	// allocation where it is.
	var s galacticv1alpha1.EdgeService
	if err := f.admin.Get(ctx, client.ObjectKeyFromObject(svc), &s); err != nil {
		t.Fatal(err)
	}
	s.Spec.Prefixes = []string{"fd00:10:0:f::/64"}
	if err := f.admin.Update(ctx, &s); err != nil {
		t.Fatal(err)
	}
	eventually(t, "re-admission under the new generation", func() bool {
		c := meta.FindStatusCondition(f.get("a1").Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted)
		return c != nil && strings.Contains(c.Message, fmt.Sprintf("generation %d", s.Generation))
	})
	if got := f.get("a1"); got.Status.Address != a1.Status.Address {
		t.Errorf("a1 moved from %s to %s", a1.Status.Address, got.Status.Address)
	}
	if got := f.allocations(svc); len(got) != 2 {
		t.Errorf("allocations after re-admission %v, want 2", got)
	}

	// A later service whose pool overlaps is refused; it never revokes the
	// attachments the earlier service already holds.
	later := f.laterService("later", "fd00:10:0:e::/64")
	f.create(attachmentFor("later", later, p1))
	f.waitCondition("later", galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionFalse, ReasonPoolConflict)
	if c := meta.FindStatusCondition(f.get("a1").Status.Conditions,
		galacticv1alpha1.EdgeAttachmentDraining); c != nil {
		t.Errorf("earlier service's attachment drained by an overlapping later one: %+v", c)
	}
}

// TestOrphanedAllocationIsReclaimed removes an attachment's finalizer by
// hand: its allocation is reclaimed the next time the service allocates.
func TestOrphanedAllocationIsReclaimed(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	svc := f.service("svc-a", poolA, 30)
	p1, p2, p3, p4 := f.pod("p1"), f.pod("p2"), f.pod("p3"), f.pod("p4")
	for name, p := range map[string]*corev1.Pod{"a1": p1, "a2": p2, "a3": p3} {
		f.create(attachmentFor(name, svc, p))
		f.waitCondition(name, galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, "")
	}
	orphan := f.get("a2")
	orphan.Finalizers = nil
	if err := f.admin.Update(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Delete(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a2 gone", func() bool { return f.get("a2") == nil })

	f.create(attachmentFor("a4", svc, p4))
	a4 := f.waitCondition("a4", galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, "")
	if a4.Status.Address != orphan.Status.Address {
		t.Errorf("a4 got %s, want the lowest free address, the orphaned %s", a4.Status.Address, orphan.Status.Address)
	}
	for _, a := range f.allocations(svc) {
		if a.AttachmentUID == string(orphan.UID) {
			t.Errorf("orphaned allocation kept: %+v", a)
		}
	}
}

func TestMissingTenantStateFailsClosed(t *testing.T) {
	f := startFixture(t)
	svc := f.service("svc-a", poolA, 30)
	noPool := f.service("no-pool", "", 30)
	p := f.pod("p1")

	orphan := attachmentFor("no-instance", svc, p)
	orphan.Spec.InstanceRef.Name = "missing"
	f.create(orphan)
	f.create(attachmentFor("no-pool", noPool, p))
	ghost := attachmentFor("no-service", svc, p)
	ghost.Spec.ServiceRef.UID = "00000000-0000-0000-0000-000000000000"
	f.create(ghost)

	for name, reason := range map[string]string{
		"no-instance": ReasonInstanceMissing,
		"no-pool":     ReasonNoClientPool,
		"no-service":  string(admission.GrantRevoked),
	} {
		a := f.waitCondition(name, galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionFalse, reason)
		if a.Status.Address != "" || a.Status.NodeName != "" {
			t.Errorf("%s: refused attachment got address %q node %q", name, a.Status.Address, a.Status.NodeName)
		}
	}
	if got := f.allocations(svc); len(got) != 0 {
		t.Errorf("refused attachments allocated %v", got)
	}
	f.waitService("svc-a", metav1.ConditionTrue, ReasonAdmitted)
	f.waitService("no-pool", metav1.ConditionFalse, ReasonNoClientPool)

	// A conflicting pool refuses the later service's attachments, and a
	// VPC without its fabric identifier refuses everything until it has one.
	conflict := f.laterService("conflict", "fd00:10:0:e::/64")
	f.create(attachmentFor("conflicting", conflict, p))
	f.waitCondition("conflicting", galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionFalse, ReasonPoolConflict)
	f.waitService("conflict", metav1.ConditionFalse, ReasonPoolConflict)
	f.waitService("svc-a", metav1.ConditionTrue, ReasonAdmitted)

	// An attachment naming another provider than its service's is refused.
	wrong := attachmentFor("wrong-provider", svc, p)
	wrong.Spec.ProviderRef.Name = "tailnet"
	f.create(wrong)
	f.waitCondition("wrong-provider", galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionFalse,
		string(admission.ProviderNotGranted))

	// An unapproved provider is refused before allocation.
	var provider galacticv1alpha1.EdgeProvider
	ctx := context.Background()
	if err := f.admin.Get(ctx, client.ObjectKey{Name: providerSA}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Status.Approved = false
	if err := f.admin.Status().Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	other := f.service("svc-b", "fd00:10:0:d::/120", 30)
	f.create(attachmentFor("unapproved", other, p))
	f.waitCondition("unapproved", galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionFalse,
		string(admission.ProviderNotApproved))
	f.waitService("svc-b", metav1.ConditionFalse, string(admission.ProviderNotApproved))
	if got := f.allocations(other); len(got) != 0 {
		t.Errorf("unapproved provider allocated %v", got)
	}
}

func TestDrainAndRelease(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	svc := f.service("svc-a", poolA, 1)
	p1, p2 := f.pod("p1"), f.pod("p2")
	f.create(attachmentFor("revoked", svc, p1))
	f.create(attachmentFor("deleted", svc, p2))
	f.waitCondition("revoked", galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, "")
	f.waitCondition("deleted", galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, "")

	// The provider deletes its own attachment: it is held until the node
	// reports the host state released, and its address with it.
	if err := f.admin.Delete(ctx, f.get("deleted")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if f.get("deleted") == nil {
		t.Fatal("attachment finalized before its node released it")
	}
	if got := f.allocations(svc); len(got) != 2 {
		t.Fatalf("address freed before release: %v", got)
	}
	f.nodeReleases("deleted")
	eventually(t, "deleted attachment finalized", func() bool { return f.get("deleted") == nil })
	if got := f.allocations(svc); len(got) != 1 {
		t.Fatalf("allocations after release %v, want 1", got)
	}

	// The provider's pod goes away: the attachment drains for the service's
	// window, then is deleted and held for its node.
	if err := f.admin.Delete(ctx, p1, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	a := f.waitCondition("revoked", galacticv1alpha1.EdgeAttachmentDraining, metav1.ConditionTrue, ReasonPodMissing)
	if a.Status.DrainDeadline == nil {
		t.Fatal("draining attachment has no deadline")
	}
	eventually(t, "drained attachment deleted", func() bool {
		a := f.get("revoked")
		return a != nil && !a.DeletionTimestamp.IsZero()
	})
	if time.Now().Before(a.Status.DrainDeadline.Time) {
		t.Errorf("deleted before its drain deadline %s", a.Status.DrainDeadline)
	}

	// Its node is removed from the cluster: nothing is left to release.
	if err := f.admin.Delete(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: edgeNode}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "attachment of a removed node finalized", func() bool { return f.get("revoked") == nil })
	if got := f.allocations(svc); len(got) != 0 {
		t.Fatalf("allocations after all released %v", got)
	}
}

func TestExpiredGrantDrains(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	svc := f.service("svc-a", poolA, 0)
	p := f.pod("p1")
	f.create(attachmentFor("a1", svc, p))
	f.waitCondition("a1", galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, "")

	var s galacticv1alpha1.EdgeService
	if err := f.admin.Get(ctx, client.ObjectKeyFromObject(svc), &s); err != nil {
		t.Fatal(err)
	}
	until := metav1.NewTime(time.Now().Add(3 * time.Second))
	s.Spec.ValidUntil = &until
	if err := f.admin.Update(ctx, &s); err != nil {
		t.Fatal(err)
	}
	f.waitCondition("a1", galacticv1alpha1.EdgeAttachmentDraining, metav1.ConditionTrue, string(admission.GrantExpired))
	eventually(t, "expired attachment deleted", func() bool {
		a := f.get("a1")
		return a != nil && !a.DeletionTimestamp.IsZero()
	})
}
