// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/yaml"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/trafficpolicy/cell"
)

// controllerUser is the identity the shipped RBAC binds: the manager runs as
// it with no other permission, so a rule missing from rbac.yaml fails here.
const controllerUser = "system:serviceaccount:galactic-system:galactic-controller"

// env is a real API server with the CRDs and the shipped webhook
// configuration installed, galactic-controller's cell role running against
// it, and clients for the controller's identity and for a tenant.
type env struct {
	tenant     client.Client
	controller client.Client
	stop       context.CancelFunc
	done       chan error
}

func startEnv(t *testing.T) *env {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	te := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd"),
		},
		ErrorIfCRDPathMissing: true,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "..", "config", "galactic-controller", "base", "webhook.yaml")},
		},
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

	userConfig := func(name string, groups ...string) *rest.Config {
		u, err := te.AddUser(envtest.User{Name: name, Groups: groups}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return u.Config()
	}
	newClient := func(c *rest.Config) client.Client {
		cl, err := client.New(c, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	installRBAC(t, newClient(cfg))
	controllerCfg := userConfig(controllerUser, "system:authenticated")

	wo := te.WebhookInstallOptions
	mgr, err := ctrl.NewManager(controllerCfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Host: wo.LocalServingHost, Port: wo.LocalServingPort, CertDir: wo.LocalServingCertDir,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Setup(mgr, controllerUser); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &env{
		tenant:     newClient(userConfig("tenant", "system:masters")),
		controller: newClient(controllerCfg),
		stop:       cancel,
		done:       make(chan error, 1),
	}
	go func() { e.done <- mgr.Start(ctx) }()
	t.Cleanup(e.shutdown)

	// Wait for the webhook to answer before the first write.
	eventually(t, "webhook serving", func() bool {
		err := e.tenant.Create(context.Background(), policy("probe", "default", `[{"name":"a","action":"Deny"}]`))
		return err == nil || apierrors.IsAlreadyExists(err)
	})
	return e
}

// installRBAC applies the shipped ServiceAccount and RBAC, so the manager's
// identity has exactly the permissions production grants it.
func installRBAC(t *testing.T, admin client.Client) {
	t.Helper()
	ctx := context.Background()
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "galactic-system"}}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"serviceaccount.yaml", "rbac.yaml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "config", "galactic-controller", f))
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(raw), "\n---\n") {
			obj := &unstructured.Unstructured{}
			if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if len(obj.Object) == 0 {
				continue
			}
			if err := admin.Create(ctx, obj); err != nil {
				t.Fatalf("%s: create %s: %v", f, obj.GetName(), err)
			}
		}
	}
}

func (e *env) shutdown() {
	if e.stop == nil {
		return
	}
	e.stop()
	<-e.done
	e.stop = nil
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func policy(name, ns, rules string) *unstructured.Unstructured {
	var r []any
	if err := json.Unmarshal([]byte(rules), &r); err != nil {
		panic(err)
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "galactic.datumapis.com/v1alpha1",
		"kind":       "TrafficPolicy",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec":       map[string]any{"rules": r},
	}}
	return u
}

func namespace(t *testing.T, c client.Client, name string) {
	t.Helper()
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
		t.Fatal(err)
	}
}

func attachment(t *testing.T, c client.Client, ns, name string) {
	t.Helper()
	a := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	a.Spec.VPC.Name = "vpc-1"
	a.Spec.Interface.Name = "eth0"
	if err := c.Create(context.Background(), a); err != nil {
		t.Fatalf("create VPCAttachment: %v", err)
	}
}

// TestCellRole runs every scenario against one API server and controller.
// The last stops the controller, so the order matters.
func TestCellRole(t *testing.T) {
	e := startEnv(t)
	t.Run("webhook rejects explicit nulls", func(t *testing.T) { testNulls(t, e) })
	t.Run("webhook rejects what only Go validation catches", func(t *testing.T) { testGoValidation(t, e) })
	t.Run("reserved name", func(t *testing.T) { testReservedName(t, e) })
	t.Run("default policy is provisioned and protected", func(t *testing.T) { testDefaultPolicy(t, e) })
	t.Run("conflicting default is left alone", func(t *testing.T) { testConflictingDefault(t, e) })
	t.Run("binding references resolve", func(t *testing.T) { testBindingResolution(t, e) })
	t.Run("policy status", func(t *testing.T) { testPolicyStatus(t, e) })
	t.Run("webhook unavailable fails closed", func(t *testing.T) { testFailsClosed(t, e) })
}

func testNulls(t *testing.T, e *env) {
	ctx := context.Background()
	for _, rules := range []string{
		`[{"name":"a","action":"Allow","match":null}]`,
		`[{"name":"a","action":"Allow","match":{"sourceIPs":null}}]`,
		`[{"name":"a","action":"Allow","match":{"destinationCIDRs":null}}]`,
		`[{"name":"a","action":"Allow","match":{"protocol":"TCP","destinationPorts":null}}]`,
		`[{"name":"a","action":"Allow","match":{"protocol":"ICMP","icmp":{"type":3,"code":null}}}]`,
	} {
		err := e.tenant.Create(ctx, policy("nulls", "default", rules))
		if err == nil || !strings.Contains(err.Error(), "must not be null") {
			t.Errorf("%s: err = %v, want a null rejection", rules, err)
		}
	}
	// An update carrying a null is rejected like a create.
	upd := policy("upd-null", "default", `[{"name":"a","action":"Allow","match":{"protocol":"TCP"}}]`)
	if err := e.tenant.Create(ctx, upd); err != nil {
		t.Fatal(err)
	}
	err := e.tenant.Patch(ctx, upd, client.RawPatch(types.JSONPatchType,
		[]byte(`[{"op":"add","path":"/spec/rules/0/match/sourceIPs","value":null}]`)))
	if err == nil || !strings.Contains(err.Error(), "must not be null") {
		t.Errorf("update: err = %v, want a null rejection", err)
	}
	// Server-side apply with an explicit null is rejected too.
	body := []byte(`{"apiVersion":"galactic.datumapis.com/v1alpha1","kind":"TrafficPolicy",
		"metadata":{"name":"ssa-null","namespace":"default"},
		"spec":{"rules":[{"name":"a","action":"Allow","match":{"sourceIPs":null}}]}}`)
	obj := policy("ssa-null", "default", `[]`)
	err = e.tenant.Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, body), client.FieldOwner("tenant"))
	if err == nil || !strings.Contains(err.Error(), "must not be null") {
		t.Errorf("apply: err = %v, want a null rejection", err)
	}
}

func testGoValidation(t *testing.T, e *env) {
	ctx := context.Background()
	err := e.tenant.Create(ctx, policy("canonical", "default",
		`[{"name":"a","action":"Allow","match":{"sourceIPs":["2001:DB8::1","2001:db8::1"]}}]`))
	if err == nil || !strings.Contains(err.Error(), "same address") {
		t.Errorf("err = %v, want a canonical duplicate rejection", err)
	}
}

func testReservedName(t *testing.T, e *env) {
	ctx := context.Background()
	err := e.tenant.Create(ctx, policy(galacticv1alpha1.DefaultPolicyName, "default",
		`[{"name":"deny-all","action":"Deny"}]`))
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("tenant create: err = %v, want a reserved-name denial", err)
	}
}

func testDefaultPolicy(t *testing.T, e *env) {
	ctx := context.Background()
	namespace(t, e.tenant, "tenant-a")
	attachment(t, e.tenant, "tenant-a", "web-0-eth0")
	key := client.ObjectKey{Namespace: "tenant-a", Name: galacticv1alpha1.DefaultPolicyName}
	var p galacticv1alpha1.TrafficPolicy
	eventually(t, "default policy", func() bool { return e.tenant.Get(ctx, key, &p) == nil })
	if p.Labels[cell.ManagedByLabel] != cell.ManagedByValue || len(p.Spec.Rules) != 1 ||
		p.Spec.Rules[0].Action != galacticv1alpha1.ActionDeny || p.Spec.Rules[0].Match != nil {
		t.Fatalf("default policy = %+v, want one controller-managed deny-all rule", p)
	}
	before := p.DeepCopy()
	p.Spec.Rules[0].Action = galacticv1alpha1.ActionAllow
	if err := e.tenant.Patch(ctx, &p, client.MergeFrom(before)); err == nil {
		t.Error("tenant turned the default policy into an allow")
	}
	if err := e.tenant.Delete(ctx, before); err == nil {
		t.Error("tenant deleted the default policy")
	}
}

func testConflictingDefault(t *testing.T, e *env) {
	ctx := context.Background()
	namespace(t, e.tenant, "tenant-b")
	// The controller identity creates an unlabeled object, as one
	// that predates the webhook would be.
	conflict := policy(galacticv1alpha1.DefaultPolicyName, "tenant-b", `[{"name":"deny-all","action":"Deny"}]`)
	if err := e.controller.Create(ctx, conflict); err != nil {
		t.Fatal(err)
	}
	attachment(t, e.tenant, "tenant-b", "db-0-eth0")
	var p galacticv1alpha1.TrafficPolicy
	key := client.ObjectKey{Namespace: "tenant-b", Name: galacticv1alpha1.DefaultPolicyName}
	eventually(t, "Accepted condition", func() bool {
		if e.tenant.Get(ctx, key, &p) != nil {
			return false
		}
		c := meta.FindStatusCondition(p.Status.Conditions, cell.ConditionAccepted)
		return c != nil && c.Reason == cell.ReasonReservedName
	})
	if p.Labels[cell.ManagedByLabel] != "" {
		t.Errorf("conflicting object was adopted: labels %v", p.Labels)
	}
	// Its owner can clear the conflict, and the controller then provisions
	// its own.
	if err := e.tenant.Delete(ctx, &p); err != nil {
		t.Fatalf("delete the conflicting object: %v", err)
	}
	eventually(t, "managed default after the conflict", func() bool {
		return e.tenant.Get(ctx, key, &p) == nil && p.Labels[cell.ManagedByLabel] == cell.ManagedByValue
	})
}

func testBindingResolution(t *testing.T, e *env) {
	ctx := context.Background()
	namespace(t, e.tenant, "tenant-c")
	b := &galacticv1alpha1.TrafficPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-eth0", Namespace: "tenant-c"},
		Spec: galacticv1alpha1.TrafficPolicyBindingSpec{
			EgressPolicyRef: &galacticv1alpha1.LocalPolicyReference{Name: "web-egress"},
		},
	}
	if err := e.tenant.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKeyFromObject(b)
	reason := func(d *galacticv1alpha1.DirectionStatus) string {
		if d == nil {
			return ""
		}
		if c := meta.FindStatusCondition(d.Conditions, cell.ConditionResolved); c != nil {
			return c.Reason
		}
		return ""
	}
	eventually(t, "unresolved egress", func() bool {
		return e.tenant.Get(ctx, key, b) == nil && reason(b.Status.Egress) == cell.ReasonNotFound &&
			reason(b.Status.Ingress) == cell.ReasonDefault
	})
	if b.Status.Ingress.Policy == nil || b.Status.Ingress.Policy.UID != galacticv1alpha1.DefaultPolicyUID {
		t.Errorf("ingress = %+v, want the built-in default identity", b.Status.Ingress)
	}

	// A node's own entry survives the controller's status writes.
	node := []byte(`{"apiVersion":"galactic.datumapis.com/v1alpha1","kind":"TrafficPolicyBinding",
		"metadata":{"name":"web-0-eth0","namespace":"tenant-c"},
		"status":{"nodes":[{"node":"dfw-compute-1","egress":{"state":"Pending"}}]}}`)
	if err := e.tenant.Status().Patch(ctx, b, client.RawPatch(types.ApplyPatchType, node),
		client.FieldOwner("dfw-compute-1")); err != nil {
		t.Fatal(err)
	}

	created := policy("web-egress", "tenant-c", `[{"name":"https","action":"Allow",
		"match":{"path":"PublicNAT","protocol":"TCP","destinationPorts":[{"start":443,"end":443}]}}]`)
	if err := e.tenant.Create(ctx, created); err != nil {
		t.Fatal(err)
	}
	eventually(t, "resolved egress", func() bool {
		return e.tenant.Get(ctx, key, b) == nil && reason(b.Status.Egress) == cell.ReasonResolved
	})
	if b.Status.Egress.Policy.UID != string(created.GetUID()) {
		t.Errorf("egress policy UID = %s, want %s", b.Status.Egress.Policy.UID, created.GetUID())
	}
	if len(b.Status.Nodes) != 1 || b.Status.Nodes[0].Node != "dfw-compute-1" {
		t.Errorf("status.nodes = %+v, want the node's entry kept", b.Status.Nodes)
	}

	if err := e.tenant.Delete(ctx, created); err != nil {
		t.Fatal(err)
	}
	eventually(t, "unresolved after deletion", func() bool {
		return e.tenant.Get(ctx, key, b) == nil && reason(b.Status.Egress) == cell.ReasonNotFound
	})
}

func testPolicyStatus(t *testing.T, e *env) {
	ctx := context.Background()
	p := policy("shadowed", "default", `[{"name":"all","action":"Allow"},{"name":"never","action":"Deny"}]`)
	if err := e.tenant.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	var got galacticv1alpha1.TrafficPolicy
	eventually(t, "Accepted", func() bool {
		if e.tenant.Get(ctx, client.ObjectKeyFromObject(p), &got) != nil {
			return false
		}
		c := meta.FindStatusCondition(got.Status.Conditions, cell.ConditionAccepted)
		return c != nil && c.Status == metav1.ConditionTrue && strings.Contains(c.Message, "never is never reached")
	})
}

// Last, since it stops the controller: with nothing answering, the
// webhook fails closed and every write is refused.
func testFailsClosed(t *testing.T, e *env) {
	ctx := context.Background()
	e.shutdown()
	err := e.tenant.Create(ctx, policy("while-down", "default", `[{"name":"a","action":"Deny"}]`))
	if err == nil || !strings.Contains(err.Error(), "failed calling webhook") {
		t.Errorf("err = %v, want the write refused because the webhook is down", err)
	}
}
