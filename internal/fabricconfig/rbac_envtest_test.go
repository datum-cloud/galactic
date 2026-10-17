// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabricconfig/activation"
)

// TestAgentWithShippedRBAC runs the deployment agent as the fabric-router
// ServiceAccount, bound only to config/fabric-router's RBAC and the
// activation Component's, through an activation and its status write, so
// a rule the agent needs and the manifests lack fails the test.
func TestAgentWithShippedRBAC(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the RBAC envtest")
	}
	root := filepath.Join("..", "..")
	names := []string{"fabricrouterdeployments", "fabricrouterrevisions", "fabricreleaseauthorizations"}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(root, "config", "crd", "galactic.datumapis.com_"+name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		crds = append(crds, crd)
	}
	env := &envtest.Environment{CRDs: crds}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// The cluster: namespace, Node, the shipped ServiceAccount and RBAC.
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: depNode}}
	for _, o := range []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: depNamespace}}, node} {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join("config", "fabric-router", "serviceaccount.yaml"),
		filepath.Join("config", "fabric-router", "rbac.yaml"),
		filepath.Join("config", "fabric-router", "components", "activation", "rbac.yaml"),
	} {
		applyManifest(t, admin, filepath.Join(root, file))
	}

	// What the rollout manager would have written.
	h := newHarness(t)
	rev := h.revs[0].DeepCopy()
	rev.ResourceVersion = ""
	if err := admin.Create(ctx, rev); err != nil {
		t.Fatal(err)
	}
	dep := deployment(networkv1alpha1.FabricConfigSourceCRD)
	dep.UID, dep.Generation = "", 0
	dep.Spec.Target.NodeUID = string(node.UID)
	if err := admin.Create(ctx, dep); err != nil {
		t.Fatal(err)
	}
	auth := release(rev)
	auth.UID = ""
	auth.Spec.Deployments[0].DeploymentUID = string(dep.UID)
	if err := admin.Create(ctx, auth); err != nil {
		t.Fatal(err)
	}
	started := metav1.Now()
	auth.Status = networkv1alpha1.FabricReleaseAuthorizationStatus{
		Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started,
	}
	if err := admin.Status().Update(ctx, auth); err != nil {
		t.Fatal(err)
	}
	promote(dep, 1, rev)
	dep.Spec.AuthorizationRef.UID = string(auth.UID)
	if err := admin.Update(ctx, dep); err != nil {
		t.Fatal(err)
	}

	// The agent, as the fabric-router ServiceAccount.
	asAgent := rest.CopyConfig(cfg)
	asAgent.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + depNamespace + ":fabric-router",
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + depNamespace, "system:authenticated"},
	}
	agentClient, err := client.New(asAgent, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	// Its identity reads: its Node and the cluster's ID.
	if err := agentClient.Get(ctx, types.NamespacedName{Name: depNode}, &corev1.Node{}); err != nil {
		t.Fatalf("read its Node: %v", err)
	}
	ks := &corev1.Namespace{}
	if err := agentClient.Get(ctx, types.NamespacedName{Name: metav1.NamespaceSystem}, ks); err != nil {
		t.Fatalf("read the cluster ID: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "state")
	if _, err := activation.BindIdentity(dir, activation.Identity{
		NodeUID: string(node.UID), MachineID: depMachine, ClusterID: string(ks.UID),
	}); err != nil {
		t.Fatal(err)
	}
	act := &activation.Activator{Dir: dir, FRR: h.frr}
	if err := act.Open(); err != nil {
		t.Fatal(err)
	}
	agent := &DeploymentAgent{
		Client: agentClient, Namespace: depNamespace, NodeName: depNode, NodeUID: string(node.UID),
		ClusterID: string(ks.UID), Activator: act, BGP: h.frr,
		Gate: NewSourceGate(networkv1alpha1.FabricConfigSourceConfigMap), ConfigDir: t.TempDir(), Version: testVersion,
	}
	if err := agent.Sync(ctx); err != nil {
		t.Fatalf("sync as the agent: %v", err)
	}
	got := &networkv1alpha1.FabricRouterDeployment{}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(dep), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AppliedEpoch != 1 || got.Status.AppliedRevision != rev.Name {
		t.Errorf("status after sync: applied epoch %d revision %q", got.Status.AppliedEpoch, got.Status.AppliedRevision)
	}
}

func applyManifest(t *testing.T, c client.Client, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range strings.Split(string(data), "\n---\n") {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
			t.Fatal(err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		if err := c.Create(context.Background(), obj); err != nil {
			t.Fatalf("apply %s %s: %v", obj.GetKind(), obj.GetName(), err)
		}
	}
}
