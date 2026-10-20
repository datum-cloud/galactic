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
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
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
	"go.datum.net/galactic/internal/rbaccheck"
)

const deploymentsCRD = "fabricrouterdeployments"

// TestAgentWithShippedRBAC runs the deployment agent as the fabric-router
// ServiceAccount, bound only to config/fabric-router's RBAC and the
// activation Component's, through an activation and its status write, so
// a rule the agent needs and the manifests lack fails the test.
func TestAgentWithShippedRBAC(t *testing.T) {
	root := filepath.Join("..", "..")
	cfg, scheme, admin := startFabricAPI(t)
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
		filepath.Join("config", "fabric-router", "components", "activation", "status-policy.yaml"),
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

	// A pod on another Node may not write this deployment's status. The
	// policy takes effect once the API server has loaded it.
	refused := func(c client.Client) bool {
		d := &networkv1alpha1.FabricRouterDeployment{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(dep), d); err != nil {
			t.Fatal(err)
		}
		before := d.DeepCopy()
		d.Status.AgentVersion = "spoofed"
		err := c.Status().Patch(ctx, d, client.MergeFrom(before))
		return err != nil && strings.Contains(err.Error(), "its own Node")
	}
	eventually(t, "the status policy to refuse another Node's write", func() bool {
		return refused(agentAs(t, cfg, scheme, "edge-b", "other-node-uid"))
	})
	// A replacement Node reusing the name is another Node.
	if !refused(agentAs(t, cfg, scheme, depNode, "replaced-node-uid")) {
		t.Error("a pod on a replacement Node with the same name wrote the status")
	}

	// The agent, as the fabric-router ServiceAccount on its own Node.
	agentClient := agentAs(t, cfg, scheme, depNode, string(node.UID))
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

// TestRetiredAgentWithShippedRBAC runs a node whose ConfigMap path is
// retired as the fabric-router ServiceAccount, bound only to what the
// activation overlay with components/configmap-retired renders: a node with
// no journal starts from its deployment's active revision and activates
// it, and a later move off CRD is reported without reading the node's
// ConfigMap, which exists.
func TestRetiredAgentWithShippedRBAC(t *testing.T) {
	out := rbaccheck.Kustomize(t, []string{fabricRouterBase}, []string{activationComponent, retiredComponent})
	cfg, scheme, admin := startFabricAPI(t)
	ctx := context.Background()

	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: depNode}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: depNamespace, Name: ConfigMapName(depNode)},
		Data: map[string]string{KeyFRRConf: minimalConf}}
	for _, o := range []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: depNamespace}}, node, cm} {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	rbaccheck.ApplyYAML(t, admin, out, append(rbaccheck.RBACKinds, "ValidatingAdmissionPolicy",
		"ValidatingAdmissionPolicyBinding")...)

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

	agentClient := agentAs(t, cfg, scheme, depNode, string(node.UID))
	if err := agentClient.Get(ctx, client.ObjectKeyFromObject(cm), &corev1.ConfigMap{}); err == nil {
		t.Error("the retired agent's ServiceAccount read its ConfigMap")
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
		Client: noConfigMaps(t, agentClient), Namespace: depNamespace, NodeName: depNode, NodeUID: string(node.UID),
		ClusterID: string(ks.UID), Activator: act, BGP: h.frr, ConfigMapsRetired: true,
		Gate: NewSourceGate(networkv1alpha1.FabricConfigSourceCRD), ConfigDir: t.TempDir(), Version: testVersion,
	}
	if conf, reason, err := agent.BootConfig(ctx, depMachine); err != nil || conf != rendered(t, rev) ||
		agent.Booted != BootActiveRevision {
		t.Fatalf("BootConfig = %q, %v, booted %s", reason, err, agent.Booted)
	}
	if err := agent.Sync(ctx); err != nil {
		t.Fatalf("sync as the agent: %v", err)
	}
	got := &networkv1alpha1.FabricRouterDeployment{}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(dep), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AppliedEpoch != 1 || got.Status.EffectiveSource != networkv1alpha1.FabricConfigSourceCRD {
		t.Fatalf("status after sync: applied epoch %d, source %s", got.Status.AppliedEpoch, got.Status.EffectiveSource)
	}

	if err := admin.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		t.Fatal(err)
	}
	got.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
	got.Spec.SourceHandoff = &networkv1alpha1.FabricSourceHandoff{
		ConfigMap:       networkv1alpha1.FabricObjectIdentity{Name: cm.Name, UID: string(cm.UID)},
		ResourceVersion: cm.ResourceVersion,
	}
	if err := admin.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := agent.Sync(ctx); err != nil {
		t.Fatalf("sync as the agent: %v", err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(dep), got); err != nil {
		t.Fatal(err)
	}
	c := meta.FindStatusCondition(got.Status.Conditions, networkv1alpha1.FabricConditionAccepted)
	if got.Status.EffectiveSource != networkv1alpha1.FabricConfigSourceCRD || c == nil ||
		c.Reason != networkv1alpha1.FabricReasonConfigMapRetired {
		t.Errorf("after a handoff on a retired node: source %s, Accepted %+v", got.Status.EffectiveSource, c)
	}
}

// startFabricAPI runs an API server with the deployment, revision and
// release CRDs, and returns its configuration, a scheme for them and an
// admin client.
func startFabricAPI(t *testing.T) (*rest.Config, *runtime.Scheme, client.Client) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the RBAC envtest")
	}
	root := filepath.Join("..", "..")
	names := []string{deploymentsCRD, "fabricrouterrevisions", "fabricreleaseauthorizations"}
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
	return cfg, scheme, admin
}

// agentAs is a client for the fabric-router ServiceAccount whose token is
// bound to a pod on the named Node.
func agentAs(t *testing.T, cfg *rest.Config, scheme *runtime.Scheme, nodeName, nodeUID string) client.WithWatch {
	t.Helper()
	as := rest.CopyConfig(cfg)
	as.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + depNamespace + ":fabric-router",
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + depNamespace, "system:authenticated"},
		Extra: map[string][]string{
			"authentication.kubernetes.io/node-name": {nodeName},
			"authentication.kubernetes.io/node-uid":  {nodeUID},
		},
	}
	c, err := client.NewWithWatch(as, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// eventually polls cond for up to 20 seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
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
