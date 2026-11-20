package endpoints

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestEndpointSchemaAndPodAcknowledgments(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	root := filepath.Join("..", "..", "..", "..")
	environment := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join(root, "config", "crd")},
		ErrorIfCRDPathMissing: true}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	admin, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := testEndpoint(t, "registered", time.Now().Add(time.Hour))
	endpoint.UID = ""
	if err := admin.Create(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*galacticv1alpha1.MASQUEEndpoint){
		func(endpoint *galacticv1alpha1.MASQUEEndpoint) {
			endpoint.Spec.Hostname = "other.example.com"
			endpoint.Spec.Revision++
		},
		func(endpoint *galacticv1alpha1.MASQUEEndpoint) { endpoint.Spec.Enabled = false },
		func(endpoint *galacticv1alpha1.MASQUEEndpoint) { endpoint.Spec.Revision = 0 },
		func(endpoint *galacticv1alpha1.MASQUEEndpoint) {
			endpoint.Spec.CertificateRef.Revision = "bad"
			endpoint.Spec.Revision++
		},
	} {
		changed := endpoint.DeepCopy()
		mutate(changed)
		if err := admin.Update(ctx, changed); err == nil {
			t.Fatal("invalid schema update accepted")
		}
	}
	endpoint.Spec.Revision++
	endpoint.Spec.Enabled = false
	if err := admin.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	policy, err := os.Open(filepath.Join(root, "config", "masque", "endpoint-status-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = policy.Close() }()
	decoder := yaml.NewYAMLOrJSONDecoder(policy, 4096)
	for {
		var object unstructured.Unstructured
		if err := decoder.Decode(&object); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if err := admin.Create(ctx, &object); err != nil {
			t.Fatal(err)
		}
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "status-test", Namespace: endpoint.Namespace},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{galacticv1alpha1.GroupVersion.Group},
			Resources: []string{"masqueendpoints", "masqueendpoints/status"}, Verbs: []string{"get", "update"}}}}
	if err := admin.Create(ctx, role); err != nil {
		t.Fatal(err)
	}
	binding := &rbacv1.RoleBinding{ObjectMeta: role.ObjectMeta,
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "masque-provider", Namespace: endpoint.Namespace}}}
	binding.ResourceVersion, binding.UID = "", ""
	if err := admin.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}
	providerConfig := rest.CopyConfig(config)
	providerConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:masque-system:masque-provider",
		Extra: map[string][]string{"authentication.kubernetes.io/pod-uid": {"pod-a"}}}
	provider, err := client.New(providerConfig, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Status.Instances = []galacticv1alpha1.MASQUEEndpointInstanceStatus{{
		InstanceName: "ei-pod-a", InstanceUID: "instance-a", PodUID: "pod-a",
		ObservedRevision: 2, AppliedRevision: 2, State: "Disabled",
		ForwardingStopped: true, LastHeartbeatTime: metav1.Now()}}
	deadline := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		probe := endpoint.DeepCopy()
		probe.Status.Instances[0].PodUID = "pod-b"
		err = provider.Status().Update(ctx, probe, client.DryRunAll)
		if err != nil && strings.Contains(err.Error(), "a provider may acknowledge only its own instance") {
			break
		}
		select {
		case <-deadline:
			t.Fatal(err)
		case <-ticker.C:
		}
	}
	if err := provider.Status().Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*galacticv1alpha1.MASQUEEndpoint){
		func(endpoint *galacticv1alpha1.MASQUEEndpoint) { endpoint.Status.Instances[0].PodUID = "pod-b" },
		func(endpoint *galacticv1alpha1.MASQUEEndpoint) {
			endpoint.Status.Instances[0].InstanceName = "ei-pod-b"
		},
	} {
		changed := endpoint.DeepCopy()
		mutate(changed)
		if err := provider.Status().Update(ctx, changed); err == nil {
			t.Fatal("cross-pod status forgery accepted")
		}
	}
}
