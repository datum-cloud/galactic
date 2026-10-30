// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestServiceEndpointProducerReportScale applies one full report per node for
// more nodes than one object holding every node's entries can store, and
// checks the API server's validation of a report.
func TestServiceEndpointProducerReportScale(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	apiRoot := os.Getenv("GALACTIC_TEST_NETWORK_API")
	if apiRoot == "" {
		apiRoot = "../../.."
	}
	data, err := os.ReadFile(filepath.Join(apiRoot, "config", "crd",
		"galactic.datumapis.com_serviceendpointproducerreports.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(data, crd); err != nil {
		t.Fatal(err)
	}
	environment := &envtest.Environment{CRDs: []*apiextensionsv1.CustomResourceDefinition{crd}}
	cfg, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const namespace = "producer-reports"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Now().Truncate(time.Second))
	failing := ""
	for len(failing) < 1024 {
		failing += "dial tcp: connect: connection refused; "
	}
	failing = failing[:1024]
	report := func(node string, producers int) map[string]any {
		entries := make([]networkv1alpha1.ServiceEndpointProducerStatus, 0, producers)
		for i := range producers {
			entries = append(entries, networkv1alpha1.ServiceEndpointProducerStatus{
				Namespace: namespace, Name: fmt.Sprintf("resolver-producer-attachment-%s-%02d", node, i),
				AttachmentUID: types.UID(fmt.Sprintf("uid-%s-%02d", node, i)), Node: node, Port: 8053,
				State: networkv1alpha1.BackendHealthUnhealthy, Reason: "ProbeFailed", Message: failing,
				LastTransitionTime: now, RenewTime: &now,
			})
		}
		return map[string]any{
			"apiVersion": networkv1alpha1.GroupVersion.String(), "kind": "ServiceEndpointProducerReport",
			"metadata": map[string]string{"name": "resolver-" + node, "namespace": namespace},
			"spec": networkv1alpha1.ServiceEndpointProducerReportSpec{
				EndpointName: "resolver", EndpointUID: "endpoint-uid", Node: node, Producers: entries,
			},
		}
	}
	apply := func(node string, body map[string]any) error {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		obj := &networkv1alpha1.ServiceEndpointProducerReport{}
		obj.Name, obj.Namespace = "resolver-"+node, namespace
		return c.Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, raw),
			client.FieldOwner("galactic-router/"+node), client.ForceOwnership)
	}

	// 300 nodes, each with the most producers a node may hold, all failing
	// with the longest probe error: 4800 entries, which one shared object
	// cannot store.
	const nodes = 300
	for n := range nodes {
		node := fmt.Sprintf("worker-node-%04d", n)
		if err := apply(node, report(node, networkv1alpha1.ServiceEndpointMaxProducersPerNode)); err != nil {
			t.Fatalf("apply report of node %d: %v", n, err)
		}
	}
	list := &networkv1alpha1.ServiceEndpointProducerReportList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	entries := 0
	for _, item := range list.Items {
		entries += len(item.Spec.Producers)
	}
	if entries != nodes*networkv1alpha1.ServiceEndpointMaxProducersPerNode {
		t.Fatalf("stored entries = %d, want %d", entries, nodes*networkv1alpha1.ServiceEndpointMaxProducersPerNode)
	}

	invalid := func(name string, body map[string]any) {
		t.Helper()
		if err := apply("worker-node-0000", body); !apierrors.IsInvalid(err) {
			t.Errorf("%s: apply error = %v, want the report refused", name, err)
		}
	}
	tooMany := report("worker-node-0000", networkv1alpha1.ServiceEndpointMaxProducersPerNode+1)
	invalid("more producers than a node holds", tooMany)
	otherNode := report("worker-node-0000", 1)
	otherNode["spec"] = networkv1alpha1.ServiceEndpointProducerReportSpec{
		EndpointName: "resolver", EndpointUID: "endpoint-uid", Node: "worker-node-0000",
		Producers: report("worker-node-0001", 1)["spec"].(networkv1alpha1.ServiceEndpointProducerReportSpec).Producers,
	}
	invalid("an entry of another node", otherNode)
	moved := report("worker-node-0000", 1)
	spec := moved["spec"].(networkv1alpha1.ServiceEndpointProducerReportSpec)
	spec.EndpointUID = "other-endpoint-uid"
	moved["spec"] = spec
	invalid("a changed endpointUID", moved)
}
