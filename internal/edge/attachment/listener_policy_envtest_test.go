// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	gatewayNS       = "galactic-system"
	listenerName    = "public"
	listenerAddress = "2001:db8:100::10"
)

func listenerObject(namespace, name string) *galacticv1alpha1.EdgeListener {
	return &galacticv1alpha1.EdgeListener{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: galacticv1alpha1.EdgeListenerSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerSA},
			ServiceRef:  galacticv1alpha1.EdgeListenerServiceReference{Namespace: gatewayNS, Name: "listener-grant"},
			Addresses:   []string{listenerAddress},
			Ports: []galacticv1alpha1.EdgeListenerPort{
				{Protocol: galacticv1alpha1.EdgeListenerProtocolTCP, Port: 443, BackendPort: 8443},
			},
		},
	}
}

// gatewayService is a NetworkService in namespace that takes its backends
// from the listener named listener, or from a selector when listener is
// empty.
func gatewayService(namespace, name, listener string) *networkv1alpha1.NetworkService {
	svc := &networkv1alpha1.NetworkService{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: networkv1alpha1.NetworkServiceSpec{
			VPCRef:       "listener-vpc",
			VIPAddresses: []string{listenerAddress},
			Protocol:     networkv1alpha1.NetworkServiceProtocolTCP,
			Port:         443,
			BackendPort:  8443,
		},
	}
	if listener != "" {
		svc.Spec.EdgeListenerRef = &networkv1alpha1.NetworkServiceEdgeListenerReference{Name: listener}
	} else {
		svc.Spec.BackendSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "selected"}}
	}
	return svc
}

// refused fails unless err is an admission refusal mentioning want.
func refused(t *testing.T, what string, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: err = %v, want a refusal mentioning %q", what, err, want)
	}
}

// TestListenerPolicies checks that no provider ServiceAccount writes an
// EdgeListener or a NetworkService, while another ServiceAccount can, and
// that listeners and services naming one stay in the gateway namespace.
func TestListenerPolicies(t *testing.T) {
	f := startAPI(t)
	utilruntime.Must(networkv1alpha1.AddToScheme(f.scheme))
	ctx := context.Background()
	provider := f.as("system:serviceaccount:"+providerNS+":"+providerSA, nil)
	authority := f.as("system:serviceaccount:platform:authority", nil)
	const (
		listenerWrite = "cannot write edgelisteners"
		serviceWrite  = "cannot write networkservices"
	)

	// The binding is enforced a moment after it is created.
	n := 0
	eventually(t, "provider listener policy enforced", func() bool {
		n++
		obj := listenerObject(gatewayNS, fmt.Sprintf("probe-%d", n))
		if err := provider.Create(ctx, obj); err != nil {
			return true
		}
		_ = f.admin.Delete(ctx, obj)
		return false
	})

	refused(t, "provider creates an EdgeListener", provider.Create(ctx, listenerObject(gatewayNS, "by-provider")),
		"a ServiceAccount of provider "+providerSA+" "+listenerWrite)
	refused(t, "provider creates a NetworkService", provider.Create(ctx, gatewayService(providerNS, "by-provider", "")),
		serviceWrite)
	refused(t, "provider creates a listener NetworkService",
		provider.Create(ctx, gatewayService(gatewayNS, "by-provider-listener", listenerName)), serviceWrite)

	listener := listenerObject(gatewayNS, listenerName)
	if err := authority.Create(ctx, listener); err != nil {
		t.Fatalf("authority creates an EdgeListener: %v", err)
	}
	svc := gatewayService(gatewayNS, "public-443", listenerName)
	if err := authority.Create(ctx, svc); err != nil {
		t.Fatalf("a non-provider ServiceAccount creates a listener NetworkService: %v", err)
	}

	// A provider can change neither the listener, nor its status, nor the
	// service, nor delete them.
	changed := listener.DeepCopy()
	changed.Spec.Addresses = []string{"2001:db8:100::11"}
	refused(t, "provider updates its EdgeListener", provider.Update(ctx, changed), listenerWrite)
	status := listener.DeepCopy()
	status.Status.Backends = []galacticv1alpha1.EdgeListenerBackend{{Attachment: "edge/ea-1", Serving: true}}
	refused(t, "provider writes its EdgeListener's status", provider.Status().Update(ctx, status),
		"cannot write edgelisteners/status")
	refused(t, "provider deletes its EdgeListener", provider.Delete(ctx, listener), listenerWrite)
	refused(t, "provider deletes the listener's NetworkService", provider.Delete(ctx, svc), serviceWrite)

	// Outside the gateway namespace, a listener and a service naming one are
	// refused for every writer; a selector service is not.
	refused(t, "EdgeListener in a project namespace", authority.Create(ctx, listenerObject(tenantNS, listenerName)),
		"an EdgeListener lives only in the gateway namespace")
	refused(t, "listener NetworkService in a project namespace",
		authority.Create(ctx, gatewayService(tenantNS, "tenant-listener", listenerName)),
		"edgeListenerRef is allowed only in the gateway namespace")
	if err := authority.Create(ctx, gatewayService(tenantNS, "tenant-selector", "")); err != nil {
		t.Errorf("selector NetworkService in a project namespace: %v", err)
	}
}
