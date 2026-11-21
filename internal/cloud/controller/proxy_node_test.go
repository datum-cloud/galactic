// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
)

const (
	proxyNS   = "envoy"
	proxyPod  = "envoy-1"
	proxyNode = "node-a"
)

func proxyScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, cloudv1alpha1.AddToScheme,
		bgpv1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// proxyAttachment is a proxy's VPCAttachment naming pod, with node recorded.
func proxyAttachment(pod, node string) *cloudv1alpha1.VPCAttachment {
	return &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy-80", Namespace: proxyNS},
		Status:     cloudv1alpha1.VPCAttachmentStatus{VPC: "80", VPCAttachment: "e80", PodName: pod, Node: node},
	}
}

// scheduledPod is the proxy pod in namespace ns, scheduled to node.
func scheduledPod(ns, node string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: proxyPod, Namespace: ns}, Spec: corev1.PodSpec{NodeName: node}}
}

func proxyClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(proxyScheme(t)).WithObjects(objs...).
		WithStatusSubresource(&cloudv1alpha1.VPCAttachment{}).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, IndexBGPAdvertisementIdentity, BGPAdvertisementIdentity).
		WithIndex(&cloudv1alpha1.VPCAttachment{}, IndexVPCAttachmentIdentity, func(obj client.Object) []string {
			a := obj.(*cloudv1alpha1.VPCAttachment)
			if id := galactic.AdvertisementName(a.Status.VPC, a.Status.VPCAttachment); id != "" {
				return []string{id}
			}
			return nil
		}).Build()
}

func reconcileProxyNode(t *testing.T, cl client.Client) string {
	t.Helper()
	r := &ProxyNodeReconciler{Client: cl, APIReader: cl}
	key := types.NamespacedName{Namespace: proxyNS, Name: "proxy-80"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	var got cloudv1alpha1.VPCAttachment
	if err := cl.Get(context.Background(), key, &got); err != nil {
		t.Fatal(err)
	}
	return got.Status.Node
}

// TestProxyNodeCertification covers when the controller certifies a proxy
// attachment's node from its pod, and when it clears it.
func TestProxyNodeCertification(t *testing.T) {
	terminating := scheduledPod(proxyNS, proxyNode)
	now := metav1.Now()
	terminating.DeletionTimestamp, terminating.Finalizers = &now, []string{"test/hold"}
	for _, tc := range []struct {
		name string
		att  *cloudv1alpha1.VPCAttachment
		objs []client.Object
		want string
	}{
		{"a scheduled pod in the attachment's namespace certifies its node",
			proxyAttachment(proxyPod, ""), []client.Object{scheduledPod(proxyNS, proxyNode)}, proxyNode},
		{"a pod of that name in another namespace certifies nothing",
			proxyAttachment(proxyPod, ""), []client.Object{scheduledPod("other", proxyNode)}, ""},
		{"an unscheduled pod certifies nothing",
			proxyAttachment(proxyPod, ""), []client.Object{scheduledPod(proxyNS, "")}, ""},
		{"a terminating pod clears the node",
			proxyAttachment(proxyPod, proxyNode), []client.Object{terminating}, ""},
		{"a deleted pod clears the node", proxyAttachment(proxyPod, proxyNode), nil, ""},
		{"a pod rescheduled to another node moves the node",
			proxyAttachment(proxyPod, proxyNode), []client.Object{scheduledPod(proxyNS, "node-b")}, "node-b"},
		{"an attachment naming no pod is left alone",
			proxyAttachment("", "node-x"), []client.Object{scheduledPod(proxyNS, proxyNode)}, "node-x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := proxyClient(t, append(tc.objs, tc.att)...)
			if got := reconcileProxyNode(t, cl); got != tc.want {
				t.Fatalf("status.node = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProxyNodeDefersToTheAdvertisement leaves the node to the
// advertisement's projection once one exists for the attachment.
func TestProxyNodeDefersToTheAdvertisement(t *testing.T) {
	adv := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Name: galactic.AdvertisementName("80", "e80") + "-node-c", Namespace: galactic.SystemNamespace}}
	cl := proxyClient(t, proxyAttachment(proxyPod, "node-c"), scheduledPod(proxyNS, proxyNode), adv)
	if got := reconcileProxyNode(t, cl); got != "node-c" {
		t.Fatalf("status.node = %q, want the advertisement's node-c kept", got)
	}
}

// TestWithdrawnAdvertisementKeepsThePodCertifiedNode: when the advertisement
// of an attachment that names a scheduled pod is withdrawn, the projection
// falls back to that pod's node instead of clearing it; once the pod is
// gone, it clears it.
func TestWithdrawnAdvertisementKeepsThePodCertifiedNode(t *testing.T) {
	key := types.NamespacedName{Namespace: galactic.SystemNamespace,
		Name: galactic.AdvertisementName("80", "e80") + "-" + proxyNode}
	attKey := types.NamespacedName{Namespace: proxyNS, Name: "proxy-80"}
	for _, tc := range []struct {
		name string
		pod  []client.Object
		want string
	}{
		{"pod scheduled", []client.Object{scheduledPod(proxyNS, proxyNode)}, proxyNode},
		{"pod gone", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := proxyClient(t, append(tc.pod, proxyAttachment(proxyPod, proxyNode))...)
			r := &BGPAdvertisementReconciler{Client: cl, Scheme: proxyScheme(t)}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			var got cloudv1alpha1.VPCAttachment
			if err := cl.Get(context.Background(), attKey, &got); err != nil {
				t.Fatal(err)
			}
			if got.Status.Node != tc.want {
				t.Fatalf("status.node after the withdrawal = %q, want %q", got.Status.Node, tc.want)
			}
		})
	}
}
