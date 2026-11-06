// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
)

// An interface event requeues the attachments on this node that use that host
// interface, and only those, so a new interface's policy is published as soon
// as it comes up rather than at the next pending retry.
func TestInterfaceChangedEnqueuesAttachmentsOnThisNode(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	attachment := func(name, node, iface string) *cloudv1alpha1.VPCAttachment {
		a := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name}}
		a.Status.Node, a.Status.HostInterface = node, iface
		return a
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&cloudv1alpha1.VPCAttachment{}, hostInterfaceIndex, attachmentHostInterface).
		WithObjects(
			attachment("here", testNode, "Gwanted"),
			attachment("elsewhere", "node-b", "Gwanted"),
			attachment("other-iface", testNode, "Gother"),
			attachment("no-iface", testNode, ""),
		).Build()
	r := &Reconciler{Client: c, NodeName: testNode, events: make(chan event.GenericEvent, 8)}

	r.InterfaceChanged("Gwanted")
	r.InterfaceChanged("")
	r.InterfaceChanged("Gunknown")

	var got []types.NamespacedName
	for len(r.events) > 0 {
		got = append(got, client.ObjectKeyFromObject((<-r.events).Object))
	}
	want := types.NamespacedName{Namespace: testNS, Name: "here"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("enqueued %v, want only %v", got, want)
	}
}

// Before SetupWithManager there is no event channel, and an interface event
// is ignored rather than blocking the interface watch.
func TestInterfaceChangedBeforeSetupIsANoop(t *testing.T) {
	(&Reconciler{NodeName: testNode}).InterfaceChanged("Gwanted")
}

// A full event queue drops the request instead of blocking the interface
// watch: what is queued already reconciles the same interface.
func TestInterfaceChangedDoesNotBlockOnAFullQueue(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	a := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "here"}}
	a.Status.Node, a.Status.HostInterface = testNode, "Gwanted"
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&cloudv1alpha1.VPCAttachment{}, hostInterfaceIndex, attachmentHostInterface).
		WithObjects(a).Build()
	r := &Reconciler{Client: c, NodeName: testNode, events: make(chan event.GenericEvent, 1)}
	r.InterfaceChanged("Gwanted")
	r.InterfaceChanged("Gwanted")
	if len(r.events) != 1 {
		t.Fatalf("queue holds %d events, want 1", len(r.events))
	}
}
