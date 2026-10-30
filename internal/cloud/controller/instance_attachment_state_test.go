/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/prometheus/client_golang/prometheus"
	locationsv1alpha1 "go.miloapis.com/locations/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/webhook"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

const (
	tenantNamespace = "tenant"
	podNode         = "node-a"
)

func instanceScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme, cloudv1alpha1.AddToScheme,
		networkingv1alpha.AddToScheme, computev1alpha.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

// instanceFixture is one instance with a single interface "nic0", its pod,
// NetworkInterface and VPCAttachment.
type instanceFixture struct {
	instance   *computev1alpha.Instance
	pod        *corev1.Pod
	iface      *networkingv1alpha.NetworkInterface
	attachment *cloudv1alpha1.VPCAttachment
}

func newInstanceFixture(name string) instanceFixture {
	instance := &computev1alpha.Instance{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tenantNamespace}}
	instance.Spec.Location = &locationsv1alpha1.LocationReference{Name: "location-a"}
	instance.Spec.NetworkInterfaces = []computev1alpha.InstanceNetworkInterface{{Name: "nic0"}}
	instance.Status.NetworkInterfaces = []computev1alpha.InstanceNetworkInterfaceStatus{{
		Name: "nic0", NetworkInterfaceRef: &networkingv1alpha.LocalNetworkInterfaceRef{Name: name + "-nic0"},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name + "-pod", Namespace: tenantNamespace,
			Labels: map[string]string{webhook.InjectInterfacesLabel: labelTrue},
			Annotations: map[string]string{
				nadv1.NetworkStatusAnnot: networkStatus(tenantNamespace + "/" + name + "-nic0"),
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: computev1alpha.GroupVersion.String(), Kind: "Instance", Name: name, Controller: ptr.To(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: podNode},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	iface := &networkingv1alpha.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: name + "-nic0", Namespace: tenantNamespace}}
	iface.Status.AttachmentRef = &networkingv1alpha.NetworkInterfaceAttachmentRef{
		APIGroup: cloudv1alpha1.GroupVersion.Group, Kind: "VPCAttachment", Name: name + "-nic0",
	}
	attachment := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: name + "-nic0", Namespace: tenantNamespace}}
	attachment.Spec.VPC.Name = "vpc-a"
	attachment.Status.Node = podNode
	attachment.Status.Conditions = []metav1.Condition{{
		Type: cloudv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionTrue, Reason: "Advertised",
	}}
	return instanceFixture{instance: instance, pod: pod, iface: iface, attachment: attachment}
}

func (f instanceFixture) objects() []client.Object {
	objs := []client.Object{f.instance, f.pod, f.iface}
	if f.attachment != nil {
		objs = append(objs, f.attachment)
	}
	return objs
}

// networkStatus renders a Multus network-status annotation listing the
// default network and network.
func networkStatus(network string) string {
	raw, err := json.Marshal([]nadv1.NetworkStatus{
		{Name: "default/cluster-network", Default: true},
		{Name: network, Interface: "net1"},
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// series is one scrape, by metric name, as label sets with their values.
type series map[string][]sample

type sample struct {
	labels map[string]string
	value  float64
}

func scrape(t *testing.T, reader client.Reader) series {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(&InstanceAttachmentCollector{Reader: reader})
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := series{}
	for _, family := range families {
		for _, m := range family.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			out[family.GetName()] = append(out[family.GetName()], sample{labels, m.GetGauge().GetValue()})
		}
	}
	return out
}

func (s series) total(state string) float64 {
	for _, m := range s["galactic_vpc_instance_interfaces"] {
		if m.labels["state"] == state {
			return m.value
		}
	}
	return -1
}

// TestInstanceAttachmentState runs one fixture per case through the
// collector and checks the totals and the series naming the unprogrammed
// interface.
func TestInstanceAttachmentState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*instanceFixture)
		// reason is empty when the interface counts as programmed, and
		// "ignored" when the pod is not expected to have an attachment yet.
		reason string
	}{
		{name: "programmed on the pod's node"},
		{
			// A pod that started on the cluster's default network never
			// reached Multus or the Galactic CNI, so it has no network-status
			// and nothing advertised its attachment.
			name: "running pod that bypassed the data plane",
			mutate: func(f *instanceFixture) {
				f.pod.Annotations = nil
				f.attachment.Status.Node = ""
				f.attachment.Status.Conditions = nil
			},
			reason: ReasonPodNotAttached,
		},
		{
			// The pod was recreated on the same node without Multus while the
			// previous pod's advertisement still keeps the attachment
			// Programmed there.
			name:   "pod bypassed the data plane while the attachment is still programmed",
			mutate: func(f *instanceFixture) { f.pod.Annotations = nil },
			reason: ReasonPodNotAttached,
		},
		{
			name: "pod attached to another network only",
			mutate: func(f *instanceFixture) {
				f.pod.Annotations[nadv1.NetworkStatusAnnot] = networkStatus("default/cluster-network")
			},
			reason: ReasonPodNotAttached,
		},
		{
			name:   "unreadable network-status",
			mutate: func(f *instanceFixture) { f.pod.Annotations[nadv1.NetworkStatusAnnot] = "{" },
			reason: ReasonNetworkStatusUnreadable,
		},
		{
			name:   "pod attached, never advertised",
			mutate: func(f *instanceFixture) { f.attachment.Status.Conditions = nil },
			reason: ReasonAwaitingDataPlane,
		},
		{
			name: "advertisement withdrawn",
			mutate: func(f *instanceFixture) {
				f.attachment.Status.Node = ""
				f.attachment.Status.Conditions[0].Status = metav1.ConditionFalse
				f.attachment.Status.Conditions[0].Reason = ReasonAdvertisementWithdrawn
			},
			reason: ReasonAdvertisementWithdrawn,
		},
		{
			name:   "programmed on another node",
			mutate: func(f *instanceFixture) { f.attachment.Status.Node = "node-b" },
			reason: ReasonNodeMismatch,
		},
		{
			name:   "interface not bound",
			mutate: func(f *instanceFixture) { f.instance.Status.NetworkInterfaces = nil },
			reason: ReasonInterfaceUnbound,
		},
		{
			name:   "interface names no attachment",
			mutate: func(f *instanceFixture) { f.iface.Status.AttachmentRef = nil },
			reason: ReasonAttachmentMissing,
		},
		{
			name:   "interface names the former attachment API",
			mutate: func(f *instanceFixture) { f.iface.Status.AttachmentRef.APIGroup = "cloud.datumapis.com" },
			reason: ReasonAttachmentMissing,
		},
		{
			name:   "attachment does not exist",
			mutate: func(f *instanceFixture) { f.attachment = nil },
			reason: ReasonAttachmentMissing,
		},
		{
			name: "pending pod",
			mutate: func(f *instanceFixture) {
				f.pod.Status.Phase = corev1.PodPending
				f.attachment.Status.Conditions = nil
			},
			reason: "ignored",
		},
		{
			name: "unscheduled pod",
			mutate: func(f *instanceFixture) {
				f.pod.Spec.NodeName = ""
				f.attachment.Status.Conditions = nil
			},
			reason: "ignored",
		},
		{
			name: "terminating pod",
			mutate: func(f *instanceFixture) {
				f.pod.DeletionTimestamp = ptr.To(metav1.Now())
				f.pod.Finalizers = []string{"example.com/hold"}
				f.attachment.Status.Conditions = nil
			},
			reason: "ignored",
		},
		{
			name: "pod not owned by an instance",
			mutate: func(f *instanceFixture) {
				f.pod.OwnerReferences[0].Kind = "ReplicaSet"
				f.attachment.Status.Conditions = nil
			},
			reason: "ignored",
		},
		{
			name: "pod not opted in to injection",
			mutate: func(f *instanceFixture) {
				f.pod.Labels = nil
				f.attachment.Status.Conditions = nil
			},
			reason: "ignored",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newInstanceFixture("web-0")
			if test.mutate != nil {
				test.mutate(&f)
			}
			reader := fake.NewClientBuilder().WithScheme(instanceScheme(t)).WithObjects(f.objects()...).Build()
			got := scrape(t, reader)

			if errs := got["galactic_vpc_instance_interfaces_collect_errors"]; len(errs) != 1 || errs[0].value != 0 {
				t.Fatalf("collect errors = %v, want one series at 0", errs)
			}
			unprogrammed := got["galactic_vpc_instance_interface_unprogrammed"]
			wantProgrammed, wantNotProgrammed := 0.0, 0.0
			switch test.reason {
			case "":
				wantProgrammed = 1
			case "ignored":
			default:
				wantNotProgrammed = 1
			}
			if p, n := got.total(stateProgrammed), got.total(stateNotProgrammed); p != wantProgrammed ||
				n != wantNotProgrammed {
				t.Errorf("totals Programmed=%v NotProgrammed=%v, want %v and %v", p, n, wantProgrammed, wantNotProgrammed)
			}
			if wantNotProgrammed == 0 {
				if len(unprogrammed) != 0 {
					t.Errorf("unprogrammed series %v, want none", unprogrammed)
				}
				return
			}
			if len(unprogrammed) != 1 {
				t.Fatalf("unprogrammed series %v, want one", unprogrammed)
			}
			labels := unprogrammed[0].labels
			want := map[string]string{
				"instance_namespace": tenantNamespace, "compute_instance": "web-0", "interface": "nic0",
				"instance_node": podNode, "location": "location-a", "reason": test.reason,
			}
			for k, v := range want {
				if labels[k] != v {
					t.Errorf("label %s = %q, want %q (all: %v)", k, labels[k], v, labels)
				}
			}
			// Only an interface that resolves to its attachment can name it.
			if test.reason != ReasonInterfaceUnbound && test.reason != ReasonAttachmentMissing &&
				(labels["vpc"] != "vpc-a" || labels["attachment"] != "web-0-nic0") {
				t.Errorf("vpc/attachment labels %q/%q, want vpc-a/web-0-nic0", labels["vpc"], labels["attachment"])
			}
		})
	}
}

// TestInstanceAttachmentStateCountsEveryInterface checks that totals cover
// every interface of every running instance and that only the broken ones get
// a series of their own.
func TestInstanceAttachmentStateCountsEveryInterface(t *testing.T) {
	var objs []client.Object
	for i, name := range []string{"web-0", "web-1", "web-2"} {
		f := newInstanceFixture(name)
		if i == 2 {
			f.attachment.Status.Conditions = nil
		}
		objs = append(objs, f.objects()...)
	}
	reader := fake.NewClientBuilder().WithScheme(instanceScheme(t)).WithObjects(objs...).Build()
	got := scrape(t, reader)
	if p, n := got.total(stateProgrammed), got.total(stateNotProgrammed); p != 2 || n != 1 {
		t.Errorf("totals Programmed=%v NotProgrammed=%v, want 2 and 1", p, n)
	}
	unprogrammed := got["galactic_vpc_instance_interface_unprogrammed"]
	if len(unprogrammed) != 1 || unprogrammed[0].labels["compute_instance"] != "web-2" {
		t.Errorf("unprogrammed series %v, want only web-2", unprogrammed)
	}
}

// TestInstanceAttachmentStateSeveralPods checks that an instance with more
// than one running pod exports each interface once: programmed when any pod
// holds it, otherwise with the newest pod's node and reason. Two series with
// the same labels would fail the whole scrape.
func TestInstanceAttachmentStateSeveralPods(t *testing.T) {
	for _, test := range []struct {
		name           string
		olderAttached  bool
		wantProgrammed bool
	}{
		{name: "older pod holds the attachment", olderAttached: true, wantProgrammed: true},
		{name: "no pod holds the attachment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newInstanceFixture("web-0")
			newer := f.pod.DeepCopy()
			newer.Name = "web-0-pod-new"
			newer.Spec.NodeName = "node-b"
			newer.CreationTimestamp = metav1.NewTime(time.Unix(2000, 0))
			newer.Annotations = nil
			f.pod.CreationTimestamp = metav1.NewTime(time.Unix(1000, 0))
			if !test.olderAttached {
				f.pod.Annotations = nil
			}
			reader := fake.NewClientBuilder().WithScheme(instanceScheme(t)).
				WithObjects(append(f.objects(), newer)...).Build()
			got := scrape(t, reader)
			unprogrammed := got["galactic_vpc_instance_interface_unprogrammed"]
			if test.wantProgrammed {
				if got.total(stateProgrammed) != 1 || got.total(stateNotProgrammed) != 0 || len(unprogrammed) != 0 {
					t.Errorf("totals %v/%v, series %v; want one programmed interface",
						got.total(stateProgrammed), got.total(stateNotProgrammed), unprogrammed)
				}
				return
			}
			if got.total(stateProgrammed) != 0 || got.total(stateNotProgrammed) != 1 || len(unprogrammed) != 1 {
				t.Fatalf("totals %v/%v, series %v; want one unprogrammed interface",
					got.total(stateProgrammed), got.total(stateNotProgrammed), unprogrammed)
			}
			if l := unprogrammed[0].labels; l["instance_node"] != "node-b" || l["reason"] != ReasonPodNotAttached {
				t.Errorf("labels %v, want the newest pod's node-b and %s", l, ReasonPodNotAttached)
			}
		})
	}
}

// TestInstanceAttachmentStateEmptyCluster checks that a cell with no instances
// still exports zero totals and the error gauge, so the series being absent
// always means the source is missing.
func TestInstanceAttachmentStateEmptyCluster(t *testing.T) {
	got := scrape(t, fake.NewClientBuilder().WithScheme(instanceScheme(t)).Build())
	if p, n := got.total(stateProgrammed), got.total(stateNotProgrammed); p != 0 || n != 0 {
		t.Errorf("totals Programmed=%v NotProgrammed=%v, want 0 and 0", p, n)
	}
	if errs := got["galactic_vpc_instance_interfaces_collect_errors"]; len(errs) != 1 || errs[0].value != 0 {
		t.Errorf("collect errors = %v, want one series at 0", errs)
	}
}

// TestInstanceAttachmentStateListFailure checks that a kind that cannot be
// listed is reported and suppresses the interface series, rather than making
// every attachment look missing or every instance look healthy.
func TestInstanceAttachmentStateListFailure(t *testing.T) {
	for _, failing := range []client.ObjectList{
		&corev1.PodList{}, &computev1alpha.InstanceList{},
		&networkingv1alpha.NetworkInterfaceList{}, &cloudv1alpha1.VPCAttachmentList{},
	} {
		t.Run(fmt.Sprintf("%T", failing), func(t *testing.T) {
			f := newInstanceFixture("web-0")
			f.attachment.Status.Conditions = nil
			reader := fake.NewClientBuilder().WithScheme(instanceScheme(t)).WithObjects(f.objects()...).
				WithInterceptorFuncs(interceptor.Funcs{List: func(
					ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption,
				) error {
					if reflect.TypeOf(list) == reflect.TypeOf(failing) {
						return errors.New("cache not synced")
					}
					return c.List(ctx, list, opts...)
				}}).Build()
			got := scrape(t, reader)
			if errs := got["galactic_vpc_instance_interfaces_collect_errors"]; len(errs) != 1 || errs[0].value != 1 {
				t.Errorf("collect errors = %v, want one series at 1", errs)
			}
			names := slices.Sorted(maps.Keys(got))
			if !slices.Equal(names, []string{"galactic_vpc_instance_interfaces_collect_errors"}) {
				t.Errorf("exported %v, want only the error gauge", names)
			}
		})
	}
}
