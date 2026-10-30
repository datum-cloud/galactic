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
	"slices"
	"strings"
	"time"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/webhook"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

// Reasons an expected instance interface is not programmed where the
// attachment's Programmed condition gives none. Otherwise the reason is that
// condition's own, as galactic-router reported it.
const (
	// ReasonInterfaceUnbound: the instance has no bound NetworkInterface for
	// one of its declared interfaces.
	ReasonInterfaceUnbound = "InterfaceUnbound"
	// ReasonAttachmentMissing: the NetworkInterface names no Galactic
	// VPCAttachment, or the one it names does not exist.
	ReasonAttachmentMissing = "AttachmentMissing"
	// ReasonPodNotAttached: the pod's Multus network-status lists no network
	// for the interface's NetworkAttachmentDefinition, or the pod has no
	// network-status at all. A pod that started on the cluster's default
	// network without Multus, such as during a node boot, is reported here
	// even while an earlier pod's advertisement keeps the attachment
	// Programmed.
	ReasonPodNotAttached = "PodNotAttached"
	// ReasonNetworkStatusUnreadable: the pod's network-status annotation is
	// not valid JSON, so whether the pod is attached is unknown.
	ReasonNetworkStatusUnreadable = "NetworkStatusUnreadable"
	// ReasonAwaitingDataPlane: the pod is attached but the attachment's
	// Programmed condition was never set, so no node advertised it.
	ReasonAwaitingDataPlane = "AwaitingDataPlane"
	// ReasonNodeMismatch: the attachment is programmed on a node other than
	// the one the pod runs on.
	ReasonNodeMismatch = "NodeMismatch"
)

const (
	stateProgrammed    = "Programmed"
	stateNotProgrammed = "NotProgrammed"
)

var (
	instanceInterfacesDesc = prometheus.NewDesc("galactic_vpc_instance_interfaces",
		"Interfaces of running instances by whether a running pod of the instance holds the interface's VPC "+
			"attachment, programmed on the pod's node.",
		[]string{"state"}, nil)
	instanceInterfaceUnprogrammedDesc = prometheus.NewDesc("galactic_vpc_instance_interface_unprogrammed",
		"1 for each interface of a running instance that no running pod of the instance holds programmed, with the "+
			"reason for its newest pod.",
		[]string{"instance_namespace", "compute_instance", "interface", "vpc", "attachment", "instance_node",
			"location", "reason"}, nil)
	instanceInterfacesCollectErrorsDesc = prometheus.NewDesc("galactic_vpc_instance_interfaces_collect_errors",
		"Kinds the last scrape could not list. While it is above zero no interface series are exported.", nil, nil)
)

// instanceStateTimeout bounds one scrape's reads.
const instanceStateTimeout = 5 * time.Second

// InjectedPodCache limits the manager's Pod cache to the Pods that opt in to
// interface injection, the only Pods InstanceAttachmentCollector reads.
func InjectedPodCache() map[client.Object]cache.ByObject {
	return map[client.Object]cache.ByObject{&corev1.Pod{}: {
		Label: labels.SelectorFromSet(labels.Set{webhook.InjectInterfacesLabel: labelTrue}),
	}}
}

// InstanceAttachmentCollector compares the VPC attachments running instances
// expect with what their pods and the data plane report, read from the cache
// at scrape time. An instance pod that is Running has its sandbox, so Multus
// should already have attached each of the instance's interfaces through the
// Galactic CNI, and galactic-router advertised it. Each instance interface is
// exported once: programmed when any running pod of the instance holds it,
// otherwise with the reason for the newest pod. Every replica exports the
// series; aggregate with max.
type InstanceAttachmentCollector struct {
	// Reader lists Pods, Instances, NetworkInterfaces and VPCAttachments,
	// normally the manager's cached client.
	Reader client.Reader
}

// Describe implements prometheus.Collector.
func (c *InstanceAttachmentCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- instanceInterfacesDesc
	ch <- instanceInterfaceUnprogrammedDesc
	ch <- instanceInterfacesCollectErrorsDesc
}

// Collect implements prometheus.Collector. A kind that fails to list would
// make every interface depending on it look unprogrammed, so a failed list
// suppresses the interface series and is reported instead.
func (c *InstanceAttachmentCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), instanceStateTimeout)
	defer cancel()
	failed := 0
	var pods corev1.PodList
	if err := c.Reader.List(ctx, &pods, client.MatchingLabels{webhook.InjectInterfacesLabel: labelTrue}); err != nil {
		failed++
	}
	var instances computev1alpha.InstanceList
	if err := c.Reader.List(ctx, &instances); err != nil {
		failed++
	}
	var interfaces networkingv1alpha.NetworkInterfaceList
	if err := c.Reader.List(ctx, &interfaces); err != nil {
		failed++
	}
	var attachments cloudv1alpha1.VPCAttachmentList
	if err := c.Reader.List(ctx, &attachments); err != nil {
		failed++
	}
	ch <- prometheus.MustNewConstMetric(instanceInterfacesCollectErrorsDesc, prometheus.GaugeValue, float64(failed))
	if failed > 0 {
		return
	}

	view := clusterView{
		instances:   map[types.NamespacedName]*computev1alpha.Instance{},
		interfaces:  map[types.NamespacedName]*networkingv1alpha.NetworkInterface{},
		attachments: map[types.NamespacedName]*cloudv1alpha1.VPCAttachment{},
	}
	for i := range instances.Items {
		view.instances[client.ObjectKeyFromObject(&instances.Items[i])] = &instances.Items[i]
	}
	for i := range interfaces.Items {
		view.interfaces[client.ObjectKeyFromObject(&interfaces.Items[i])] = &interfaces.Items[i]
	}
	for i := range attachments.Items {
		view.attachments[client.ObjectKeyFromObject(&attachments.Items[i])] = &attachments.Items[i]
	}

	live := map[types.NamespacedName][]*corev1.Pod{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if instance := view.liveInstance(pod); instance != nil {
			key := client.ObjectKeyFromObject(instance)
			live[key] = append(live[key], pod)
		}
	}

	programmed, unprogrammed := 0, 0
	for key, instancePods := range live {
		instance := view.instances[key]
		newestFirst(instancePods)
		location := ""
		if instance.Spec.Location != nil {
			location = instance.Spec.Location.Name
		}
		for _, declared := range instance.Spec.NetworkInterfaces {
			var newest interfaceState
			for i, pod := range instancePods {
				s := view.interfaceState(instance, declared.Name, pod)
				if i == 0 {
					newest = s
				}
				if s.reason == "" {
					newest = s
					break
				}
			}
			if newest.reason == "" {
				programmed++
				continue
			}
			unprogrammed++
			ch <- prometheus.MustNewConstMetric(instanceInterfaceUnprogrammedDesc, prometheus.GaugeValue, 1,
				instance.Namespace, instance.Name, declared.Name, newest.vpc, newest.attachment,
				instancePods[0].Spec.NodeName, location, newest.reason)
		}
	}
	ch <- prometheus.MustNewConstMetric(instanceInterfacesDesc, prometheus.GaugeValue, float64(programmed),
		stateProgrammed)
	ch <- prometheus.MustNewConstMetric(instanceInterfacesDesc, prometheus.GaugeValue, float64(unprogrammed),
		stateNotProgrammed)
}

// newestFirst orders pods by creation time, newest first, then by name.
func newestFirst(pods []*corev1.Pod) {
	slices.SortFunc(pods, func(a, b *corev1.Pod) int {
		if c := b.CreationTimestamp.Compare(a.CreationTimestamp.Time); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
}

// clusterView indexes one scrape's listings by namespace and name.
type clusterView struct {
	instances   map[types.NamespacedName]*computev1alpha.Instance
	interfaces  map[types.NamespacedName]*networkingv1alpha.NetworkInterface
	attachments map[types.NamespacedName]*cloudv1alpha1.VPCAttachment
}

// liveInstance returns the Instance controlling pod when pod is scheduled,
// Running and not terminating, and the Instance is not being deleted.
func (v clusterView) liveInstance(pod *corev1.Pod) *computev1alpha.Instance {
	if pod.DeletionTimestamp != nil || pod.Spec.NodeName == "" || pod.Status.Phase != corev1.PodRunning {
		return nil
	}
	name, ok := webhook.InstanceOwner(pod)
	if !ok {
		return nil
	}
	instance := v.instances[types.NamespacedName{Namespace: pod.Namespace, Name: name}]
	if instance == nil || instance.DeletionTimestamp != nil {
		return nil
	}
	return instance
}

// interfaceState is one instance interface's attachment as the data plane
// sees it. reason is empty when the attachment is programmed on node.
type interfaceState struct {
	vpc, attachment, reason string
}

// interfaceState follows an instance's declared interface to its VPCAttachment
// and checks that pod is attached to it and that it is programmed on pod's
// node.
func (v clusterView) interfaceState(instance *computev1alpha.Instance, declared string, pod *corev1.Pod) interfaceState {
	ref := ""
	for _, status := range instance.Status.NetworkInterfaces {
		if status.Name == declared && status.NetworkInterfaceRef != nil {
			ref = status.NetworkInterfaceRef.Name
		}
	}
	if ref == "" {
		return interfaceState{reason: ReasonInterfaceUnbound}
	}
	iface := v.interfaces[types.NamespacedName{Namespace: instance.Namespace, Name: ref}]
	if iface == nil || iface.Status.AttachmentRef == nil ||
		iface.Status.AttachmentRef.APIGroup != cloudv1alpha1.GroupVersion.Group {
		return interfaceState{reason: ReasonAttachmentMissing}
	}
	name := iface.Status.AttachmentRef.Name
	attachment := v.attachments[types.NamespacedName{Namespace: instance.Namespace, Name: name}]
	if attachment == nil {
		return interfaceState{attachment: name, reason: ReasonAttachmentMissing}
	}
	s := interfaceState{vpc: attachment.Spec.VPC.Name, attachment: name}
	// The pod webhook names each NetworkAttachmentDefinition after its
	// NetworkInterface, and Multus records it as namespace/name.
	if s.reason = podAttached(pod, instance.Namespace+"/"+ref); s.reason != "" {
		return s
	}
	condition := meta.FindStatusCondition(attachment.Status.Conditions, cloudv1alpha1.ConditionTypeProgrammed)
	switch {
	case condition == nil:
		s.reason = ReasonAwaitingDataPlane
	case condition.Status != metav1.ConditionTrue:
		s.reason = condition.Reason
	case attachment.Status.Node != pod.Spec.NodeName:
		s.reason = ReasonNodeMismatch
	}
	return s
}

// podAttached returns an empty reason when pod's Multus network-status lists
// network, and why not otherwise.
func podAttached(pod *corev1.Pod, network string) string {
	raw, ok := pod.Annotations[nadv1.NetworkStatusAnnot]
	if !ok {
		return ReasonPodNotAttached
	}
	var statuses []nadv1.NetworkStatus
	if err := json.Unmarshal([]byte(raw), &statuses); err != nil {
		return ReasonNetworkStatusUnreadable
	}
	for _, status := range statuses {
		if status.Name == network {
			return ""
		}
	}
	return ReasonPodNotAttached
}
