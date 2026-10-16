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

// Package webhook delivers a prepared attachment to the Pod that consumes it.
// Injecting the annotation here is what keeps Multus knowledge inside the one
// component that writes NetworkAttachmentDefinitions.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	"go.datum.net/galactic/internal/cloud/galactic"
)

const (
	// InjectInterfacesLabel is the opt-in an infrastructure provider stamps on a
	// Pod. It is a label rather than an annotation because objectSelector matches
	// only labels, and that selector is what bounds a failurePolicy of Fail to
	// the Pods that need an interface.
	InjectInterfacesLabel = "networking.datumapis.com/inject-interfaces"

	// InjectedInterfacesAnnotation records which interfaces were injected, so the
	// difference between the Pod applied and the Pod admitted is traceable.
	InjectedInterfacesAnnotation = "networking.datumapis.com/injected-interfaces"

	// MultusNetworksAnnotation is what Multus resolves at sandbox creation.
	MultusNetworksAnnotation = "k8s.v1.cni.cncf.io/networks"

	// MultusDefaultNetworkAnnotation displaces the cluster's default network for
	// this Pod, so the instance's first interface carries its traffic rather than
	// whatever CNI the cluster installs by default.
	MultusDefaultNetworkAnnotation = "v1.multus-cni.io/default-network"

	// WebhookPath is the path the mutating webhook configuration points at.
	WebhookPath = "/mutate-v1-pod"

	// instanceKind is the owner a Pod must resolve to for interfaces to inject.
	instanceKind = "Instance"
)

// PodInterfaceInjector injects the attachments prepared for a Pod's instance.
type PodInterfaceInjector struct {
	client.Client
	Decoder admission.Decoder
}

// +kubebuilder:rbac:groups=compute.datumapis.com,resources=instances,verbs=get;list;watch

// Handle resolves a Pod to its instance's interfaces and injects the annotation
// that delivers them.
func (i *PodInterfaceInjector) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := i.Decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if pod.Labels[InjectInterfacesLabel] != "true" {
		return admission.Allowed("pod did not opt in to interface injection")
	}

	namespace := req.Namespace
	instanceName, found := instanceOwner(pod)
	if !found {
		return admission.Denied(fmt.Sprintf(
			"pod carries %s but is not owned by a %s, so its interfaces cannot be resolved",
			InjectInterfacesLabel, instanceKind))
	}

	var instance computev1alpha.Instance
	if err := i.Get(ctx, types.NamespacedName{Namespace: namespace, Name: instanceName}, &instance); err != nil {
		if apierrors.IsNotFound(err) {
			return admission.Denied(fmt.Sprintf("instance %s/%s does not exist", namespace, instanceName))
		}
		return admission.Errored(http.StatusInternalServerError, err)
	}

	networks, injected, response := i.resolveNetworks(ctx, &instance, namespace)
	if response != nil {
		return *response
	}
	if len(networks) == 0 {
		return admission.Allowed("instance declares no network interfaces")
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	injectNetworks(pod.Annotations, networks)
	pod.Annotations[InjectedInterfacesAnnotation] = strings.Join(injected, ",")

	patched, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	ctrl.LoggerFrom(ctx).Info("injected network interfaces into pod",
		"instance", instanceName, "interfaces", injected,
		"networks", pod.Annotations[MultusNetworksAnnotation],
		"defaultNetwork", pod.Annotations[MultusDefaultNetworkAnnotation])
	return admission.PatchResponseFromRaw(req.Object.Raw, patched)
}

// resolveNetworks walks the instance's interfaces in declared order and finds the
// attachment definition prepared for each.
func (i *PodInterfaceInjector) resolveNetworks(
	ctx context.Context, instance *computev1alpha.Instance, namespace string,
) (networks, injected []string, denied *admission.Response) {
	for _, declared := range instance.Spec.NetworkInterfaces {
		interfaceName := interfaceRefFor(instance, declared.Name)
		if interfaceName == "" {
			response := admission.Denied(fmt.Sprintf(
				"instance %s has no bound NetworkInterface for %s yet", instance.Name, declared.Name))
			return nil, nil, &response
		}

		// The controller created this NAD alongside the interface, so it shares
		// its name; the convention never crosses a component boundary.
		var nad nadv1.NetworkAttachmentDefinition
		key := types.NamespacedName{Namespace: namespace, Name: interfaceName}
		if err := i.Get(ctx, key, &nad); err != nil {
			response := admission.Denied(fmt.Sprintf(
				"no attachment definition prepared for NetworkInterface %s: %v", key, err))
			return nil, nil, &response
		}
		if _, ours := nad.Labels[galactic.LabelVPCAttachment]; !ours {
			response := admission.Denied(fmt.Sprintf(
				"attachment definition %s carries no attachment identifier", key))
			return nil, nil, &response
		}

		networks = append(networks, fmt.Sprintf("%s/%s", nad.Namespace, nad.Name))
		injected = append(injected, interfaceName)
	}
	return networks, injected, nil
}

// interfaceRefFor returns the NetworkInterface bound to an instance's entry.
func interfaceRefFor(instance *computev1alpha.Instance, name string) string {
	for _, status := range instance.Status.NetworkInterfaces {
		if status.Name != name || status.NetworkInterfaceRef == nil {
			continue
		}
		return status.NetworkInterfaceRef.Name
	}
	return ""
}

// instanceOwner returns the name of the Instance controlling a Pod.
func instanceOwner(pod *corev1.Pod) (string, bool) {
	for _, owner := range pod.OwnerReferences {
		if owner.Kind != instanceKind || owner.Controller == nil || !*owner.Controller {
			continue
		}
		if group, _, _ := strings.Cut(owner.APIVersion, "/"); group != computev1alpha.GroupVersion.Group {
			continue
		}
		return owner.Name, true
	}
	return "", false
}

// injectNetworks makes the first network the Pod's default and lists the rest as
// additional networks. Multus attaches the default network as eth0 on its own, so
// listing it again would attach the same definition a second time as net1.
func injectNetworks(annotations map[string]string, networks []string) {
	defaultNetwork := networks[0]
	annotations[MultusDefaultNetworkAnnotation] = defaultNetwork

	merged := mergeNetworks(annotations[MultusNetworksAnnotation], networks[1:], defaultNetwork)
	if merged == "" {
		delete(annotations, MultusNetworksAnnotation)
		return
	}
	annotations[MultusNetworksAnnotation] = merged
}

// mergeNetworks appends the resolved networks to whatever the Pod already asked
// for, without duplicating an entry or repeating the default network.
func mergeNetworks(existing string, networks []string, defaultNetwork string) string {
	merged := []string{}
	for entry := range strings.SplitSeq(existing, ",") {
		if entry = strings.TrimSpace(entry); entry != "" && entry != defaultNetwork {
			merged = append(merged, entry)
		}
	}
	for _, network := range networks {
		if !slices.Contains(merged, network) {
			merged = append(merged, network)
		}
	}
	return strings.Join(merged, ",")
}

// SetupWithManager registers the webhook with the manager's webhook server.
func (i *PodInterfaceInjector) SetupWithManager(mgr ctrl.Manager) {
	i.Decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register(WebhookPath, &admission.Webhook{Handler: i})
}
