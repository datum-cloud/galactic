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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
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

var (
	// vpcAttachmentKind controls each NetworkAttachmentDefinition.
	vpcAttachmentKind = cloudv1alpha1.GroupVersion.WithKind("VPCAttachment").GroupKind()
	// networkInterfaceKind controls each VPCAttachment.
	networkInterfaceKind = networkingv1alpha.GroupVersion.WithKind("NetworkInterface").GroupKind()
)

// PodInterfaceInjector injects the attachments prepared for a Pod's instance.
type PodInterfaceInjector struct {
	client.Client
	// APIReader reads the instance, each definition and the attachment chain
	// behind it without the cache. They are checked while a previous instance's
	// objects are being replaced, and a cached read can still show those as
	// current. When nil, the embedded Client is used.
	APIReader client.Reader
	Decoder   admission.Decoder
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
	owner := instanceOwnerRef(pod)
	if owner == nil {
		return admission.Denied(fmt.Sprintf(
			"pod carries %s but is not owned by a %s, so its interfaces cannot be resolved",
			InjectInterfacesLabel, instanceKind))
	}

	var instance computev1alpha.Instance
	key := types.NamespacedName{Namespace: namespace, Name: owner.Name}
	if err := i.reader().Get(ctx, key, &instance); err != nil {
		if apierrors.IsNotFound(err) {
			return admission.Denied(fmt.Sprintf("instance %s does not exist", key))
		}
		return admission.Errored(http.StatusInternalServerError, err)
	}
	// The pod names the instance it was created for by UID. A different UID
	// under the same name is a predecessor or a replacement, and the claim
	// check below must compare against the pod's own instance.
	if owner.UID != "" && instance.UID != owner.UID {
		return admission.Denied(fmt.Sprintf(
			"pod was created for instance %s with uid %s, but that name now holds uid %s",
			key, owner.UID, instance.UID))
	}
	if !instance.DeletionTimestamp.IsZero() {
		return admission.Denied(fmt.Sprintf("instance %s is being deleted", key))
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
		"instanceName", instance.Name, "interfaces", injected,
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
		if err := i.reader().Get(ctx, key, &nad); err != nil {
			if !apierrors.IsNotFound(err) {
				response := admission.Errored(http.StatusInternalServerError,
					fmt.Errorf("get attachment definition %s: %w", key, err))
				return nil, nil, &response
			}
			response := admission.Denied(fmt.Sprintf(
				"no attachment definition prepared for NetworkInterface %s: %v", key, err))
			return nil, nil, &response
		}
		if _, ours := nad.Labels[galactic.LabelVPCAttachment]; !ours {
			response := admission.Denied(fmt.Sprintf(
				"attachment definition %s carries no attachment identifier", key))
			return nil, nil, &response
		}
		reason, err := i.verifyAttachmentChain(ctx, instance, &nad, interfaceName)
		if err != nil {
			response := admission.Errored(http.StatusInternalServerError, err)
			return nil, nil, &response
		}
		if reason != "" {
			response := admission.Denied(fmt.Sprintf(
				"attachment definition %s does not belong to instance %s yet: %s", key, instance.Name, reason))
			return nil, nil, &response
		}

		networks = append(networks, fmt.Sprintf("%s/%s", nad.Namespace, nad.Name))
		injected = append(injected, interfaceName)
	}
	return networks, injected, nil
}

// verifyAttachmentChain checks that a definition found by name belongs to the
// instance being admitted, and returns why not, or "" when it does.
//
// The definition, its VPCAttachment and its NetworkInterface are all named after
// the instance's interface slot. A replacement instance of the same name finds
// the previous instance's objects under those names until garbage collection
// removes them. That definition still names the previous attachment identifier,
// and nothing on the CNI path can tell it is stale: the runtime hands the plugin
// the identifier the definition names, and the two agree. A pod admitted against
// it is wired under an identifier no attachment record describes, and its
// interface is never reported Programmed (#1332).
//
// So the controller references the operator writes are followed from the
// definition to the claim holding its interface. Each link must be live and be
// the object its reference was written for. The attachment's interface must be
// the one bound to the instance, and the claim must be held by this instance or
// by nothing; a claim without a controller is accepted, as compute accepts it.
// An interface retained across replacements keeps its chain, and its claim is
// held by the replacement, so it passes. A denial makes the provider retry pod
// creation, by which time the chain belongs to the replacement.
func (i *PodInterfaceInjector) verifyAttachmentChain(
	ctx context.Context, instance *computev1alpha.Instance,
	nad *nadv1.NetworkAttachmentDefinition, interfaceName string,
) (string, error) {
	if !nad.DeletionTimestamp.IsZero() {
		return "it is being deleted", nil
	}

	var attachment cloudv1alpha1.VPCAttachment
	reason, err := i.controller(ctx, nad, "attachment definition", vpcAttachmentKind, &attachment)
	if reason != "" || err != nil {
		return reason, err
	}
	var iface networkingv1alpha.NetworkInterface
	reason, err = i.controller(ctx, &attachment, "VPCAttachment", networkInterfaceKind, &iface)
	if reason != "" || err != nil {
		return reason, err
	}
	if iface.Name != interfaceName {
		return fmt.Sprintf("VPCAttachment %s is controlled by NetworkInterface %s, not the bound %s",
			attachment.Name, iface.Name, interfaceName), nil
	}

	if iface.Spec.ClaimRef == nil {
		return fmt.Sprintf("NetworkInterface %s is not held by a claim", iface.Name), nil
	}
	var claim networkingv1alpha.NetworkInterfaceClaim
	key := types.NamespacedName{Namespace: iface.Namespace, Name: iface.Spec.ClaimRef.Name}
	if err := i.reader().Get(ctx, key, &claim); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Sprintf("NetworkInterfaceClaim %s holding NetworkInterface %s no longer exists",
				key.Name, iface.Name), nil
		}
		return "", fmt.Errorf("get NetworkInterfaceClaim %s: %w", key, err)
	}
	if !claim.DeletionTimestamp.IsZero() {
		return fmt.Sprintf("NetworkInterfaceClaim %s is being deleted", claim.Name), nil
	}
	if holder := metav1.GetControllerOf(&claim); holder != nil && holder.UID != instance.UID {
		return fmt.Sprintf("NetworkInterfaceClaim %s is held by %s %s (uid %s), not this instance (uid %s)",
			claim.Name, holder.Kind, holder.Name, holder.UID, instance.UID), nil
	}
	return "", nil
}

// controller reads the object controlling child into parent and returns why it
// cannot be trusted, or "" when it can. child must have a controller of the
// wanted kind, and that object must still exist, carry the UID the reference
// was written for, and not be on its way out.
func (i *PodInterfaceInjector) controller(
	ctx context.Context, child client.Object, childKind string,
	want schema.GroupKind, parent client.Object,
) (string, error) {
	ref := metav1.GetControllerOf(child)
	if ref == nil {
		return fmt.Sprintf("%s %s has no controller", childKind, child.GetName()), nil
	}
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	if err != nil || gv.Group != want.Group || ref.Kind != want.Kind {
		return fmt.Sprintf("%s %s is controlled by %s %s, not a %s",
			childKind, child.GetName(), ref.Kind, ref.Name, want), nil
	}

	key := types.NamespacedName{Namespace: child.GetNamespace(), Name: ref.Name}
	if err := i.reader().Get(ctx, key, parent); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Sprintf("%s %s controlling %s %s no longer exists",
				want.Kind, ref.Name, childKind, child.GetName()), nil
		}
		return "", fmt.Errorf("get %s %s: %w", want.Kind, key, err)
	}
	if parent.GetUID() != ref.UID {
		return fmt.Sprintf("%s %s is controlled by a previous %s %s (uid %s, now %s)",
			childKind, child.GetName(), want.Kind, ref.Name, ref.UID, parent.GetUID()), nil
	}
	if parent.GetDeletionTimestamp() != nil {
		return fmt.Sprintf("%s %s controlling %s %s is being deleted",
			want.Kind, ref.Name, childKind, child.GetName()), nil
	}
	return "", nil
}

// reader returns the uncached reader when one is configured.
func (i *PodInterfaceInjector) reader() client.Reader {
	if i.APIReader != nil {
		return i.APIReader
	}
	return i.Client
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

// InstanceOwner returns the name of the Instance controlling a Pod.
func InstanceOwner(pod *corev1.Pod) (string, bool) {
	if owner := instanceOwnerRef(pod); owner != nil {
		return owner.Name, true
	}
	return "", false
}

// instanceOwnerRef returns the reference to the Instance controlling a Pod, or
// nil when no Instance does.
func instanceOwnerRef(pod *corev1.Pod) *metav1.OwnerReference {
	for idx := range pod.OwnerReferences {
		owner := &pod.OwnerReferences[idx]
		if owner.Kind != instanceKind || owner.Controller == nil || !*owner.Controller {
			continue
		}
		if group, _, _ := strings.Cut(owner.APIVersion, "/"); group != computev1alpha.GroupVersion.Group {
			continue
		}
		return owner
	}
	return nil
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
