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

package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

const (
	chainNamespace = "tenant"
	chainInstance  = "web-0"
	chainInterface = "web-0-eth0"
)

// attachmentChain is the set of objects the operator writes for one instance
// interface, each controlled by the next, as a test case starts from.
type attachmentChain struct {
	instance   *computev1alpha.Instance
	claim      *networkingv1alpha.NetworkInterfaceClaim
	iface      *networkingv1alpha.NetworkInterface
	attachment *cloudv1alpha1.VPCAttachment
	nad        *nadv1.NetworkAttachmentDefinition
}

func controllerRef(apiVersion, kind, name string, uid types.UID) []metav1.OwnerReference {
	return []metav1.OwnerReference{{
		APIVersion: apiVersion, Kind: kind, Name: name, UID: uid, Controller: new(true),
	}}
}

// newAttachmentChain returns a chain wholly held by the instance.
func newAttachmentChain() *attachmentChain {
	meta := func(name string, uid types.UID) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: chainNamespace, UID: uid}
	}
	c := &attachmentChain{}
	c.instance = &computev1alpha.Instance{
		ObjectMeta: meta(chainInstance, "instance-uid"),
		Spec: computev1alpha.InstanceSpec{
			NetworkInterfaces: []computev1alpha.InstanceNetworkInterface{{Name: "eth0"}},
		},
		Status: computev1alpha.InstanceStatus{
			NetworkInterfaces: []computev1alpha.InstanceNetworkInterfaceStatus{{
				Name:                "eth0",
				NetworkInterfaceRef: &networkingv1alpha.LocalNetworkInterfaceRef{Name: chainInterface},
			}},
		},
	}
	c.claim = &networkingv1alpha.NetworkInterfaceClaim{ObjectMeta: meta(chainInterface, "claim-uid")}
	c.claim.OwnerReferences = controllerRef(computev1alpha.GroupVersion.String(), "Instance",
		chainInstance, c.instance.UID)
	c.iface = &networkingv1alpha.NetworkInterface{ObjectMeta: meta(chainInterface, "iface-uid")}
	c.iface.Spec.ClaimRef = &networkingv1alpha.NetworkInterfaceClaimRef{Name: c.claim.Name}
	c.attachment = &cloudv1alpha1.VPCAttachment{ObjectMeta: meta(chainInterface, "attachment-uid")}
	c.attachment.OwnerReferences = controllerRef(networkingv1alpha.GroupVersion.String(), "NetworkInterface",
		c.iface.Name, c.iface.UID)
	c.nad = &nadv1.NetworkAttachmentDefinition{ObjectMeta: meta(chainInterface, "nad-uid")}
	c.nad.Labels = map[string]string{galactic.LabelVPCAttachment: "currentid"}
	c.nad.OwnerReferences = controllerRef(cloudv1alpha1.GroupVersion.String(), "VPCAttachment",
		c.attachment.Name, c.attachment.UID)
	return c
}

func chainScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, computev1alpha.AddToScheme, cloudv1alpha1.AddToScheme,
		networkingv1alpha.AddToScheme, nadv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

// deleting marks an object as being deleted. The fake client keeps such an
// object only while it carries a finalizer.
func deleting(obj client.Object) {
	obj.SetDeletionTimestamp(new(metav1.Now()))
	obj.SetFinalizers([]string{"example.com/hold"})
}

func TestResolveNetworksAttachmentChain(t *testing.T) {
	tests := []struct {
		name string
		// mutate edits the chain, setting a field to nil to leave that object
		// out, and returns any further objects to store.
		mutate func(*attachmentChain) []client.Object
		// deny is a fragment of the denial message, or "" for admission.
		deny string
	}{
		{
			name: "chain held by the instance",
		},
		{
			// A retained interface keeps its interface, attachment and definition
			// across a replacement. Compute replaces the claim under the same
			// name, controlled by the replacement instance.
			name: "retained interface held by the replacement's new claim",
			mutate: func(c *attachmentChain) []client.Object {
				c.claim.UID = "replacement-claim-uid"
				return nil
			},
		},
		{
			name: "claim without a controller",
			mutate: func(c *attachmentChain) []client.Object {
				c.claim.OwnerReferences = nil
				return nil
			},
		},
		{
			// #1332: the instance was deleted and recreated under the same name
			// before garbage collection reached its claim, so every object of the
			// old chain, including the definition, is still present and consistent.
			name: "recreated instance finds its predecessor's chain",
			mutate: func(c *attachmentChain) []client.Object {
				c.claim.OwnerReferences = controllerRef(computev1alpha.GroupVersion.String(), "Instance",
					chainInstance, "previous-instance-uid")
				return nil
			},
			deny: "held by Instance web-0 (uid previous-instance-uid)",
		},
		{
			name: "claim held by another kind",
			mutate: func(c *attachmentChain) []client.Object {
				c.claim.OwnerReferences = controllerRef("v1", "Pod", "web-0", "pod-uid")
				return nil
			},
			deny: "held by Pod web-0",
		},
		{
			name: "claim being deleted",
			mutate: func(c *attachmentChain) []client.Object {
				deleting(c.claim)
				return nil
			},
			deny: "NetworkInterfaceClaim web-0-eth0 is being deleted",
		},
		{
			name: "claim gone",
			mutate: func(c *attachmentChain) []client.Object {
				c.claim = nil
				return nil
			},
			deny: "NetworkInterfaceClaim web-0-eth0 holding NetworkInterface web-0-eth0 no longer exists",
		},
		{
			name: "interface not held by a claim",
			mutate: func(c *attachmentChain) []client.Object {
				c.iface.Spec.ClaimRef = nil
				return nil
			},
			deny: "is not held by a claim",
		},
		{
			name: "interface being deleted",
			mutate: func(c *attachmentChain) []client.Object {
				deleting(c.iface)
				return nil
			},
			deny: "NetworkInterface web-0-eth0 controlling VPCAttachment web-0-eth0 is being deleted",
		},
		{
			name: "attachment controlled by a replaced interface",
			mutate: func(c *attachmentChain) []client.Object {
				c.attachment.OwnerReferences[0].UID = "previous-iface-uid"
				return nil
			},
			deny: "controlled by a previous NetworkInterface web-0-eth0 (uid previous-iface-uid, now iface-uid)",
		},
		{
			name: "attachment controlled by another interface",
			mutate: func(c *attachmentChain) []client.Object {
				other := c.iface.DeepCopy()
				other.Name, other.UID, other.ResourceVersion = "web-1-eth0", "other-iface-uid", ""
				c.attachment.OwnerReferences = controllerRef(networkingv1alpha.GroupVersion.String(),
					"NetworkInterface", other.Name, other.UID)
				return []client.Object{other}
			},
			deny: "controlled by NetworkInterface web-1-eth0, not the bound web-0-eth0",
		},
		{
			name: "attachment being deleted",
			mutate: func(c *attachmentChain) []client.Object {
				deleting(c.attachment)
				return nil
			},
			deny: "VPCAttachment web-0-eth0 controlling attachment definition web-0-eth0 is being deleted",
		},
		{
			name: "attachment gone",
			mutate: func(c *attachmentChain) []client.Object {
				c.attachment = nil
				return nil
			},
			deny: "VPCAttachment web-0-eth0 controlling attachment definition web-0-eth0 no longer exists",
		},
		{
			name: "definition controlled by a replaced attachment",
			mutate: func(c *attachmentChain) []client.Object {
				c.nad.OwnerReferences[0].UID = "previous-attachment-uid"
				return nil
			},
			deny: "controlled by a previous VPCAttachment web-0-eth0",
		},
		{
			name: "definition without a controller",
			mutate: func(c *attachmentChain) []client.Object {
				c.nad.OwnerReferences = nil
				return nil
			},
			deny: "attachment definition web-0-eth0 has no controller",
		},
		{
			name: "definition controlled by another kind",
			mutate: func(c *attachmentChain) []client.Object {
				c.nad.OwnerReferences = controllerRef("example.com/v1", "VPCAttachment",
					chainInterface, c.attachment.UID)
				return nil
			},
			deny: "not a VPCAttachment.galactic.datumapis.com",
		},
		{
			name: "definition being deleted",
			mutate: func(c *attachmentChain) []client.Object {
				deleting(c.nad)
				return nil
			},
			deny: "it is being deleted",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := newAttachmentChain()
			var objects []client.Object
			if test.mutate != nil {
				objects = test.mutate(chain)
			}
			for _, obj := range []client.Object{chain.claim, chain.iface, chain.attachment, chain.nad} {
				if !reflect.ValueOf(obj).IsNil() {
					objects = append(objects, obj)
				}
			}

			injector := &PodInterfaceInjector{
				Client: fake.NewClientBuilder().WithScheme(chainScheme(t)).WithObjects(objects...).Build(),
			}
			networks, injected, denied := injector.resolveNetworks(context.Background(), chain.instance, chainNamespace)

			if test.deny == "" {
				if denied != nil {
					t.Fatalf("denied: %s", denied.Result.Message)
				}
				if len(networks) != 1 || networks[0] != chainNamespace+"/"+chainInterface {
					t.Errorf("networks: got %v", networks)
				}
				if len(injected) != 1 || injected[0] != chainInterface {
					t.Errorf("injected: got %v", injected)
				}
				return
			}
			if denied == nil {
				t.Fatalf("admitted %v, want a denial containing %q", networks, test.deny)
			}
			if denied.Allowed || !strings.Contains(denied.Result.Message, test.deny) {
				t.Errorf("got allowed=%v %q, want a denial containing %q",
					denied.Allowed, denied.Result.Message, test.deny)
			}
		})
	}
}

// TestResolveNetworksChainReadsUncached checks the chain is read through the
// uncached reader, and that a failed read is an error rather than a denial
// carrying a reason that might be wrong.
func TestResolveNetworksChainReadsUncached(t *testing.T) {
	chain := newAttachmentChain()
	scheme := chainScheme(t)
	// The cache still holds the previous instance's claim; the API server holds
	// the replacement's.
	cached := chain.claim.DeepCopy()
	cached.OwnerReferences = controllerRef(computev1alpha.GroupVersion.String(), "Instance",
		chainInstance, "previous-instance-uid")
	cache := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(cached, chain.iface, chain.attachment, chain.nad).Build()
	live := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(chain.claim, chain.iface, chain.attachment, chain.nad).Build()

	injector := &PodInterfaceInjector{Client: cache, APIReader: live}
	if _, _, denied := injector.resolveNetworks(context.Background(), chain.instance, chainNamespace); denied != nil {
		t.Fatalf("denied from a stale cache: %s", denied.Result.Message)
	}

	failing := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(chain.claim, chain.iface, chain.attachment, chain.nad).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*cloudv1alpha1.VPCAttachment); ok {
					return errors.New("connection refused")
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).Build()
	injector = &PodInterfaceInjector{Client: cache, APIReader: failing}
	_, _, denied := injector.resolveNetworks(context.Background(), chain.instance, chainNamespace)
	if denied == nil || denied.Allowed || denied.Result.Code != 500 {
		t.Fatalf("got %+v, want a 500 error response", denied)
	}
}

// TestResolveNetworksStopsAtFirstStaleInterface checks that an instance with
// several interfaces is refused when any one of them still has its
// predecessor's chain, even when the interfaces before it are current.
func TestResolveNetworksStopsAtFirstStaleInterface(t *testing.T) {
	first := newAttachmentChain()
	second := newAttachmentChain()
	for _, obj := range []client.Object{second.claim, second.iface, second.attachment, second.nad} {
		obj.SetName("web-0-eth1")
		obj.SetUID(obj.GetUID() + "-eth1")
	}
	second.iface.Spec.ClaimRef.Name = "web-0-eth1"
	second.attachment.OwnerReferences = controllerRef(networkingv1alpha.GroupVersion.String(),
		"NetworkInterface", second.iface.Name, second.iface.UID)
	second.nad.OwnerReferences = controllerRef(cloudv1alpha1.GroupVersion.String(), "VPCAttachment",
		second.attachment.Name, second.attachment.UID)
	second.claim.OwnerReferences = controllerRef(computev1alpha.GroupVersion.String(), "Instance",
		chainInstance, "previous-instance-uid")

	instance := first.instance
	instance.Spec.NetworkInterfaces = append(instance.Spec.NetworkInterfaces,
		computev1alpha.InstanceNetworkInterface{Name: "eth1"})
	instance.Status.NetworkInterfaces = append(instance.Status.NetworkInterfaces,
		computev1alpha.InstanceNetworkInterfaceStatus{
			Name:                "eth1",
			NetworkInterfaceRef: &networkingv1alpha.LocalNetworkInterfaceRef{Name: "web-0-eth1"},
		})

	injector := &PodInterfaceInjector{Client: fake.NewClientBuilder().WithScheme(chainScheme(t)).
		WithObjects(first.claim, first.iface, first.attachment, first.nad,
			second.claim, second.iface, second.attachment, second.nad).Build()}
	networks, _, denied := injector.resolveNetworks(context.Background(), instance, chainNamespace)
	if denied == nil {
		t.Fatalf("admitted %v with a stale second interface", networks)
	}
	if !strings.Contains(denied.Result.Message, "web-0-eth1") ||
		!strings.Contains(denied.Result.Message, "previous-instance-uid") {
		t.Errorf("denial names the wrong link: %q", denied.Result.Message)
	}
}

// admissionRequest builds the admission request for a pod controlled by the
// instance with the given UID.
func admissionRequest(t *testing.T, ownerUID types.UID) admission.Request {
	t.Helper()
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-0-pod", Namespace: chainNamespace,
			Labels: map[string]string{InjectInterfacesLabel: "true"},
			OwnerReferences: controllerRef(computev1alpha.GroupVersion.String(), "Instance",
				chainInstance, ownerUID),
		},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Namespace: chainNamespace,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

// TestHandleAnchorsOnThePodsInstance checks the instance is read uncached and
// must be the one the pod was created for. A cache still holding the
// predecessor would otherwise make the predecessor's claim look held.
func TestHandleAnchorsOnThePodsInstance(t *testing.T) {
	scheme := chainScheme(t)
	chain := newAttachmentChain()

	// The predecessor, under the same name, still controls the claim.
	predecessor := chain.instance.DeepCopy()
	predecessor.UID = "previous-instance-uid"
	chain.claim.OwnerReferences = controllerRef(computev1alpha.GroupVersion.String(), "Instance",
		chainInstance, predecessor.UID)
	replacement := chain.instance.DeepCopy()
	chainObjects := func(instance *computev1alpha.Instance) []client.Object {
		return []client.Object{instance.DeepCopy(), chain.claim.DeepCopy(), chain.iface.DeepCopy(),
			chain.attachment.DeepCopy(), chain.nad.DeepCopy()}
	}

	tests := []struct {
		name     string
		cached   *computev1alpha.Instance
		live     *computev1alpha.Instance
		ownerUID types.UID
		deny     string
	}{
		{
			name:   "cache holds the predecessor, API server the replacement",
			cached: predecessor, live: replacement, ownerUID: replacement.UID,
			deny: "held by Instance web-0 (uid previous-instance-uid), not this instance (uid instance-uid)",
		},
		{
			name:   "pod created for an instance the name no longer holds",
			cached: replacement, live: replacement, ownerUID: "previous-instance-uid",
			deny: "created for instance tenant/web-0 with uid previous-instance-uid, " +
				"but that name now holds uid instance-uid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			injector := &PodInterfaceInjector{
				Client:    fake.NewClientBuilder().WithScheme(scheme).WithObjects(chainObjects(test.cached)...).Build(),
				APIReader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(chainObjects(test.live)...).Build(),
				Decoder:   admission.NewDecoder(scheme),
			}
			response := injector.Handle(context.Background(), admissionRequest(t, test.ownerUID))
			if response.Allowed || !strings.Contains(response.Result.Message, test.deny) {
				t.Errorf("got allowed=%v %q, want a denial containing %q",
					response.Allowed, response.Result.Message, test.deny)
			}
		})
	}
}

func TestHandleInstanceLifecycle(t *testing.T) {
	scheme := chainScheme(t)
	handle := func(t *testing.T, chain *attachmentChain) admission.Response {
		t.Helper()
		live := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(chain.instance, chain.claim, chain.iface, chain.attachment, chain.nad).Build()
		injector := &PodInterfaceInjector{Client: live, Decoder: admission.NewDecoder(scheme)}
		return injector.Handle(context.Background(), admissionRequest(t, chain.instance.UID))
	}

	t.Run("instance being deleted", func(t *testing.T) {
		chain := newAttachmentChain()
		deleting(chain.instance)
		response := handle(t, chain)
		if response.Allowed || !strings.Contains(response.Result.Message, "instance tenant/web-0 is being deleted") {
			t.Errorf("got allowed=%v %q", response.Allowed, response.Result.Message)
		}
	})

	t.Run("current chain is injected", func(t *testing.T) {
		response := handle(t, newAttachmentChain())
		if !response.Allowed {
			t.Fatalf("denied: %s", response.Result.Message)
		}
		patches, err := json.Marshal(response.Patches)
		if err != nil {
			t.Fatal(err)
		}
		want := `"` + MultusDefaultNetworkAnnotation + `":"` + chainNamespace + "/" + chainInterface + `"`
		if !strings.Contains(string(patches), want) {
			t.Errorf("patch does not set the default network: %s", patches)
		}
	})
}
