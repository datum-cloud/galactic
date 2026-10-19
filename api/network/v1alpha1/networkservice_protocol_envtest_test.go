// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Messages the NetworkService schema refuses a protocol or port shape with.
const (
	notServedMessage          = "protocol is not served yet"
	portRequiredMessage       = "port is required for tcp, udp and sctp"
	backendPortRequiredMsg    = "backendPort is required for tcp, udp and sctp"
	portForbiddenMessage      = "port must not be set for esp, gre and icmp"
	backendPortForbiddenMsg   = "backendPort must not be set for esp, gre and icmp"
	unsupportedProtocolPrefix = `spec.protocol: Unsupported value`
)

// protocolNamespace is the namespace every object in this file is created in.
const protocolNamespace = "protocols"

// startProtocolAPI starts an API server serving NetworkService and the three
// other kinds whose protocol field shares NetworkServiceProtocol. It returns
// a client and the NetworkService CRD as installed.
func startProtocolAPI(t *testing.T) (client.Client, *apiextensionsv1.CustomResourceDefinition) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	names := []string{
		"galactic.datumapis.com_networkservices.yaml",
		"galactic.datumapis.com_serviceendpoints.yaml",
		"galactic.datumapis.com_serviceroutepolicies.yaml",
		"galactic.datumapis.com_servicevipbindings.yaml",
	}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", name))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		crds = append(crds, crd)
	}
	environment := &envtest.Environment{CRDs: crds}
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
	_ = apiextensionsv1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: protocolNamespace}}
	if err := c.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	return c, crds[0]
}

// protocolService returns a NetworkService for protocol with the given ports,
// zero meaning unset.
func protocolService(name string, protocol networkv1alpha1.NetworkServiceProtocol,
	port, backendPort int32) *networkv1alpha1.NetworkService {
	return &networkv1alpha1.NetworkService{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: protocolNamespace},
		Spec: networkv1alpha1.NetworkServiceSpec{
			VPCRef:          "vpc-a",
			VIPAddresses:    []string{"2001:db8:1::10"},
			Protocol:        protocol,
			Port:            port,
			BackendSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			BackendPort:     backendPort,
		},
	}
}

// requireRefusal fails unless err is a schema rejection containing every one
// of want and none of unwanted.
func requireRefusal(t *testing.T, err error, want, unwanted []string) {
	t.Helper()
	if !apierrors.IsInvalid(err) {
		t.Fatalf("err = %v, want a schema rejection", err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("err = %v, want it to contain %q", err, w)
		}
	}
	for _, u := range unwanted {
		if strings.Contains(err.Error(), u) {
			t.Errorf("err = %v, want it not to contain %q", err, u)
		}
	}
}

// TestNetworkServiceProtocolAdmission covers every admitted protocol with
// every port shape, against a real API server: tcp and udp need both ports,
// sctp needs both and is refused as not served yet, esp, gre and icmp must
// set neither and are refused as not served yet, and a protocol the schema
// does not list gets the enum's own rejection.
func TestNetworkServiceProtocolAdmission(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()

	type shape struct {
		name              string
		port, backendPort int32
	}
	both := shape{"both ports", 443, 8443}
	none := shape{"no ports", 0, 0}
	portOnly := shape{"port only", 443, 0}
	backendOnly := shape{"backendPort only", 0, 8443}

	tests := []struct {
		protocol networkv1alpha1.NetworkServiceProtocol
		shape    shape
		want     []string // empty: admitted
		unwanted []string
	}{
		{"tcp", both, nil, nil},
		{"tcp", none, []string{portRequiredMessage, backendPortRequiredMsg}, []string{notServedMessage}},
		{"tcp", portOnly, []string{backendPortRequiredMsg}, []string{notServedMessage, portRequiredMessage}},
		{"tcp", backendOnly, []string{portRequiredMessage}, []string{notServedMessage, backendPortRequiredMsg}},
		{"udp", both, nil, nil},
		{"udp", none, []string{portRequiredMessage, backendPortRequiredMsg}, []string{notServedMessage}},
		{"udp", portOnly, []string{backendPortRequiredMsg}, []string{notServedMessage}},
		{"udp", backendOnly, []string{portRequiredMessage}, []string{notServedMessage}},
		{"sctp", both, []string{notServedMessage}, []string{portRequiredMessage, backendPortRequiredMsg}},
		{"sctp", none, []string{notServedMessage, portRequiredMessage, backendPortRequiredMsg}, nil},
		{"sctp", portOnly, []string{notServedMessage, backendPortRequiredMsg}, nil},
		{"sctp", backendOnly, []string{notServedMessage, portRequiredMessage}, nil},
		{"esp", none, []string{notServedMessage}, []string{portForbiddenMessage, backendPortForbiddenMsg}},
		{"esp", both, []string{notServedMessage, portForbiddenMessage, backendPortForbiddenMsg}, nil},
		{"esp", portOnly, []string{notServedMessage, portForbiddenMessage}, []string{backendPortForbiddenMsg}},
		{"esp", backendOnly, []string{notServedMessage, backendPortForbiddenMsg}, []string{portForbiddenMessage}},
		{"gre", none, []string{notServedMessage}, []string{portForbiddenMessage, backendPortForbiddenMsg}},
		{"gre", both, []string{notServedMessage, portForbiddenMessage, backendPortForbiddenMsg}, nil},
		{"gre", portOnly, []string{notServedMessage, portForbiddenMessage}, nil},
		{"gre", backendOnly, []string{notServedMessage, backendPortForbiddenMsg}, nil},
		{"icmp", none, []string{notServedMessage}, []string{portForbiddenMessage, backendPortForbiddenMsg}},
		{"icmp", both, []string{notServedMessage, portForbiddenMessage, backendPortForbiddenMsg}, nil},
		{"icmp", portOnly, []string{notServedMessage, portForbiddenMessage}, nil},
		{"icmp", backendOnly, []string{notServedMessage, backendPortForbiddenMsg}, nil},
		{"quic", both, []string{unsupportedProtocolPrefix}, nil},
		{"quic", none, []string{unsupportedProtocolPrefix}, nil},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("%s %s", tt.protocol, tt.shape.name), func(t *testing.T) {
			svc := protocolService(fmt.Sprintf("create-%d", i), tt.protocol, tt.shape.port, tt.shape.backendPort)
			err := c.Create(ctx, svc)
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("create: %v", err)
				}
				return
			}
			requireRefusal(t, err, tt.want, tt.unwanted)
		})
	}

	// A typed client omits a zero port, so an explicit 0 and an out-of-range
	// value go through unstructured objects.
	for _, tt := range []struct {
		name  string
		field string
		value int64
		want  string
	}{
		{"explicit zero port", "port", 0, "spec.port: Invalid value: 0: spec.port in body should be greater than or equal to 1"},
		{"explicit zero backendPort", "backendPort", 0, "spec.backendPort in body should be greater than or equal to 1"},
		{"port above range", "port", 65536, "spec.port in body should be less than or equal to 65535"},
		{"backendPort above range", "backendPort", 70000, "spec.backendPort in body should be less than or equal to 65535"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := unstructuredService(t, protocolService("range-"+strings.ReplaceAll(tt.name, " ", "-"), "tcp", 443, 8443))
			if err := unstructured.SetNestedField(u.Object, tt.value, "spec", tt.field); err != nil {
				t.Fatal(err)
			}
			requireRefusal(t, c.Create(ctx, u), []string{tt.want}, []string{notServedMessage})
		})
	}
}

// unstructuredService converts svc to an unstructured object, so a test can
// set a field to a value the typed struct would omit.
func unstructuredService(t *testing.T, svc *networkv1alpha1.NetworkService) *unstructured.Unstructured {
	t.Helper()
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(svc)
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{Object: obj}
	u.SetAPIVersion(networkv1alpha1.GroupVersion.String())
	u.SetKind("NetworkService")
	return u
}

// TestNetworkServiceProtocolUpdates covers updates against a real API server:
// a tcp service can switch to udp and back, and an update to a protocol the
// datapath does not serve is refused with the not-served message whatever
// port shape it carries.
func TestNetworkServiceProtocolUpdates(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()
	svc := protocolService("update", "tcp", 443, 8443)
	if err := c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		protocol          networkv1alpha1.NetworkServiceProtocol
		port, backendPort int32
		want              []string
	}{
		{"udp", 443, 8443, nil},
		{"sctp", 443, 8443, []string{notServedMessage}},
		{"icmp", 0, 0, []string{notServedMessage}},
		{"gre", 443, 8443, []string{notServedMessage, portForbiddenMessage}},
		{"tcp", 443, 8443, nil},
	} {
		t.Run(string(tt.protocol), func(t *testing.T) {
			current := &networkv1alpha1.NetworkService{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(svc), current); err != nil {
				t.Fatal(err)
			}
			current.Spec.Protocol, current.Spec.Port, current.Spec.BackendPort = tt.protocol, tt.port, tt.backendPort
			err := c.Update(ctx, current)
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("update: %v", err)
				}
				return
			}
			requireRefusal(t, err, tt.want, nil)
		})
	}
}

// TestNetworkServiceStoredShapeUnchanged covers existing clients against a real
// API server: a tcp and a udp service written in the shape every earlier
// release accepted are stored and read back with the same protocol and ports,
// and an update that leaves them alone still validates.
func TestNetworkServiceStoredShapeUnchanged(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()
	for _, protocol := range []networkv1alpha1.NetworkServiceProtocol{
		networkv1alpha1.NetworkServiceProtocolTCP, networkv1alpha1.NetworkServiceProtocolUDP,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			svc := protocolService("stored-"+string(protocol), protocol, 53, 5353)
			if err := c.Create(ctx, svc); err != nil {
				t.Fatalf("create: %v", err)
			}
			got := &networkv1alpha1.NetworkService{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(svc), got); err != nil {
				t.Fatal(err)
			}
			if got.Spec.Protocol != protocol || got.Spec.Port != 53 || got.Spec.BackendPort != 5353 {
				t.Errorf("stored protocol/port/backendPort = %s/%d/%d, want %s/53/5353",
					got.Spec.Protocol, got.Spec.Port, got.Spec.BackendPort, protocol)
			}
			got.Labels = map[string]string{"edited": "true"}
			if err := c.Update(ctx, got); err != nil {
				t.Fatalf("update leaving protocol and ports alone: %v", err)
			}
		})
	}
}

// TestSharedProtocolKindsAdmitTCPAndUDPOnly covers the other kinds whose
// protocol field shares NetworkServiceProtocol: each still admits tcp and udp
// and refuses every value NetworkService added.
func TestSharedProtocolKindsAdmitTCPAndUDPOnly(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()
	kinds := []struct {
		name   string
		object func(name string, protocol networkv1alpha1.NetworkServiceProtocol) client.Object
		field  string
	}{
		{
			name: "ServiceEndpoint",
			object: func(name string, protocol networkv1alpha1.NetworkServiceProtocol) client.Object {
				return &networkv1alpha1.ServiceEndpoint{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: protocolNamespace},
					Spec: networkv1alpha1.ServiceEndpointSpec{
						ServiceClass: "ipv6-egress-dns",
						Address:      "fd53::53",
						Port:         53,
						Protocol:     protocol,
						DeliveryMode: networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal,
						AttachmentSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"service": "dns"},
						},
					},
				}
			},
			field: "spec.protocol",
		},
		{
			name: "ServiceRoutePolicy",
			object: func(name string, protocol networkv1alpha1.NetworkServiceProtocol) client.Object {
				return &networkv1alpha1.ServiceRoutePolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: protocolNamespace},
					Spec: networkv1alpha1.ServiceRoutePolicySpec{
						ServiceRef:         networkv1alpha1.ServiceEndpointReference{Name: "dns"},
						AttachmentSelector: metav1.LabelSelector{MatchLabels: map[string]string{"access": "dns"}},
						ProtocolPorts:      []networkv1alpha1.ServiceRouteProtocolPort{{Protocol: protocol, Port: 53}},
					},
				}
			},
			field: "spec.protocolPorts[0].protocol",
		},
		{
			name: "ServiceVIPBinding",
			object: func(name string, protocol networkv1alpha1.NetworkServiceProtocol) client.Object {
				return &networkv1alpha1.ServiceVIPBinding{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: protocolNamespace},
					Spec: networkv1alpha1.ServiceVIPBindingSpec{
						TargetRef:      networkv1alpha1.TargetRef{Kind: "Node", Name: "node-a"},
						VPCRef:         "vpc-a",
						VIPAddress:     "2001:db8:1::10",
						Port:           443,
						Protocol:       protocol,
						BackendAddress: "fd00::10",
						BackendPort:    8443,
						EgressKind:     networkv1alpha1.ServiceVIPBindingEgressKindVeth,
					},
				}
			},
			field: "spec.protocol",
		},
	}
	for _, kind := range kinds {
		for _, protocol := range []networkv1alpha1.NetworkServiceProtocol{"tcp", "udp", "sctp", "esp", "gre", "icmp"} {
			t.Run(kind.name+" "+string(protocol), func(t *testing.T) {
				name := strings.ToLower(kind.name) + "-" + string(protocol)
				err := c.Create(ctx, kind.object(name, protocol))
				if protocol == "tcp" || protocol == "udp" {
					if err != nil {
						t.Fatalf("create: %v", err)
					}
					return
				}
				requireRefusal(t, err, []string{kind.field + `: Unsupported value: "` + string(protocol) + `"`}, nil)
			})
		}
	}
}

// TestNetworkServiceRollbackAdmitsEveryAdmittedService covers rollback against
// a real API server: every service the schema admits, created through every
// protocol and port shape, is still valid under the schema that admitted only
// tcp and udp with both ports required, both as a stored object an update
// touches and as a fresh create.
func TestNetworkServiceRollbackAdmitsEveryAdmittedService(t *testing.T) {
	c, current := startProtocolAPI(t)
	ctx := context.Background()

	var admitted []*networkv1alpha1.NetworkService
	for _, protocol := range []networkv1alpha1.NetworkServiceProtocol{"tcp", "udp", "sctp", "esp", "gre", "icmp"} {
		for _, ports := range [][2]int32{{443, 8443}, {0, 0}, {443, 0}, {0, 8443}, {1, 65535}} {
			svc := protocolService(fmt.Sprintf("rollback-%s-%d-%d", protocol, ports[0], ports[1]),
				protocol, ports[0], ports[1])
			if err := c.Create(ctx, svc); err == nil {
				admitted = append(admitted, svc)
			} else if !apierrors.IsInvalid(err) {
				t.Fatalf("create %s: %v", svc.Name, err)
			}
		}
	}
	names := make([]string, 0, len(admitted))
	for _, svc := range admitted {
		names = append(names, svc.Name)
	}
	want := []string{
		"rollback-tcp-443-8443", "rollback-tcp-1-65535",
		"rollback-udp-443-8443", "rollback-udp-1-65535",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("admitted %v, want %v", names, want)
	}

	installLegacyProtocolSchema(ctx, t, c, current)

	for _, svc := range admitted {
		stored := &networkv1alpha1.NetworkService{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(svc), stored); err != nil {
			t.Fatal(err)
		}
		stored.Labels = map[string]string{"rolled-back": "true"}
		if err := c.Update(ctx, stored); err != nil {
			t.Errorf("update %s under the legacy schema: %v", svc.Name, err)
		}
		fresh := protocolService(svc.Name+"-fresh", svc.Spec.Protocol, svc.Spec.Port, svc.Spec.BackendPort)
		if err := c.Create(ctx, fresh); err != nil {
			t.Errorf("create %s under the legacy schema: %v", fresh.Name, err)
		}
	}
}

// installLegacyProtocolSchema replaces the served NetworkService schema with
// current's as it stood before NetworkService admitted protocols without
// ports: protocol limited to tcp and udp with no rule of its own, port and
// backendPort required, and no spec rule about ports. It waits until the API
// server enforces it, which a service with no ports refused for a missing
// required field shows.
func installLegacyProtocolSchema(ctx context.Context, t *testing.T, c client.Client,
	current *apiextensionsv1.CustomResourceDefinition) {
	t.Helper()
	legacy := current.DeepCopy()
	schema := legacy.Spec.Versions[0].Schema.OpenAPIV3Schema
	spec := schema.Properties["spec"]
	protocol := spec.Properties["protocol"]
	protocol.Enum = []apiextensionsv1.JSON{{Raw: []byte(`"tcp"`)}, {Raw: []byte(`"udp"`)}}
	protocol.XValidations = nil
	spec.Properties["protocol"] = protocol
	spec.Required = append(spec.Required, "backendPort", "port")
	slices.Sort(spec.Required)
	kept := spec.XValidations[:0]
	for _, v := range spec.XValidations {
		if !strings.Contains(v.Rule, "self.protocol") {
			kept = append(kept, v)
		}
	}
	spec.XValidations = kept
	schema.Properties["spec"] = spec

	installed := &apiextensionsv1.CustomResourceDefinition{}
	if err := c.Get(ctx, client.ObjectKey{Name: legacy.Name}, installed); err != nil {
		t.Fatal(err)
	}
	installed.Spec.Versions = legacy.Spec.Versions
	if err := c.Update(ctx, installed); err != nil {
		t.Fatalf("install the legacy NetworkService schema: %v", err)
	}
	var lastErr error
	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true,
		func(ctx context.Context) (bool, error) {
			lastErr = c.Create(ctx, protocolService("legacy-probe", "tcp", 0, 0))
			return apierrors.IsInvalid(lastErr) && strings.Contains(lastErr.Error(), "spec.port: Required value"), nil
		})
	if err != nil {
		t.Fatalf("legacy schema not enforced: last probe error %v", lastErr)
	}
}
