// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"strings"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

func withNodeName(t *testing.T, nodeName string) {
	t.Helper()
	t.Setenv(config.EnvCNINodeName, nodeName)
	orig := cniConfig
	cniConfig = config.NewCNIConfig()
	cniConfig.Resolve(&config.ConflistValues{NodeName: nodeName})
	t.Cleanup(func() { cniConfig = orig })
}

func testPluginConf() *PluginConf {
	return &PluginConf{VPC: testVPC, VPCAttachment: testAttachment, Namespace: testPodNamespace}
}

func TestCheckEndpointSlice(t *testing.T) {
	const nodeName = "node1"
	withNodeName(t, nodeName)

	wantTenantID := crdnames.TenantIdentifier(testVPC, testAttachment)

	t.Run("missing EndpointSlice is an error", func(t *testing.T) {
		k8s := fakeClient()
		err := checkEndpointSlice(
			context.Background(), k8s, testPluginConf(), testPodName, testPodNamespace, mustParseAddr(t), false, 0)
		if err == nil {
			t.Fatal("checkEndpointSlice() = nil, want an error when the EndpointSlice does not exist")
		}
	})

	t.Run("address mismatch is an error", func(t *testing.T) {
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testPodNamespace,
				Labels:    map[string]string{crdnames.LabelTenantID: wantTenantID},
				Annotations: map[string]string{
					crdnames.AnnotationTenantID: wantTenantID,
				},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"fd00::dead"}}},
		}
		k8s := fakeClient(slice)
		err := checkEndpointSlice(
			context.Background(), k8s, testPluginConf(), testPodName, testPodNamespace, mustParseAddr(t), false, 0)
		if err == nil {
			t.Fatal("checkEndpointSlice() = nil, want an address-mismatch error")
		}
		if !strings.Contains(err.Error(), "address") {
			t.Errorf("error %q does not mention address", err)
		}
	})

	t.Run("tenant label/annotation mismatch is an error", func(t *testing.T) {
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testPodNamespace,
				Labels:    map[string]string{crdnames.LabelTenantID: testStaleTenantID},
				Annotations: map[string]string{
					crdnames.AnnotationTenantID: testStaleTenantID,
				},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testPodAddr}}},
		}
		k8s := fakeClient(slice)
		err := checkEndpointSlice(
			context.Background(), k8s, testPluginConf(), testPodName, testPodNamespace, mustParseAddr(t), false, 0)
		if err == nil {
			t.Fatal("checkEndpointSlice() = nil, want a tenant-id mismatch error")
		}
		if !strings.Contains(err.Error(), crdnames.LabelTenantID) {
			t.Errorf("error %q does not mention %s", err, crdnames.LabelTenantID)
		}
	})

	t.Run("everything matches, vrfIDKnown false: SID not checked", func(t *testing.T) {
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testPodNamespace,
				Labels:    map[string]string{crdnames.LabelTenantID: wantTenantID},
				Annotations: map[string]string{
					crdnames.AnnotationTenantID: wantTenantID,
				},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testPodAddr}}},
		}
		k8s := fakeClient(slice)
		err := checkEndpointSlice(
			context.Background(), k8s, testPluginConf(), testPodName, testPodNamespace, mustParseAddr(t), false, 0)
		if err != nil {
			t.Fatalf("checkEndpointSlice() = %v, want nil", err)
		}
	})

	t.Run("vrfIDKnown true, SRv6 configured: SID mismatch is an error", func(t *testing.T) {
		const (
			locator = "fd00:10::/48"
			srvNode = 7
			vrfID   = int32(1234)
		)
		router := routerForNode(testRouterName, nodeName, testPodNamespace, 65000)
		router.Spec.SRv6Locator = locator
		router.Spec.NodeID = srvNode

		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testPodNamespace,
				Labels:    map[string]string{crdnames.LabelTenantID: wantTenantID},
				Annotations: map[string]string{
					crdnames.AnnotationTenantID: wantTenantID,
					crdnames.AnnotationSID:      "fd00::dead:beef",
				},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testPodAddr}}},
		}
		k8s := fakeClient(router, slice)

		err := checkEndpointSlice(
			context.Background(), k8s, testPluginConf(), testPodName, testPodNamespace, mustParseAddr(t), true, vrfID)
		if err == nil {
			t.Fatal("checkEndpointSlice() = nil, want a SID-mismatch error")
		}
		if !strings.Contains(err.Error(), crdnames.AnnotationSID) {
			t.Errorf("error %q does not mention %s", err, crdnames.AnnotationSID)
		}
	})

	t.Run("vrfIDKnown true, SRv6 configured: matching SID passes", func(t *testing.T) {
		const (
			locator = "fd00:10::/48"
			srvNode = 7
			vrfID   = int32(1234)
		)
		router := routerForNode(testRouterName, nodeName, testPodNamespace, 65000)
		router.Spec.SRv6Locator = locator
		router.Spec.NodeID = srvNode

		wantSID, err := srv6.ComputeSID(locator, srvNode, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)
		if err != nil {
			t.Fatalf("srv6.ComputeSID: %v", err)
		}

		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testPodNamespace,
				Labels:    map[string]string{crdnames.LabelTenantID: wantTenantID},
				Annotations: map[string]string{
					crdnames.AnnotationTenantID: wantTenantID,
					crdnames.AnnotationSID:      wantSID.String(),
				},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testPodAddr}}},
		}
		k8s := fakeClient(router, slice)

		if err := checkEndpointSlice(
			context.Background(), k8s, testPluginConf(), testPodName, testPodNamespace, mustParseAddr(t), true, vrfID,
		); err != nil {
			t.Fatalf("checkEndpointSlice() = %v, want nil", err)
		}
	})

	t.Run("vrfIDKnown true, SRv6 not configured: SID not checked", func(t *testing.T) {
		const vrfID = int32(1234)
		router := routerForNode(testRouterName, nodeName, testPodNamespace, 65000)

		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testPodNamespace,
				Labels:    map[string]string{crdnames.LabelTenantID: wantTenantID},
				Annotations: map[string]string{
					crdnames.AnnotationTenantID: wantTenantID,
				},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testPodAddr}}},
		}
		k8s := fakeClient(router, slice)

		if err := checkEndpointSlice(
			context.Background(), k8s, testPluginConf(), testPodName, testPodNamespace, mustParseAddr(t), true, vrfID,
		); err != nil {
			t.Fatalf("checkEndpointSlice() = %v, want nil", err)
		}
	})
}
