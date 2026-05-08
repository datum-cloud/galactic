// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	galacticv1alpha "go.datum.net/galactic/pkg/apis/v1alpha"

	"go.datum.net/galactic/internal/operator/bgpattrs"
	"go.datum.net/galactic/internal/operator/identifier"
	"go.datum.net/galactic/internal/operator/srv6sid"
)

// Test fixtures for the cluster-wide SRv6/BGP config. These are arbitrary
// for the test; the values just need to be consistent across runs.
const (
	testPOPLocator = "fc00::/56"
	testASN        = uint32(65000)
)

func newSIDEncoder() *srv6sid.Encoder {
	enc, err := srv6sid.NewEncoder(testPOPLocator)
	Expect(err).NotTo(HaveOccurred())
	return enc
}

func newBGPFormatter() *bgpattrs.Formatter {
	f, err := bgpattrs.NewFormatter(testASN)
	Expect(err).NotTo(HaveOccurred())
	return f
}

var _ = Describe("VPCAttachment Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		vpcName := "test-vpc"
		vpcTypeNamespacedName := types.NamespacedName{
			Name:      vpcName,
			Namespace: "default",
		}

		BeforeEach(func() {
			err := nadv1.AddToScheme(k8sClient.Scheme())
			Expect(err).NotTo(HaveOccurred())

			By("creating the custom resource for the Kind VPC")
			resource := &galacticv1alpha.VPC{}
			err = k8sClient.Get(ctx, vpcTypeNamespacedName, resource)
			if err != nil && errors.IsNotFound(err) {
				resource := &galacticv1alpha.VPC{
					ObjectMeta: metav1.ObjectMeta{
						Name:      vpcName,
						Namespace: "default",
					},
					Spec: galacticv1alpha.VPCSpec{
						Networks: []string{
							"10.1.1.0/24",
							"2001:10:1:1::/64",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &galacticv1alpha.VPC{}
			err := k8sClient.Get(ctx, vpcTypeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("cleanup the specific resource instance VPC")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("creating the custom resource for the Kind VPCAttachment")

			vpcAttachmentName := "test-vpcattachment"
			vpcAttachmentTypeNamespacedName := types.NamespacedName{
				Name:      vpcAttachmentName,
				Namespace: "default",
			}

			resource := &galacticv1alpha.VPCAttachment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vpcAttachmentName,
					Namespace: "default",
				},
				Spec: galacticv1alpha.VPCAttachmentSpec{
					VPC: corev1.ObjectReference{
						APIVersion: "galactic.datumapis.com/v1alpha",
						Kind:       "VPC",
						Name:       vpcName,
						Namespace:  "default",
					},
					Interface: galacticv1alpha.VPCAttachmentInterface{
						Name: "galactic0",
						Addresses: []string{
							"10.1.1.1/24",
							"2001:10:1:1::1/64",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			Expect(resource.Status.Ready).To(BeFalse())
			Expect(resource.Status.Identifier).To(BeEmpty())

			for run := 1; run <= 3; run++ { // make sure multiple reconcile runs work
				By(fmt.Sprintf("reconciling the created resource (run #%d)", run))

				if run > 1 { // skip the first run to test what happens if the the VPC is not ready yet
					vpcControllerReconciler := &VPCReconciler{
						Client:     k8sClient,
						Scheme:     k8sClient.Scheme(),
						Identifier: identifier.NewFromSeed(424242),
					}
					_, err := vpcControllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: vpcTypeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
				}

				vpcAttachmentControllerReconciler := &VPCAttachmentReconciler{
					Client:       k8sClient,
					Scheme:       k8sClient.Scheme(),
					Identifier:   identifier.NewFromSeed(424242),
					SIDEncoder:   newSIDEncoder(),
					BGPFormatter: newBGPFormatter(),
				}
				_, err := vpcAttachmentControllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: vpcAttachmentTypeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())

				resource = &galacticv1alpha.VPCAttachment{}
				err = k8sClient.Get(ctx, vpcAttachmentTypeNamespacedName, resource)
				Expect(err).NotTo(HaveOccurred())
				if run == 1 {
					Expect(resource.Status.Ready).To(BeFalse())
				} else {
					Expect(resource.Status.Ready).To(BeTrue())
					Expect(resource.Status.Identifier).To(Equal("e513"))
					// VPC's seeded identifier under MaxVPC=0xFFFFFFFF
					// is "02d1d335" (47305525 decimal). The expected
					// SID/RT/RD are derived from that and from the test
					// POP-locator/ASN constants above.
					Expect(resource.Status.ServiceSID).To(Equal("fc00::2d1:d335:e513:0"))
					Expect(resource.Status.RouteTarget).To(Equal("65000:47305525"))
					Expect(resource.Status.RouteDistinguisher).To(Equal("65000:47305525"))

					nadResource := &nadv1.NetworkAttachmentDefinition{}
					err = k8sClient.Get(ctx, vpcAttachmentTypeNamespacedName, nadResource)
					Expect(err).NotTo(HaveOccurred())
					Expect(len(nadResource.Spec.Config)).To(BeNumerically(">", 100))
				}
			}
		})
	})
})
