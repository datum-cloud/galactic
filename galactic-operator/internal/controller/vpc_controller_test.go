package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha "github.com/datum-cloud/galactic-operator/api/v1alpha"
	"github.com/datum-cloud/galactic-operator/internal/identifier"
)

var _ = Describe("VPC Controller", func() {
	result_identifiers := []string{
		"f5b6726c782b",
		"f68a7a2a17d9",
		"ecfd7bca4d29",
	}

	Context("When reconciling a resource", func() {
		ctx := context.Background()

		for resourceNum := 0; resourceNum < len(result_identifiers); resourceNum++ {
			var resourceName = fmt.Sprintf("vpc-%d", resourceNum)

			typeNamespacedName := types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}
			vpc := &galacticv1alpha.VPC{}

			BeforeEach(func() {
				By("creating the custom resource for the Kind VPC")
				err := k8sClient.Get(ctx, typeNamespacedName, vpc)
				if err != nil && errors.IsNotFound(err) {
					resource := &galacticv1alpha.VPC{
						ObjectMeta: metav1.ObjectMeta{
							Name:      resourceName,
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

					err = k8sClient.Get(ctx, typeNamespacedName, resource)
					Expect(err).NotTo(HaveOccurred())
					Expect(resource.Status.Ready).To(BeFalse())
					Expect(resource.Status.Identifier).To(BeEmpty())
				}
			})

			It("should successfully reconcile the resource", func() {
				By("reconciling the created resource")
				controllerReconciler := &VPCReconciler{
					Client:     k8sClient,
					Scheme:     k8sClient.Scheme(),
					Identifier: identifier.NewFromSeed(424242),
				}

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())

				resource := &galacticv1alpha.VPC{}
				err = k8sClient.Get(ctx, typeNamespacedName, resource)
				Expect(err).NotTo(HaveOccurred())

				Expect(resource.Status.Ready).To(BeTrue())
				Expect(resource.Status.Identifier).To(Equal(result_identifiers[resourceNum]))
			})
		}

		It("should cleanup the resources", func() {
			By("listing and checking the number of VPCs and then deleting them")
			var vpcs galacticv1alpha.VPCList
			err := k8sClient.List(ctx, &vpcs)
			Expect(err).NotTo(HaveOccurred())
			Expect(vpcs.Items).To(HaveLen(len(result_identifiers)))
			for _, vpc := range vpcs.Items {
				Expect(k8sClient.Delete(ctx, &vpc)).To(Succeed())
			}
		})
	})
})
