package v1

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	galacticv1alpha "github.com/datum-cloud/galactic-operator/api/v1alpha"
)

const PodAnnotationMultusNetworks = "k8s.v1.cni.cncf.io/networks"

// nolint:unused
var podlog = logf.Log.WithName("pod-resource")

func SetupPodWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Pod{}).
		WithValidator(&PodCustomValidator{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).
		WithDefaulter(&PodCustomDefaulter{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate--v1-pod,mutating=true,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create;update,versions=v1,name=mpod-v1.kb.io,admissionReviewVersions=v1

type PodCustomDefaulter struct {
	client.Client
	Scheme *runtime.Scheme
}

var _ webhook.CustomDefaulter = &PodCustomDefaulter{}

func (d *PodCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	pod, ok := obj.(*corev1.Pod)

	if !ok {
		return fmt.Errorf("expected an Pod object but got %T", obj)
	}

	if _, exists := pod.Annotations[galacticv1alpha.VPCAttachmentAnnotation]; !exists {
		return nil
	}

	if vpcAttachment, _ := vpcAttachmentByName(d.Client, ctx, pod.Annotations[galacticv1alpha.VPCAttachmentAnnotation], pod.GetNamespace()); vpcAttachment != nil {
		pod.Annotations[PodAnnotationMultusNetworks] = fmt.Sprintf("%s@%s", vpcAttachment.Name, vpcAttachment.Spec.Interface.Name)
	}

	return nil
}

// +kubebuilder:webhook:path=/validate--v1-pod,mutating=false,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create;update,versions=v1,name=vpod-v1.kb.io,admissionReviewVersions=v1

type PodCustomValidator struct {
	client.Client
	Scheme *runtime.Scheme
}

var _ webhook.CustomValidator = &PodCustomValidator{}

func (v *PodCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object but got %T", obj)
	}

	if _, exists := pod.Annotations[galacticv1alpha.VPCAttachmentAnnotation]; !exists {
		return nil, nil
	}

	if _, err := vpcAttachmentByName(v.Client, ctx, pod.Annotations[galacticv1alpha.VPCAttachmentAnnotation], pod.GetNamespace()); err != nil {
		return nil, err
	}

	return nil, nil
}

func (v *PodCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	_, ok := newObj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object for the newObj but got %T", newObj)
	}

	return nil, nil
}

func (v *PodCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	_, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object but got %T", obj)
	}

	return nil, nil
}

func vpcAttachmentByName(k8sClient client.Client, ctx context.Context, name, namespace string) (*galacticv1alpha.VPCAttachment, error) {
	typeNamespacedName := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	var vpcAttachment galacticv1alpha.VPCAttachment
	if err := k8sClient.Get(ctx, typeNamespacedName, &vpcAttachment); err != nil {
		return nil, err
	}
	return &vpcAttachment, nil
}
