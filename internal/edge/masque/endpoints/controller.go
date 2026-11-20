package endpoints

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const FenceLabel = "masque.galactic.datumapis.com/endpoint-fence"

const stateApplied = "Applied"
const stateError = "Error"

type Fence struct {
	RevokedRevision int64                               `json:"revokedRevision,omitempty"`
	Spec            galacticv1alpha1.MASQUEEndpointSpec `json:"spec"`
	Removed         bool                                `json:"removed"`
}

type Controller struct {
	Ready                             func() bool
	Client                            client.Client
	Registry                          *Registry
	Namespace, Provider, Cell, PodUID string
}

func SameIdentity(first, second galacticv1alpha1.MASQUEEndpointSpec) bool {
	return first.MASQUEEndpointScope == second.MASQUEEndpointScope &&
		first.Metro == second.Metro && first.Provider == second.Provider
}

func (controller *Controller) fence(ctx context.Context, spec galacticv1alpha1.MASQUEEndpointSpec, removed bool) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		key := client.ObjectKey{Namespace: controller.Namespace, Name: FenceName(spec.EndpointUID)}
		var config corev1.ConfigMap
		err := controller.Client.Get(ctx, key, &config)
		missing := apierrors.IsNotFound(err)
		var revokedRevision int64
		if err != nil && !missing {
			return err
		}
		if !missing {
			var previous Fence
			if err := json.Unmarshal([]byte(config.Data["fence.json"]), &previous); err != nil {
				return err
			}
			revokedRevision = previous.RevokedRevision
			if !SameIdentity(previous.Spec, spec) || spec.Revision < previous.Spec.Revision ||
				(spec.Revision == previous.Spec.Revision && (spec != previous.Spec || previous.Removed && !removed)) {
				return errors.New("obsolete or conflicting endpoint revision")
			}
			if previous.Spec == spec && previous.Removed == removed {
				return nil
			}
		} else {
			config.ObjectMeta = metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name,
				Labels: map[string]string{FenceLabel: controller.Provider}}
		}
		if removed || !spec.Enabled {
			revokedRevision = spec.Revision
		}
		encoded, err := json.Marshal(Fence{Spec: spec, Removed: removed, RevokedRevision: revokedRevision})
		if err != nil {
			return err
		}
		config.Data = map[string]string{"fence.json": string(encoded)}
		if missing {
			err = controller.Client.Create(ctx, &config)
			if apierrors.IsAlreadyExists(err) {
				return apierrors.NewConflict(corev1.Resource("configmaps"), key.Name, err)
			}
			return err
		}
		return controller.Client.Update(ctx, &config)
	})
}

func GrantRevision(ctx context.Context, reader client.Reader, namespace, endpointUID string) (int64, int64, error) {
	var config corev1.ConfigMap
	if err := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: FenceName(endpointUID)}, &config); err != nil {
		return 0, 0, err
	}
	var fence Fence
	if err := json.Unmarshal([]byte(config.Data["fence.json"]), &fence); err != nil {
		return 0, 0, err
	}
	if fence.Removed || !fence.Spec.Enabled {
		return 0, 0, errors.New("endpoint is revoked")
	}
	return fence.Spec.Revision, fence.RevokedRevision, nil
}

func (controller *Controller) Sync(ctx context.Context) error {
	var endpoints galacticv1alpha1.MASQUEEndpointList
	if err := controller.Client.List(ctx, &endpoints, client.InNamespace(controller.Namespace)); err != nil {
		return err
	}
	var fences corev1.ConfigMapList
	if err := controller.Client.List(ctx, &fences, client.InNamespace(controller.Namespace),
		client.MatchingLabels{FenceLabel: controller.Provider}); err != nil {
		return err
	}
	seen := map[string]bool{}
	hostnames := map[string]int{}
	identities := map[string]int{}
	for _, endpoint := range endpoints.Items {
		if endpoint.Spec.Provider == controller.Provider && endpoint.Spec.Cell == controller.Cell {
			hostnames[endpoint.Spec.Hostname]++
			identities[endpoint.Spec.EndpointUID]++
		}
	}
	var failures []error
	for _, endpoint := range endpoints.Items {
		spec := endpoint.Spec
		if spec.Provider != controller.Provider || spec.Cell != controller.Cell {
			continue
		}
		seen[spec.EndpointUID] = true
		applyErr := ValidateSpec(spec)
		if hostnames[spec.Hostname] > 1 || identities[spec.EndpointUID] > 1 {
			applyErr = errors.New("duplicate endpoint identity or hostname")
		}
		if applyErr == nil {
			applyErr = controller.fence(ctx, spec, !endpoint.DeletionTimestamp.IsZero())
		}
		if applyErr != nil || !spec.Enabled || !endpoint.DeletionTimestamp.IsZero() {
			controller.Registry.Remove(spec.EndpointUID)
		} else {
			applyErr = controller.activate(ctx, spec)
		}
		if err := controller.report(ctx, &endpoint, applyErr); err != nil {
			failures = append(failures, err)
		}
	}
	for _, config := range fences.Items {
		var previous Fence
		if err := json.Unmarshal([]byte(config.Data["fence.json"]), &previous); err != nil {
			failures = append(failures, err)
			continue
		}
		if previous.Spec.Cell == controller.Cell && !seen[previous.Spec.EndpointUID] {
			controller.Registry.Remove(previous.Spec.EndpointUID)
			if err := controller.fence(ctx, previous.Spec, true); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (controller *Controller) activate(ctx context.Context, spec galacticv1alpha1.MASQUEEndpointSpec) error {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: controller.Namespace, Name: spec.CertificateRef.Name}
	err := controller.Client.Get(ctx, key, &secret)
	if err == nil {
		err = controller.Registry.Apply(spec, &secret)
	}
	if err == nil {
		return nil
	}
	current, ok := controller.Registry.Current(spec.EndpointUID)
	if !ok {
		return err
	}
	if current == spec || current.CertificateRef.Name == spec.CertificateRef.Name && apierrors.IsNotFound(err) {
		if apierrors.IsNotFound(err) {
			controller.Registry.Remove(spec.EndpointUID)
		}
		return err
	}
	key.Name = current.CertificateRef.Name
	var previous corev1.Secret
	if previousErr := controller.Client.Get(ctx, key, &previous); previousErr == nil {
		_ = controller.Registry.Apply(current, &previous)
	} else if apierrors.IsNotFound(previousErr) {
		controller.Registry.Remove(spec.EndpointUID)
	}
	return err
}

func (controller *Controller) report(
	ctx context.Context, endpoint *galacticv1alpha1.MASQUEEndpoint, applyErr error,
) error {
	var instance galacticv1alpha1.EdgeInstance
	name := "ei-" + controller.PodUID
	key := client.ObjectKey{Namespace: controller.Namespace, Name: name}
	if err := controller.Client.Get(ctx, key, &instance); err != nil {
		return err
	}
	if instance.Spec.PodUID != controller.PodUID || instance.Spec.ProviderRef.Name != controller.Provider {
		return errors.New("instance identity does not match provider")
	}
	status := galacticv1alpha1.MASQUEEndpointInstanceStatus{
		InstanceName: name, InstanceUID: string(instance.UID), PodUID: controller.PodUID,
		ObservedRevision: endpoint.Spec.Revision, LastHeartbeatTime: metav1.Now(), State: "Disabled", ForwardingStopped: true,
	}
	if current, ok := controller.Registry.Current(endpoint.Spec.EndpointUID); ok {
		status.AppliedRevision = current.Revision
		status.AppliedCertificateRevision = current.CertificateRef.Revision
		status.State, status.ForwardingStopped = stateApplied, false
	} else if applyErr == nil {
		status.AppliedRevision = endpoint.Spec.Revision
	}
	if applyErr != nil {
		status.State, status.Message = stateError, applyErr.Error()
	}
	if status.State == stateApplied && controller.Ready != nil && !controller.Ready() {
		status.State, status.Message = stateError, "provider instance is not ready"
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest galacticv1alpha1.MASQUEEndpoint
		if err := controller.Client.Get(ctx, client.ObjectKeyFromObject(endpoint), &latest); err != nil {
			return err
		}
		if latest.UID != endpoint.UID || latest.Spec != endpoint.Spec {
			return errors.New("endpoint changed before acknowledgment")
		}
		found := false
		for index := range latest.Status.Instances {
			if latest.Status.Instances[index].InstanceName == name {
				latest.Status.Instances[index] = status
				found = true
				break
			}
		}
		if !found {
			latest.Status.Instances = append(latest.Status.Instances, status)
		}
		return controller.Client.Status().Update(ctx, &latest)
	})
}

func (controller *Controller) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = controller.Sync(callCtx)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func CheckScope(
	ctx context.Context, reader client.Reader, namespace, provider string,
	scope *galacticv1alpha1.MASQUEEndpointScope,
) error {
	if scope == nil {
		return nil
	}
	var endpoints galacticv1alpha1.MASQUEEndpointList
	if err := reader.List(ctx, &endpoints, client.InNamespace(namespace)); err != nil {
		return err
	}
	matches := 0
	for _, endpoint := range endpoints.Items {
		if endpoint.Spec.EndpointUID != scope.EndpointUID {
			continue
		}
		matches++
		if !endpoint.Spec.Enabled || !endpoint.DeletionTimestamp.IsZero() || endpoint.Spec.MASQUEEndpointScope != *scope ||
			provider != "" && endpoint.Spec.Provider != provider {
			return errors.New("endpoint scope is disabled or mismatched")
		}
		var config corev1.ConfigMap
		key := client.ObjectKey{Namespace: namespace, Name: FenceName(scope.EndpointUID)}
		if err := reader.Get(ctx, key, &config); err != nil {
			return err
		}
		var fence Fence
		if err := json.Unmarshal([]byte(config.Data["fence.json"]), &fence); err != nil {
			return err
		}
		if fence.Removed || fence.Spec != endpoint.Spec {
			return errors.New("endpoint revision not accepted")
		}
	}
	if matches != 1 {
		return fmt.Errorf("expected one endpoint registration, got %d", matches)
	}
	return nil
}
