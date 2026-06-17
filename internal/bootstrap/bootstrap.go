// Package bootstrap manages the lifecycle of galactic-agent's BGPProvider resource.
package bootstrap

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	providersv1alpha1 "go.miloapis.com/cosmos/api/providers/v1alpha1"
)

const (
	labelNode      = "bgp.miloapis.com/node"
	labelManagedBy = "galactic.io/managed-by"
	labelRole      = "galactic.io/role"
	labelDaemon    = "galactic.io/daemon"

	managedByValue = "galactic-agent"
	defaultRole    = "overlay"
)

// providerName returns the BGPProvider resource name for this node and role.
// The default "overlay" role uses the short form for compatibility with existing
// deployments; additional roles append a suffix.
func providerName(nodeName, role string) string {
	if role == "" || role == defaultRole {
		return fmt.Sprintf("galactic-gobgp-%s", nodeName)
	}
	return fmt.Sprintf("galactic-gobgp-%s-%s", nodeName, role)
}

// EnsureGoBGPProvider creates or updates the BGPProvider resource for this node.
// Idempotent — safe to call on every startup.
func EnsureGoBGPProvider(ctx context.Context, c client.Client, nodeName, role, endpoint string) error {
	if role == "" {
		role = defaultRole
	}

	obj := &providersv1alpha1.BGPProvider{}
	obj.Name = providerName(nodeName, role)

	_, err := controllerutil.CreateOrUpdate(ctx, c, obj, func() error {
		if obj.Labels == nil {
			obj.Labels = make(map[string]string)
		}
		obj.Labels[labelNode] = nodeName
		obj.Labels[labelManagedBy] = managedByValue
		obj.Labels[labelRole] = role
		obj.Labels[labelDaemon] = "gobgp"
		obj.Spec = providersv1alpha1.BGPProviderSpec{
			Type:     "GoBGP",
			Endpoint: endpoint,
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("bootstrap: ensure BGPProvider %s: %w", obj.Name, err)
	}
	return nil
}

// DeleteGoBGPProvider removes the BGPProvider resource for this node and role.
// Idempotent — safe to call even if the resource does not exist.
func DeleteGoBGPProvider(ctx context.Context, c client.Client, nodeName, role string) error {
	obj := &providersv1alpha1.BGPProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: providerName(nodeName, role),
		},
	}
	if err := c.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("bootstrap: delete BGPProvider %s: %w", obj.Name, err)
	}
	return nil
}
