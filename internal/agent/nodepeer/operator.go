// Package nodepeer implements the node auto-peer operator.
// It watches corev1.Node objects and creates/updates/deletes BGPEndpoint resources
// named "node-{node.Name}" for each node that has an IPv6 InternalIP.
// The BGPEndpoint represents this node's BGP speaker identity and is used by
// BGPPeeringPolicy to automate BGPSession creation.
package nodepeer

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bgpv1alpha1 "go.datum.net/galactic/pkg/apis/bgp/v1alpha1"
	"go.datum.net/galactic/internal/agent/nodeutil"
)

// Operator reconciles corev1.Node objects into BGPEndpoint resources.
type Operator struct {
	client.Client

	// LocalNodeName is the name of the node this agent is running on.
	LocalNodeName string

	// LocalNodeIPv6 is the IPv6 InternalIP of the local node, used as
	// spec.address on the local node's BGPEndpoint.
	LocalNodeIPv6 string
}

// Reconcile handles Node events: creates/updates BGPEndpoint for ready nodes,
// and deletes BGPEndpoint for non-ready or deleted nodes.
func (o *Operator) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var node corev1.Node
	if err := o.Get(ctx, req.NamespacedName, &node); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Node deleted — clean up its BGPEndpoint.
		return ctrl.Result{}, o.deleteEndpoint(ctx, req.Name)
	}

	// Get the cluster's BGPConfiguration for the AS number.
	asNumber, err := o.clusterASNumber(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get cluster AS number: %w", err)
	}

	// Delete endpoint if node is being deleted or is not Ready.
	if node.DeletionTimestamp != nil || !isNodeReady(&node) {
		return ctrl.Result{}, o.deleteEndpoint(ctx, node.Name)
	}

	// Extract the node's IPv6 InternalIP.
	nodeIP := nodeutil.NodeIPv6(node)
	if nodeIP == nil {
		log.Printf("nodepeer: node %s has no IPv6 InternalIP, skipping", node.Name)
		return ctrl.Result{}, nil
	}

	endpointName := endpointNameForNode(node.Name)

	// Build the desired BGPEndpoint.
	desired := &bgpv1alpha1.BGPEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name: endpointName,
			Labels: map[string]string{
				"bgp.galactic.datumapis.com/type": "node",
				"bgp.galactic.datumapis.com/node": node.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Node",
					Name:       node.Name,
					UID:        node.UID,
				},
			},
		},
		Spec: bgpv1alpha1.BGPEndpointSpec{
			Address:  nodeIP.String(),
			ASNumber: asNumber,
		},
	}

	// Create or update.
	var existing bgpv1alpha1.BGPEndpoint
	err = o.Get(ctx, types.NamespacedName{Name: endpointName}, &existing)
	if err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("get BGPEndpoint %s: %w", endpointName, err)
		}
		// Create.
		if err := o.Create(ctx, desired); err != nil && !errors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("create BGPEndpoint %s: %w", endpointName, err)
		}
		log.Printf("nodepeer: created BGPEndpoint %s (address=%s)", endpointName, nodeIP)
		return ctrl.Result{}, nil
	}

	// Update if spec differs.
	if existing.Spec.Address != desired.Spec.Address ||
		existing.Spec.ASNumber != desired.Spec.ASNumber {

		patch := client.MergeFrom(existing.DeepCopy())
		existing.Spec = desired.Spec
		if err := o.Patch(ctx, &existing, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("patch BGPEndpoint %s: %w", endpointName, err)
		}
		log.Printf("nodepeer: updated BGPEndpoint %s (address=%s)", endpointName, nodeIP)
	}

	return ctrl.Result{}, nil
}

// deleteEndpoint removes the BGPEndpoint for a given node name if it exists.
func (o *Operator) deleteEndpoint(ctx context.Context, nodeName string) error {
	endpointName := endpointNameForNode(nodeName)
	var endpoint bgpv1alpha1.BGPEndpoint
	if err := o.Get(ctx, types.NamespacedName{Name: endpointName}, &endpoint); err != nil {
		return client.IgnoreNotFound(err)
	}
	if err := o.Delete(ctx, &endpoint); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("delete BGPEndpoint %s: %w", endpointName, err)
	}
	log.Printf("nodepeer: deleted BGPEndpoint %s", endpointName)
	return nil
}

// clusterASNumber reads the BGPConfiguration named "default" and returns its AS number.
func (o *Operator) clusterASNumber(ctx context.Context) (uint32, error) {
	var cfg bgpv1alpha1.BGPConfiguration
	if err := o.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); err != nil {
		return 0, fmt.Errorf("get BGPConfiguration default: %w", err)
	}
	return cfg.Spec.ASNumber, nil
}

// isNodeReady returns true when the Node's Ready condition is True.
func isNodeReady(node *corev1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// endpointNameForNode returns the deterministic BGPEndpoint name for a given node name.
func endpointNameForNode(nodeName string) string {
	return "node-" + nodeName
}

// SetupWithManager registers the Operator with the controller-runtime manager.
func (o *Operator) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Complete(o)
}
