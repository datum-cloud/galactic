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

	"go.datum.net/galactic/internal/agent/nodeutil"
	bgpv1alpha1 "go.miloapis.com/bgp/api/v1alpha1"
)

const (
	// srv6NetAnnotation is the Node annotation key that holds the node's SRv6 /48 prefix.
	// The node auto-peer operator reads this annotation to create BGPAdvertisement resources.
	srv6NetAnnotation = "galactic.datumapis.com/srv6-net"
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
				"bgp.miloapis.com/type": "node",
				"bgp.miloapis.com/node": node.Name,
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

	// Create or update the BGPEndpoint.
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
		// Re-read to get the assigned UID for owner references on the advertisement.
		if err := o.Get(ctx, types.NamespacedName{Name: endpointName}, &existing); err != nil {
			return ctrl.Result{}, fmt.Errorf("get BGPEndpoint after create %s: %w", endpointName, err)
		}
	} else if existing.Spec.Address != desired.Spec.Address ||
		existing.Spec.ASNumber != desired.Spec.ASNumber {
		// Update if spec differs.
		patch := client.MergeFrom(existing.DeepCopy())
		existing.Spec = desired.Spec
		if err := o.Patch(ctx, &existing, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("patch BGPEndpoint %s: %w", endpointName, err)
		}
		log.Printf("nodepeer: updated BGPEndpoint %s (address=%s)", endpointName, nodeIP)
	}

	// If the node has an SRv6 net annotation, create/update a BGPAdvertisement
	// to inject that prefix into GoBGP. Owner reference on BGPEndpoint ensures GC.
	if srv6Net, ok := node.Annotations[srv6NetAnnotation]; ok && srv6Net != "" {
		if err := o.ensureSRv6Advertisement(ctx, &existing, node.Name, srv6Net); err != nil {
			log.Printf("nodepeer: ensure SRv6 advertisement for %s: %v", node.Name, err)
			// Non-fatal: BGPEndpoint is still healthy; advertisement will reconcile on next event.
		}
	}

	return ctrl.Result{}, nil
}

// ensureSRv6Advertisement creates or updates the BGPAdvertisement for a node's SRv6 prefix.
// The advertisement is named "node-{nodeName}-srv6" and is owned by the BGPEndpoint.
func (o *Operator) ensureSRv6Advertisement(ctx context.Context, endpoint *bgpv1alpha1.BGPEndpoint, nodeName, srv6Net string) error {
	advertName := "node-" + nodeName + "-srv6"

	desired := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: advertName,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(endpoint, bgpv1alpha1.GroupVersion.WithKind("BGPEndpoint")),
			},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			Prefixes: []string{srv6Net},
		},
	}

	var existing bgpv1alpha1.BGPAdvertisement
	if err := o.Get(ctx, types.NamespacedName{Name: advertName}, &existing); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get BGPAdvertisement %s: %w", advertName, err)
		}
		if createErr := o.Create(ctx, desired); createErr != nil && !errors.IsAlreadyExists(createErr) {
			return fmt.Errorf("create BGPAdvertisement %s: %w", advertName, createErr)
		}
		log.Printf("nodepeer: created BGPAdvertisement %s (prefix=%s)", advertName, srv6Net)
		return nil
	}

	// Update if the prefix list differs.
	if len(existing.Spec.Prefixes) != 1 || existing.Spec.Prefixes[0] != srv6Net {
		patch := client.MergeFrom(existing.DeepCopy())
		existing.Spec.Prefixes = []string{srv6Net}
		if err := o.Patch(ctx, &existing, patch); err != nil {
			return fmt.Errorf("patch BGPAdvertisement %s: %w", advertName, err)
		}
		log.Printf("nodepeer: updated BGPAdvertisement %s (prefix=%s)", advertName, srv6Net)
	}
	return nil
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
