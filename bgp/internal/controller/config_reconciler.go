package controller

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bgpv1alpha1 "go.miloapis.com/bgp/api/v1alpha1"
)

// ConfigReconciler reconciles BGPConfiguration resources into GoBGP StartBgp calls.
type ConfigReconciler struct {
	client.Client
	GoBGP         *GoBGPClient
	LocalEndpoint string
}

// Reconcile ensures GoBGP is configured with the spec from the BGPConfiguration object.
// It only calls StopBgp/StartBgp when the AS or port actually changes.
func (r *ConfigReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var cfg bgpv1alpha1.BGPConfiguration
	if err := r.Get(ctx, req.NamespacedName, &cfg); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// BGPConfiguration deleted: log and do nothing (GoBGP keeps running with last config).
		log.Printf("bgp/config: BGPConfiguration %s not found — leaving GoBGP as-is", req.Name)
		return ctrl.Result{}, nil
	}

	// Resolve router ID.
	routerID, err := r.resolveRouterID(ctx, &cfg)
	if err != nil {
		log.Printf("bgp/config: router ID resolution failed for %s (localEndpoint=%s): %v", req.Name, r.LocalEndpoint, err)
		return r.setNotReady(ctx, &cfg, fmt.Sprintf("router ID resolution failed: %v", err))
	}

	log.Printf("bgp/config: resolved router ID %s for %s (localEndpoint=%s)", routerID, req.Name, r.LocalEndpoint)

	c := r.GoBGP.Client()
	if c == nil {
		return r.setNotReady(ctx, &cfg, "GoBGP not connected")
	}

	// Check current GoBGP state.
	bgpResp, err := c.GetBgp(ctx, &gobgpapi.GetBgpRequest{})
	if err != nil && status.Code(err) != codes.NotFound {
		return r.setNotReady(ctx, &cfg, fmt.Sprintf("GetBgp: %v", err))
	}

	needsRestart := false
	if bgpResp == nil || bgpResp.Global == nil {
		needsRestart = true
	} else {
		current := bgpResp.Global
		if current.Asn != cfg.Spec.ASNumber ||
			current.ListenPort != cfg.Spec.ListenPort ||
			current.RouterId != routerID {
			needsRestart = true
		}
	}

	if needsRestart {
		// Stop if currently running.
		if bgpResp != nil && bgpResp.Global != nil {
			if _, err := c.StopBgp(ctx, &gobgpapi.StopBgpRequest{}); err != nil {
				return r.setNotReady(ctx, &cfg, fmt.Sprintf("StopBgp: %v", err))
			}
			log.Printf("bgp/config: stopped GoBGP for reconfiguration")
		}

		// Start with new config.
		_, err = c.StartBgp(ctx, &gobgpapi.StartBgpRequest{
			Global: &gobgpapi.Global{
				Asn:        cfg.Spec.ASNumber,
				RouterId:   routerID,
				ListenPort: cfg.Spec.ListenPort,
			},
		})
		if err != nil {
			return r.setNotReady(ctx, &cfg, fmt.Sprintf("StartBgp: %v", err))
		}
		log.Printf("bgp/config: started GoBGP AS=%d routerID=%s port=%d",
			cfg.Spec.ASNumber, routerID, cfg.Spec.ListenPort)
	}

	// Update status.
	patch := client.MergeFrom(cfg.DeepCopy())
	cfg.Status.ObservedASNumber = cfg.Spec.ASNumber
	cfg.Status.ObservedRouterID = routerID
	apimeta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
		Type:               bgpv1alpha1.BGPSpeakerReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Configured",
		Message:            fmt.Sprintf("GoBGP running with AS %d router-id %s", cfg.Spec.ASNumber, routerID),
		ObservedGeneration: cfg.Generation,
	})
	if err := r.Status().Patch(ctx, &cfg, patch); err != nil {
		log.Printf("bgp/config: failed to patch status: %v", err)
	}

	return ctrl.Result{}, nil
}

// setNotReady updates the SpeakerReady condition to False with a message and requeues.
func (r *ConfigReconciler) setNotReady(ctx context.Context, cfg *bgpv1alpha1.BGPConfiguration, msg string) (reconcile.Result, error) {
	patch := client.MergeFrom(cfg.DeepCopy())
	apimeta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
		Type:               bgpv1alpha1.BGPSpeakerReady,
		Status:             metav1.ConditionFalse,
		Reason:             "Error",
		Message:            msg,
		ObservedGeneration: cfg.Generation,
	})
	if err := r.Status().Patch(ctx, cfg, patch); err != nil {
		log.Printf("bgp/config: failed to patch status: %v", err)
	}
	return ctrl.Result{}, fmt.Errorf("%s", msg)
}

// resolveRouterID determines the BGP router ID based on RouterIDSource.
func (r *ConfigReconciler) resolveRouterID(ctx context.Context, cfg *bgpv1alpha1.BGPConfiguration) (string, error) {
	switch cfg.Spec.RouterIDSource {
	case "Manual":
		if cfg.Spec.RouterID == "" {
			return "", fmt.Errorf("routerIDSource is Manual but routerID is empty")
		}
		return cfg.Spec.RouterID, nil
	default: // NodeIP — derive from the local node's BGPEndpoint address
		ip, err := r.localEndpointAddress(ctx)
		if err != nil {
			return "", fmt.Errorf("get local endpoint address: %w", err)
		}
		return ipv6ToRouterID(ip), nil
	}
}

// localEndpointAddress looks up the BGPEndpoint identified by LocalEndpoint and
// returns its spec.address as a net.IP. The endpoint is the source of truth for
// the speaker's address — no Kubernetes Node API dependency.
func (r *ConfigReconciler) localEndpointAddress(ctx context.Context) (net.IP, error) {
	endpointName := r.LocalEndpoint
	var ep bgpv1alpha1.BGPEndpoint
	if err := r.Get(ctx, types.NamespacedName{Name: endpointName}, &ep); err != nil {
		return nil, fmt.Errorf("get BGPEndpoint %s: %w", endpointName, err)
	}
	ip := net.ParseIP(ep.Spec.Address)
	if ip == nil {
		return nil, fmt.Errorf("BGPEndpoint %s has invalid address %q", endpointName, ep.Spec.Address)
	}
	return ip, nil
}

// ipv6ToRouterID maps the last 4 bytes of an IPv6 address to a dotted-decimal
// IPv4 string for use as a BGP router ID. This is the standard approach when
// a router has no IPv4 address — the 32-bit router ID is still required by BGP.
func ipv6ToRouterID(ip net.IP) string {
	ip16 := ip.To16()
	if ip16 == nil {
		return "0.0.0.0"
	}
	last4 := ip16[12:]
	n := binary.BigEndian.Uint32(last4)
	return fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// SetupWithManager registers the ConfigReconciler with the controller-runtime manager.
// The GenerationChangedPredicate prevents status-only updates from triggering a
// re-reconcile, which would otherwise create a feedback loop: status patch →
// watch event → reconcile → status patch → ...
func (r *ConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPConfiguration{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
