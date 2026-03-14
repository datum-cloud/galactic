package bgp

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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"google.golang.org/protobuf/types/known/anypb"

	"go.datum.net/galactic/internal/agent/nodeutil"
	bgpv1alpha1 "go.datum.net/galactic/pkg/apis/bgp/v1alpha1"
	"k8s.io/client-go/kubernetes"
)


// ConfigReconciler reconciles BGPConfiguration resources into GoBGP StartBgp calls.
type ConfigReconciler struct {
	client.Client
	GoBGP     *GoBGPClient
	K8sClient kubernetes.Interface
	NodeName  string
	// SRv6Net is this node's SRv6 /48 prefix (e.g. "2001:db8:ff01::/48").
	// When non-empty, the reconciler advertises this prefix into GoBGP after startup.
	SRv6Net string
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
		return r.setNotReady(ctx, &cfg, fmt.Sprintf("router ID resolution failed: %v", err))
	}

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

	// Advertise this node's SRv6 prefix into GoBGP so peers learn the route.
	// This is idempotent — calling AddPath for an already-advertised prefix is safe.
	if r.SRv6Net != "" {
		localIP, err := nodeutil.LocalNodeIPv6(ctx, r.K8sClient, r.NodeName)
		if err != nil {
			log.Printf("bgp/config: could not get local IPv6 for prefix advertisement: %v", err)
		} else if err := advertiseSRv6Prefix(ctx, c, r.SRv6Net, localIP); err != nil {
			log.Printf("bgp/config: advertise SRv6 prefix %s: %v", r.SRv6Net, err)
		} else {
			log.Printf("bgp/config: advertising SRv6 prefix %s via %s", r.SRv6Net, localIP)
		}
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
	default: // NodeIP
		ip, err := nodeutil.LocalNodeIPv6(ctx, r.K8sClient, r.NodeName)
		if err != nil {
			return "", fmt.Errorf("get local node IPv6: %w", err)
		}
		return ipv6ToRouterID(ip), nil
	}
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

// advertiseSRv6Prefix injects this node's SRv6 /48 prefix into GoBGP's RIB so it is
// distributed to BGP peers. The next-hop is the node's own IPv6 link address.
func advertiseSRv6Prefix(ctx context.Context, c gobgpapi.GobgpApiClient, srv6Net string, localIP net.IP) error {
	_, prefix, err := net.ParseCIDR(srv6Net)
	if err != nil {
		return fmt.Errorf("parse SRv6 prefix %s: %w", srv6Net, err)
	}
	prefixLen, _ := prefix.Mask.Size()

	nlri, err := anypb.New(&gobgpapi.IPAddressPrefix{
		PrefixLen: uint32(prefixLen),
		Prefix:    prefix.IP.String(),
	})
	if err != nil {
		return fmt.Errorf("marshal NLRI: %w", err)
	}

	origin, err := anypb.New(&gobgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return fmt.Errorf("marshal origin: %w", err)
	}

	mpReach, err := anypb.New(&gobgpapi.MpReachNLRIAttribute{
		Family: &gobgpapi.Family{
			Afi:  gobgpapi.Family_AFI_IP6,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		},
		NextHops: []string{localIP.String()},
		Nlris:    []*anypb.Any{nlri},
	})
	if err != nil {
		return fmt.Errorf("marshal mp_reach: %w", err)
	}

	_, err = c.AddPath(ctx, &gobgpapi.AddPathRequest{
		TableType: gobgpapi.TableType_GLOBAL,
		Path: &gobgpapi.Path{
			Family: &gobgpapi.Family{
				Afi:  gobgpapi.Family_AFI_IP6,
				Safi: gobgpapi.Family_SAFI_UNICAST,
			},
			Nlri:   nlri,
			Pattrs: []*anypb.Any{origin, mpReach},
		},
	})
	return err
}

// SetupWithManager registers the ConfigReconciler with the controller-runtime manager.
func (r *ConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPConfiguration{}).
		Complete(r)
}

