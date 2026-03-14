// Package bgp implements the Kubernetes-native BGP control plane.
// It reconciles BGPConfiguration, BGPSession, and BGPPeeringPolicy CRDs into
// GoBGP gRPC calls, and runs a route watcher that programs netlink routes from
// BGP RIB events.
package bgp

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/pkg/apis/bgp/v1alpha1"
)

const (
	// gobgpAddr is the local GoBGP gRPC endpoint.
	gobgpAddr = "127.0.0.1:50051"

	// connectMaxAttempts is the maximum number of connection attempts before giving up.
	connectMaxAttempts = 30

	// connectRetryInterval is the wait between connection attempts.
	connectRetryInterval = 2 * time.Second

	// healthPollInterval is how often the health watcher checks GoBGP liveness.
	healthPollInterval = 5 * time.Second
)

// GoBGPClient wraps the GoBGP gRPC connection and exposes helpers used by reconcilers.
// It is safe for concurrent use across reconcilers after Connect() returns.
type GoBGPClient struct {
	mu     sync.RWMutex
	conn   *grpc.ClientConn
	client gobgpapi.GobgpApiClient

	// reconnectCh is closed and recreated each time GoBGP reconnects,
	// allowing reconcilers to trigger full re-reconciliation.
	reconnectCh chan struct{}
	reconnectMu sync.Mutex
}

// NewGoBGPClient creates an unconnected GoBGP client wrapper.
// Call Connect() before using any API methods.
func NewGoBGPClient() *GoBGPClient {
	return &GoBGPClient{
		reconnectCh: make(chan struct{}),
	}
}

// Connect dials GoBGP at gobgpAddr with retries. It blocks until a working
// connection is established or ctx is cancelled.
func (g *GoBGPClient) Connect(ctx context.Context) error {
	for attempt := 0; ; attempt++ {
		conn, err := grpc.NewClient(
			gobgpAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err == nil {
			c := gobgpapi.NewGobgpApiClient(conn)
			_, pingErr := c.GetBgp(ctx, &gobgpapi.GetBgpRequest{})
			if pingErr == nil {
				g.mu.Lock()
				g.conn = conn
				g.client = c
				g.mu.Unlock()
				log.Printf("bgp: connected to GoBGP at %s", gobgpAddr)
				return nil
			}
			conn.Close()
			err = pingErr
		}

		if attempt >= connectMaxAttempts {
			return fmt.Errorf("connect to GoBGP at %s after %d attempts: %w", gobgpAddr, attempt, err)
		}

		log.Printf("bgp: waiting for GoBGP at %s (attempt %d): %v", gobgpAddr, attempt+1, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(connectRetryInterval):
		}
	}
}

// Client returns the underlying GoBGP API client. Callers must hold at least
// a read lock if they need to check validity, but for normal use the client
// is stable after Connect().
func (g *GoBGPClient) Client() gobgpapi.GobgpApiClient {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.client
}

// ReconnectCh returns a channel that is closed when GoBGP reconnects after
// a detected failure. Consumers watch this channel to trigger re-reconciliation.
func (g *GoBGPClient) ReconnectCh() <-chan struct{} {
	g.reconnectMu.Lock()
	defer g.reconnectMu.Unlock()
	return g.reconnectCh
}

// WatchHealth polls GoBGP every healthPollInterval. When it detects GoBGP
// is unreachable, it re-dials and on recovery triggers FullReconcile.
// This function blocks until ctx is cancelled.
func (g *GoBGPClient) WatchHealth(ctx context.Context, k8sClient client.Client, srv6Net string) {
	ticker := time.NewTicker(healthPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c := g.Client()
			if c == nil {
				continue
			}
			_, err := c.GetBgp(ctx, &gobgpapi.GetBgpRequest{})
			if err == nil {
				continue
			}

			log.Printf("bgp: health check failed: %v — attempting reconnect", err)

			// Close the stale connection.
			g.mu.Lock()
			if g.conn != nil {
				g.conn.Close()
				g.conn = nil
				g.client = nil
			}
			g.mu.Unlock()

			// Reconnect with retries.
			if reconnErr := g.Connect(ctx); reconnErr != nil {
				log.Printf("bgp: reconnect failed: %v", reconnErr)
				continue
			}

			// Signal all listeners that GoBGP reconnected.
			g.reconnectMu.Lock()
			close(g.reconnectCh)
			g.reconnectCh = make(chan struct{})
			g.reconnectMu.Unlock()

			log.Printf("bgp: GoBGP reconnected; triggering full re-reconciliation")
			if err := g.FullReconcile(ctx, k8sClient, srv6Net); err != nil {
				log.Printf("bgp: full re-reconciliation failed: %v", err)
			}
		}
	}
}

// FullReconcile re-applies BGPConfiguration and all BGPSessions to GoBGP.
// Called on startup and after GoBGP restarts. GoBGP is treated as stateless —
// the CRDs are the source of truth.
func (g *GoBGPClient) FullReconcile(ctx context.Context, k8sClient client.Client, srv6Net string) error {
	c := g.Client()
	if c == nil {
		return fmt.Errorf("GoBGP client not connected")
	}

	// Fetch the BGPConfiguration to get the listen port.
	var bgpCfg bgpv1alpha1.BGPConfiguration
	listenPort := int32(1790) // default
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "default"}, &bgpCfg); err == nil {
		listenPort = bgpCfg.Spec.ListenPort
	}

	// Re-apply all BGPSession resources by resolving their endpoint references.
	var sessionList bgpv1alpha1.BGPSessionList
	if err := k8sClient.List(ctx, &sessionList); err != nil {
		return fmt.Errorf("list BGPSessions: %w", err)
	}

	applied := 0
	for i := range sessionList.Items {
		sess := &sessionList.Items[i]
		if sess.DeletionTimestamp != nil {
			continue
		}

		var localEP bgpv1alpha1.BGPEndpoint
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: sess.Spec.LocalEndpoint}, &localEP); err != nil {
			log.Printf("bgp: re-reconcile session %s: get local endpoint %q: %v", sess.Name, sess.Spec.LocalEndpoint, err)
			continue
		}

		var remoteEP bgpv1alpha1.BGPEndpoint
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: sess.Spec.RemoteEndpoint}, &remoteEP); err != nil {
			log.Printf("bgp: re-reconcile session %s: get remote endpoint %q: %v", sess.Name, sess.Spec.RemoteEndpoint, err)
			continue
		}

		gobgpPeer := buildGoBGPPeer(sess, &localEP, &remoteEP, listenPort)
		if err := addOrUpdatePeer(ctx, c, gobgpPeer); err != nil {
			log.Printf("bgp: re-reconcile AddPeer %s: %v", remoteEP.Spec.Address, err)
			continue
		}
		applied++
	}

	log.Printf("bgp: full re-reconciliation complete (%d/%d sessions applied)", applied, len(sessionList.Items))
	return nil
}

// buildGoBGPPeer converts a BGPSession and its resolved endpoints into a gobgpapi.Peer struct.
// The remote endpoint provides the neighbor address and peer AS; the local endpoint provides
// the transport local address. listenPort is the non-standard BGP listen port used by GoBGP
// (from BGPConfiguration.Spec.ListenPort); it is set as the remote port so GoBGP dials the
// correct port on the peer.
func buildGoBGPPeer(session *bgpv1alpha1.BGPSession, localEP, remoteEP *bgpv1alpha1.BGPEndpoint, listenPort int32) *gobgpapi.Peer {
	p := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: remoteEP.Spec.Address,
			PeerAsn:         remoteEP.Spec.ASNumber,
		},
		Timers: &gobgpapi.Timers{
			Config: &gobgpapi.TimersConfig{
				HoldTime:          uint64(session.Spec.HoldTime),
				KeepaliveInterval: uint64(session.Spec.KeepaliveTime),
			},
		},
		AfiSafis: buildAfiSafis(remoteEP.Spec.AddressFamilies),
		Transport: &gobgpapi.Transport{
			LocalAddress: localEP.Spec.Address,
			RemotePort:   uint32(listenPort),
		},
	}

	return p
}

// buildAfiSafis converts a list of AddressFamily CRD values into gobgpapi.AfiSafi structs.
// If the list is empty, it defaults to IPv6 unicast.
func buildAfiSafis(afs []bgpv1alpha1.AddressFamily) []*gobgpapi.AfiSafi {
	if len(afs) == 0 {
		return []*gobgpapi.AfiSafi{
			{
				Config: &gobgpapi.AfiSafiConfig{
					Family: &gobgpapi.Family{
						Afi:  gobgpapi.Family_AFI_IP6,
						Safi: gobgpapi.Family_SAFI_UNICAST,
					},
					Enabled: true,
				},
			},
		}
	}

	result := make([]*gobgpapi.AfiSafi, 0, len(afs))
	for _, af := range afs {
		afi, safi := afiSafiFromStrings(af.AFI, af.SAFI)
		result = append(result, &gobgpapi.AfiSafi{
			Config: &gobgpapi.AfiSafiConfig{
				Family: &gobgpapi.Family{
					Afi:  afi,
					Safi: safi,
				},
				Enabled: true,
			},
		})
	}
	return result
}

// afiSafiFromStrings maps the kubebuilder enum strings to GoBGP family constants.
func afiSafiFromStrings(afi, safi string) (gobgpapi.Family_Afi, gobgpapi.Family_Safi) {
	var a gobgpapi.Family_Afi
	switch afi {
	case "IPv4":
		a = gobgpapi.Family_AFI_IP
	default: // IPv6
		a = gobgpapi.Family_AFI_IP6
	}

	var s gobgpapi.Family_Safi
	switch safi {
	case "Multicast":
		s = gobgpapi.Family_SAFI_MULTICAST
	default: // Unicast
		s = gobgpapi.Family_SAFI_UNICAST
	}
	return a, s
}

// addOrUpdatePeer calls AddPeer; on AlreadyExists (or GoBGP's Unknown "can't overwrite"
// error), falls back to UpdatePeer.
// GoBGP returns codes.Unknown with the message "can't overwrite the existing peer"
// rather than codes.AlreadyExists, so we check the message text as a fallback.
func addOrUpdatePeer(ctx context.Context, c gobgpapi.GobgpApiClient, peer *gobgpapi.Peer) error {
	_, err := c.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: peer})
	if err != nil {
		code := status.Code(err)
		msg := status.Convert(err).Message()
		isAlreadyExists := code == codes.AlreadyExists ||
			(code == codes.Unknown && strings.Contains(msg, "can't overwrite the existing peer"))
		if isAlreadyExists {
			_, err = c.UpdatePeer(ctx, &gobgpapi.UpdatePeerRequest{Peer: peer})
			if err != nil {
				return fmt.Errorf("UpdatePeer %s: %w", peer.Conf.NeighborAddress, err)
			}
			return nil
		}
		return fmt.Errorf("AddPeer %s: %w", peer.Conf.NeighborAddress, err)
	}
	return nil
}

// isNotFound returns true when the gRPC error code indicates the resource does not exist.
func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}
