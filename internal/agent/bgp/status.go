package bgp

import (
	"context"
	"log"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/pkg/apis/bgp/v1alpha1"
)

const statusPollInterval = 10 * time.Second

// RunStatusPoller polls GoBGP every statusPollInterval and updates BGPSession.status
// for sessions owned by this node. It also emits Prometheus metrics.
// nodeName is used to filter sessions where this node is the local endpoint.
// This function blocks until ctx is cancelled.
func RunStatusPoller(ctx context.Context, k8sClient client.Client, gobgp *GoBGPClient, nodeName string) {
	ticker := time.NewTicker(statusPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollAndUpdate(ctx, k8sClient, gobgp, nodeName)
		}
	}
}

func pollAndUpdate(ctx context.Context, k8sClient client.Client, gobgp *GoBGPClient, nodeName string) {
	c := gobgp.Client()
	if c == nil {
		return
	}

	// Collect peer states from GoBGP keyed by neighbor address.
	peerStates := make(map[string]*gobgpapi.Peer)
	stream, err := c.ListPeer(ctx, &gobgpapi.ListPeerRequest{EnableAdvertised: true})
	if err != nil {
		log.Printf("bgp/status: ListPeer: %v", err)
		return
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		p := resp.Peer
		if p != nil && p.Conf != nil {
			peerStates[p.Conf.NeighborAddress] = p
		}
	}

	// List all BGPSession resources and update their status.
	var sessionList bgpv1alpha1.BGPSessionList
	if err := k8sClient.List(ctx, &sessionList); err != nil {
		log.Printf("bgp/status: list BGPSessions: %v", err)
		return
	}

	for i := range sessionList.Items {
		sess := &sessionList.Items[i]
		if sess.DeletionTimestamp != nil {
			continue
		}

		// Resolve the remote endpoint to get the neighbor address GoBGP uses.
		var remoteEP bgpv1alpha1.BGPEndpoint
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: sess.Spec.RemoteEndpoint}, &remoteEP); err != nil {
			// Endpoint may not exist yet — skip silently; the session reconciler will handle it.
			continue
		}

		gobgpPeer, found := peerStates[remoteEP.Spec.Address]
		if !found {
			continue
		}

		sessionState, isEstablished := peerStateToString(gobgpPeer)
		prevState := sess.Status.SessionState

		patch := client.MergeFrom(sess.DeepCopy())
		sess.Status.SessionState = sessionState

		// Count received/advertised prefixes.
		var rxPrefixes, txPrefixes int64
		for _, af := range gobgpPeer.AfiSafis {
			if af.State != nil {
				rxPrefixes += int64(af.State.Received)
				txPrefixes += int64(af.State.Advertised)
			}
		}
		sess.Status.ReceivedPrefixes = rxPrefixes
		sess.Status.AdvertisedPrefixes = txPrefixes

		// Increment flap counter when transitioning away from Established.
		if prevState == "Established" && !isEstablished {
			sess.Status.FlapCount++
			RecordSessionFlap(sess.Name)
		}

		// Track session state transition time.
		if prevState != sessionState {
			now := metav1.Now()
			sess.Status.LastTransitionTime = &now
		}

		// Set SessionEstablished condition.
		condStatus := metav1.ConditionFalse
		if isEstablished {
			condStatus = metav1.ConditionTrue
		}
		apimeta.SetStatusCondition(&sess.Status.Conditions, metav1.Condition{
			Type:    bgpv1alpha1.BGPSessionEstablished,
			Status:  condStatus,
			Reason:  sessionState,
			Message: "GoBGP session state: " + sessionState,
		})

		if err := k8sClient.Status().Patch(ctx, sess, patch); err != nil {
			log.Printf("bgp/status: patch %s status: %v", sess.Name, err)
		}

		// Emit Prometheus metrics keyed on session name.
		RecordSessionState(sess.Name, sessionState)
		RecordReceivedPrefixes(sess.Name, rxPrefixes)
	}
}

// peerStateToString maps GoBGP peer state to a human-readable string.
// Returns (state string, isEstablished bool).
func peerStateToString(p *gobgpapi.Peer) (string, bool) {
	if p.State == nil {
		return "Unknown", false
	}
	switch p.State.SessionState {
	case gobgpapi.PeerState_UNKNOWN:
		return "Unknown", false
	case gobgpapi.PeerState_IDLE:
		return "Idle", false
	case gobgpapi.PeerState_CONNECT:
		return "Connect", false
	case gobgpapi.PeerState_ACTIVE:
		return "Active", false
	case gobgpapi.PeerState_OPENSENT:
		return "OpenSent", false
	case gobgpapi.PeerState_OPENCONFIRM:
		return "OpenConfirm", false
	case gobgpapi.PeerState_ESTABLISHED:
		return "Established", true
	default:
		return "Unknown", false
	}
}
