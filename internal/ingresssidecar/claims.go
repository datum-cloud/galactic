// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

// ClaimClient is the part of the Worker client the claim manager uses.
// *workerclient.Client implements it.
type ClaimClient interface {
	Request(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
		spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error)
	Update(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
		spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error)
	Release(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64) (
		*workerv1alpha1.ClaimStatus, error)
}

// ProxyAttachment is the proxy's own VPCAttachment in one VPC on this node.
// Its addresses are the proxy's gateway addresses in the VPC: Envoy's
// upstream sockets send from them, and replies return to them.
type ProxyAttachment struct {
	VPC       string
	UID       string
	Addresses []netip.Addr
}

// BackendAttachment is one backend of the proxy: an EndpointSlice address
// and the VPCAttachment that holds it.
type BackendAttachment struct {
	VPC     string
	UID     string
	Address netip.Addr
}

// ClaimInputs reads what the claims are made of.
type ClaimInputs interface {
	// Attachments returns the proxy's attachments on this node.
	Attachments(ctx context.Context) ([]ProxyAttachment, error)
	// Backends returns every backend whose attachment is known.
	Backends(ctx context.Context) ([]BackendAttachment, error)
}

// PodLink configures the pod's end of a VPC's routed link, in the pod's
// network namespace.
type PodLink interface {
	// Configure enslaves the link podEnd to vpc's VRF, assigns it the
	// gateway addresses and sets it up, and routes each address in local
	// through the link to hostLL in the VRF's table, removing any other
	// route it made there. It returns an error wrapping errVRFMissing while
	// the VRF does not exist.
	Configure(vpc, podEnd string, gateway []netip.Addr, hostLL netip.Addr, local []netip.Addr) error
}

// errVRFMissing is returned while the VPC's VRF in the pod is not created
// yet; the Store creates it with the VPC's first backend route.
var errVRFMissing = errors.New("the VPC's VRF does not exist in the pod yet")

// The states a VPC's claim reports in worker_claims.
const (
	ClaimReady    = "ready"
	ClaimPending  = "pending"
	ClaimRefused  = "refused"
	ClaimNotWired = "unconfigured"
)

// The reasons an unconfigured claim reports.
const (
	// ReasonVRFMissing: the Store has not created the VPC's pod VRF yet.
	ReasonVRFMissing = "VRFMissing"
	// ReasonPodEndNotConfigured: Worker has not reported the routed link's
	// ends yet, or configuring the pod end failed.
	ReasonPodEndNotConfigured = "PodEndNotConfigured"
)

// claimState is the manager's record of one VPC's claim.
type claimState struct {
	key  *workerv1alpha1.ClaimKey
	gen  uint64
	spec *workerv1alpha1.ClaimSpec
	// gateway are the proxy attachment's addresses.
	gateway []netip.Addr
	// backends maps a destination attachment UID to its addresses.
	backends map[string][]netip.Addr
	status   *workerv1alpha1.ClaimStatus
	// refused is the reason Worker last refused a call, until one succeeds.
	refused string
	// wired is true once the pod end is configured for the current status.
	wired   bool
	wireErr error
	// vrfMissingLogged is true once the wait for the VPC's VRF was logged.
	vrfMissingLogged bool
	podEnd           string
	hostLL           netip.Addr
	localSet         []netip.Addr
}

// Claims keeps one Worker socket claim per VPC the proxy serves, and wires
// the pod end of each claim's routed link.
//
// The claim's attachment is the proxy's own VPCAttachment in the VPC on this
// node, and its destinations are the VPCAttachments of the VPC's backends.
// Worker gives the claim a routed link from the VPC's host VRF into this pod
// and resolves each destination to Local or Fabric. The manager routes a
// Local backend over the link and leaves a Fabric backend to the VRF's
// default route into the sidecar's encapsulating datapath. Replies to the
// gateway address return over the link in both cases.
//
// A claim serves one pod. While another pod of the proxy still holds it,
// Worker refuses this pod with ClaimHeldByAnotherPod, and the manager keeps
// retrying, reporting not ready, until that pod is gone.
type Claims struct {
	client  ClaimClient
	inputs  ClaimInputs
	link    PodLink
	node    string
	metrics *ClaimMetrics
	log     *slog.Logger

	mu       sync.Mutex
	claims   map[string]*claimState
	observed map[string]*workerv1alpha1.ClaimStatus
	desired  map[string]bool
	synced   bool
}

// NewClaims returns a claim manager for node.
func NewClaims(client ClaimClient, inputs ClaimInputs, link PodLink, node string, m *ClaimMetrics) *Claims {
	return &Claims{client: client, inputs: inputs, link: link, node: node, metrics: m,
		log:    slog.Default().With("component", "worker-claims"),
		claims: map[string]*claimState{}, observed: map[string]*workerv1alpha1.ClaimStatus{},
		desired: map[string]bool{}}
}

// Observe records a status snapshot from Worker's Observe stream, which
// lists every claim of the caller, including those an earlier sidecar
// container of this pod made.
func (c *Claims) Observe(st *workerv1alpha1.ClaimStatus) {
	vpc := st.GetKey().GetVpc()
	c.mu.Lock()
	defer c.mu.Unlock()
	if st.GetReleased() {
		delete(c.observed, vpc)
	} else {
		c.observed[vpc] = st
	}
	if s := c.claims[vpc]; s != nil && sameKey(s.key, st.GetKey()) {
		if st.GetReleased() {
			// Worker removed the claim, for example when its lease
			// expired: the next pass requests it again.
			s.status, s.gen, s.spec = nil, 0, nil
			return
		}
		if st.GetGeneration() >= s.gen {
			s.status = st
		}
	}
}

// Sync makes the claims match the inputs and wires every claim's pod end.
func (c *Claims) Sync(ctx context.Context) error {
	atts, err := c.inputs.Attachments(ctx)
	if err != nil {
		return fmt.Errorf("read the proxy's attachments: %w", err)
	}
	backends, err := c.inputs.Backends(ctx)
	if err != nil {
		return fmt.Errorf("read backends: %w", err)
	}
	want := desiredClaims(c.node, atts, backends)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.synced = true
	c.desired = map[string]bool{}
	var errs []error
	for vpc, w := range want {
		c.desired[vpc] = true
		if err := c.ensureLocked(ctx, vpc, w); err != nil {
			errs = append(errs, err)
		}
	}
	for vpc, s := range c.claims {
		if _, ok := want[vpc]; !ok {
			if err := c.releaseLocked(ctx, s.key, s.gen); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(c.claims, vpc)
		}
	}
	// A claim an earlier container made that is no longer wanted.
	for vpc, st := range c.observed {
		if _, ok := want[vpc]; ok {
			continue
		}
		if _, ok := c.claims[vpc]; ok {
			continue
		}
		if err := c.releaseLocked(ctx, st.GetKey(), st.GetGeneration()); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(c.observed, vpc)
	}
	for vpc, s := range c.claims {
		c.wireLocked(vpc, s)
	}
	c.reportLocked()
	return errors.Join(errs...)
}

// wantedClaim is the claim desiredClaims computes for one VPC.
type wantedClaim struct {
	key      *workerv1alpha1.ClaimKey
	spec     *workerv1alpha1.ClaimSpec
	gateway  []netip.Addr
	backends map[string][]netip.Addr
}

// desiredClaims computes one claim per VPC that has both a proxy attachment
// and a backend. Worker refuses a claim without destinations, and a VPC
// without a proxy attachment has no gateway address to send from. When the
// proxy has several attachments in a VPC on this node, the one with the
// lowest UID is used.
func desiredClaims(node string, atts []ProxyAttachment, backends []BackendAttachment) map[string]wantedClaim {
	byVPC := map[string]ProxyAttachment{}
	for _, a := range atts {
		if prev, ok := byVPC[a.VPC]; !ok || a.UID < prev.UID {
			byVPC[a.VPC] = a
		}
	}
	out := map[string]wantedClaim{}
	for _, b := range backends {
		a, ok := byVPC[b.VPC]
		if !ok || b.UID == "" {
			continue
		}
		w, ok := out[b.VPC]
		if !ok {
			w = wantedClaim{key: &workerv1alpha1.ClaimKey{Node: node, Vpc: b.VPC, AttachmentUid: a.UID},
				gateway: slices.Clone(a.Addresses), backends: map[string][]netip.Addr{}}
		}
		if b.Address.IsValid() && !slices.Contains(w.backends[b.UID], b.Address) {
			w.backends[b.UID] = append(w.backends[b.UID], b.Address)
		}
		if _, ok := w.backends[b.UID]; !ok {
			w.backends[b.UID] = nil
		}
		out[b.VPC] = w
	}
	for vpc, w := range out {
		uids := make([]string, 0, len(w.backends))
		for uid := range w.backends {
			uids = append(uids, uid)
		}
		sort.Strings(uids)
		spec := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_SOCKET,
			Mode: workerv1alpha1.Mode_MODE_AUTO}
		for _, uid := range uids {
			spec.Destinations = append(spec.Destinations, &workerv1alpha1.Destination{
				Target: &workerv1alpha1.Destination_Attachment{Attachment: &workerv1alpha1.AttachmentRef{Uid: uid}}})
		}
		w.spec = spec
		out[vpc] = w
	}
	return out
}

// ensureLocked requests or updates vpc's claim to w.
func (c *Claims) ensureLocked(ctx context.Context, vpc string, w wantedClaim) error {
	s := c.claims[vpc]
	if s != nil && !sameKey(s.key, w.key) {
		// The proxy's attachment in the VPC changed: the old claim goes.
		if err := c.releaseLocked(ctx, s.key, s.gen); err != nil {
			return err
		}
		s = nil
	}
	if s == nil {
		s = &claimState{key: w.key}
		c.claims[vpc] = s
	}
	if s.gen == 0 {
		if st := c.observed[vpc]; st != nil && sameKey(st.GetKey(), w.key) {
			// A claim this container did not make: an earlier container of
			// this pod, or the proxy's previous pod, made it.
			s.gen, s.status = st.GetGeneration(), st
		}
	}
	s.gateway, s.backends = w.gateway, w.backends

	var st *workerv1alpha1.ClaimStatus
	var err error
	op := ""
	switch {
	case s.gen == 0:
		op = "request"
		st, err = c.client.Request(ctx, w.key, 1, w.spec)
		if err == nil {
			s.gen = 1
		}
	case s.spec == nil || !proto.Equal(s.spec, w.spec) || s.refused != "":
		// Also retried after a refusal, such as while the proxy's previous
		// pod still holds the claim: the same generation would be a no-op.
		op = "update"
		st, err = c.client.Update(ctx, w.key, s.gen+1, w.spec)
		if err == nil {
			s.gen++
		}
	default:
		// Re-assert the claim each pass. Worker answers a repeated
		// Request at the current generation and spec with the claim's
		// status and changes nothing, and recreates a claim it lost, as
		// after a lease expiry the Observe stream did not report.
		op = "reassert"
		st, err = c.client.Request(ctx, w.key, s.gen, w.spec)
	}
	c.metrics.operation(op, err)
	if err != nil {
		reason := workerclient.Reason(err)
		if reason == "" {
			reason = status.Code(err).String()
		}
		s.refused = reason
		switch reason {
		case workerv1alpha1.ReasonClaimNotFound:
			// Updated a claim Worker no longer has: request it anew.
			s.gen, s.spec, s.status = 0, nil, nil
		case workerv1alpha1.ReasonClaimExists, workerv1alpha1.ReasonGenerationConflict,
			workerv1alpha1.ReasonStaleGeneration:
			// The claim exists at a generation this container does not
			// know; Observe reports it.
			if ob := c.observed[vpc]; ob != nil && sameKey(ob.GetKey(), w.key) {
				s.gen = ob.GetGeneration()
			}
		}
		return fmt.Errorf("%s claim for VPC %s: %w", op, vpc, err)
	}
	if op != "reassert" {
		c.log.Info("Worker accepted the claim", "operation", op, "vpc", vpc, "attachment", w.key.GetAttachmentUid(),
			"generation", s.gen, "destinations", len(w.spec.GetDestinations()))
	}
	s.refused, s.spec = "", proto.Clone(w.spec).(*workerv1alpha1.ClaimSpec)
	if st != nil {
		s.status = st
	}
	return nil
}

// releaseLocked releases the claim key at gen. A claim Worker no longer has
// is released already.
func (c *Claims) releaseLocked(ctx context.Context, key *workerv1alpha1.ClaimKey, gen uint64) error {
	if gen == 0 {
		return nil
	}
	_, err := c.client.Release(ctx, key, gen)
	c.metrics.operation("release", err)
	if err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("release claim for VPC %s: %w", key.GetVpc(), err)
	}
	return nil
}

// ReleaseAll releases every claim, so the proxy's next pod can take the
// routed links over at once instead of after this pod is gone.
func (c *Claims) ReleaseAll(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	for vpc, s := range c.claims {
		if err := c.releaseLocked(ctx, s.key, s.gen); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(c.claims, vpc)
	}
	return errors.Join(errs...)
}

// wireLocked configures the pod end of s's routed link from its status.
func (c *Claims) wireLocked(vpc string, s *claimState) {
	s.wired, s.wireErr = false, nil
	st := s.status
	if st == nil || s.refused != "" {
		return
	}
	var podEnd string
	var hostLL netip.Addr
	for _, h := range st.GetHandoffInterfaces() {
		switch h.GetRole() {
		case workerv1alpha1.HandoffRolePod:
			podEnd = h.GetName()
		case workerv1alpha1.HandoffRoleHost:
			if a, err := netip.ParseAddr(h.GetLinkLocal()); err == nil {
				hostLL = a
			}
		}
	}
	if podEnd == "" || !hostLL.IsValid() {
		s.wireErr = errors.New("the routed link's ends are not reported yet")
		return
	}
	var local []netip.Addr
	for _, d := range st.GetDestinations() {
		uid := d.GetDestination().GetAttachment().GetUid()
		if d.GetResolved() && d.GetMode() == workerv1alpha1.Mode_MODE_LOCAL {
			local = append(local, s.backends[uid]...)
		}
	}
	slices.SortFunc(local, func(a, b netip.Addr) int { return a.Compare(b) })
	local = slices.Compact(local)
	if err := c.link.Configure(vpc, podEnd, s.gateway, hostLL, local); err != nil {
		s.wireErr = err
		switch {
		case !errors.Is(err, errVRFMissing):
			c.log.Error("configure the routed link's pod end", "vpc", vpc, "link", podEnd, "error", err)
		case !s.vrfMissingLogged:
			// The Store creates the VRF with the VPC's first route; say
			// once that the pod end waits for it.
			s.vrfMissingLogged = true
			c.log.Info("the routed link's pod end waits for the VPC's VRF", "vpc", vpc, "link", podEnd)
		}
		return
	}
	if s.podEnd != podEnd || s.hostLL != hostLL || !slices.Equal(s.localSet, local) {
		c.log.Info("configured the routed link's pod end", "vpc", vpc, "link", podEnd,
			"localBackends", len(local))
	}
	s.wired, s.podEnd, s.hostLL, s.localSet, s.vrfMissingLogged = true, podEnd, hostLL, local, false
}

// claimStateOf returns the worker_claims state and reason of s.
func claimStateOf(s *claimState) (string, string) {
	switch {
	case s.refused != "":
		return ClaimRefused, s.refused
	case s.status == nil || s.status.GetObservedGeneration() < s.gen:
		return ClaimPending, ""
	case !s.wired:
		reason := ReasonPodEndNotConfigured
		if errors.Is(s.wireErr, errVRFMissing) {
			reason = ReasonVRFMissing
		}
		return ClaimNotWired, reason
	}
	for _, cond := range s.status.GetConditions() {
		if cond.GetType() == workerv1alpha1.ConditionReady &&
			cond.GetStatus() != workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE {
			return ClaimPending, cond.GetReason()
		}
	}
	return ClaimReady, ""
}

// reportLocked publishes the claims' states and their destinations' modes.
func (c *Claims) reportLocked() {
	if c.metrics == nil {
		return
	}
	states := map[[2]string]int{}
	modes := map[string]int{}
	for _, s := range c.claims {
		st, reason := claimStateOf(s)
		states[[2]string{st, reason}]++
		if s.status == nil {
			continue
		}
		for _, d := range s.status.GetDestinations() {
			switch {
			case !d.GetResolved():
				modes["unresolved"]++
			case d.GetMode() == workerv1alpha1.Mode_MODE_LOCAL:
				modes["local"]++
			default:
				modes["fabric"]++
			}
		}
	}
	c.metrics.setClaims(states, modes)
}

// Ready returns nil once every VPC the proxy serves has a claim this pod
// holds, whose pod end is configured. It names the first VPC that is not.
func (c *Claims) Ready() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.synced {
		return errors.New("the Worker claims have not been synced yet")
	}
	var notReady []string
	for vpc := range c.desired {
		s := c.claims[vpc]
		if s == nil {
			notReady = append(notReady, vpc+": no claim")
			continue
		}
		if !s.wired || s.refused != "" {
			st, reason := claimStateOf(s)
			notReady = append(notReady, vpc+": "+st+" "+reason)
		}
	}
	if len(notReady) > 0 {
		sort.Strings(notReady)
		return fmt.Errorf("worker claims not ready: %s", strings.Join(notReady, ", "))
	}
	return nil
}

func sameKey(a, b *workerv1alpha1.ClaimKey) bool {
	return a.GetNode() == b.GetNode() && a.GetVpc() == b.GetVpc() && a.GetAttachmentUid() == b.GetAttachmentUid()
}
