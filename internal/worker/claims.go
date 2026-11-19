// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/refusal"
	"go.datum.net/galactic/internal/worker/sources"
	"go.datum.net/galactic/internal/worker/store"
)

type keyGen struct {
	key module.ClaimKey
	gen uint64
}

// vpcID matches a base62 VPC identifier.
var vpcID = regexp.MustCompile(`^[0-9A-Za-z]{1,16}$`)

func errShuttingDown() error {
	return refusal.New(codes.Unavailable, workerv1alpha1.ReasonShuttingDown, "Worker is shutting down", nil)
}

func malformed(msg string) error {
	return refusal.New(codes.InvalidArgument, workerv1alpha1.ReasonMalformedSpec, msg, nil)
}

// validateKey checks a claim key's form and node.
func (w *Worker) validateKey(key *workerv1alpha1.ClaimKey) (module.ClaimKey, error) {
	if key == nil || key.GetNode() == "" || key.GetAttachmentUid() == "" {
		return module.ClaimKey{}, malformed("key needs node, vpc and attachment_uid")
	}
	if key.GetNode() != w.cfg.Node {
		return module.ClaimKey{}, refusal.New(codes.InvalidArgument, workerv1alpha1.ReasonWrongNode,
			fmt.Sprintf("this Worker serves node %q, not %q", w.cfg.Node, key.GetNode()), nil)
	}
	if !vpcID.MatchString(key.GetVpc()) {
		return module.ClaimKey{}, malformed("vpc must be a base62 VPC identifier")
	}
	return module.ClaimKey{Node: key.GetNode(), VPC: key.GetVpc(), AttachmentUID: key.GetAttachmentUid()}, nil
}

// validateSpec checks a spec's form.
func validateSpec(gen uint64, spec *workerv1alpha1.ClaimSpec) error {
	if gen == 0 {
		return malformed("generation must be at least 1")
	}
	if spec == nil {
		return malformed("spec is required")
	}
	if workerv1alpha1.HandoffCapability(spec.GetHandoff()) == "" {
		return malformed("handoff must be tap, veth_pair, routed_link or socket")
	}
	switch spec.GetMode() {
	case workerv1alpha1.Mode_MODE_UNSPECIFIED, workerv1alpha1.Mode_MODE_AUTO,
		workerv1alpha1.Mode_MODE_LOCAL, workerv1alpha1.Mode_MODE_FABRIC:
	default:
		return malformed("mode must be auto, local or fabric")
	}
	if len(spec.GetDestinations()) == 0 {
		return malformed("at least one destination is required")
	}
	seen := map[string]bool{}
	for i, d := range spec.GetDestinations() {
		ok := false
		switch t := d.GetTarget().(type) {
		case *workerv1alpha1.Destination_Attachment:
			ok = t.Attachment.GetUid() != ""
		case *workerv1alpha1.Destination_Shard:
			if t.Shard.GetGroup() != "" || t.Shard.GetIndex() != 0 {
				return malformed(fmt.Sprintf("destination %d: a shard is named by name; group and index are not used", i))
			}
			ok = t.Shard.GetName() != ""
		case *workerv1alpha1.Destination_Backend:
			ok = t.Backend.GetNode() != ""
		}
		if !ok {
			return malformed(fmt.Sprintf("destination %d names no attachment, shard or backend", i))
		}
		id := module.DestinationID(d)
		if seen[id] {
			return malformed("destination " + id + " is listed twice")
		}
		seen[id] = true
	}
	return nil
}

// specHash is the hash of a spec's deterministic encoding.
func specHash(spec *workerv1alpha1.ClaimSpec) string {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(spec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func genMD(gen uint64) map[string]string {
	return map[string]string{workerv1alpha1.MetadataCurrentGeneration: strconv.FormatUint(gen, 10)}
}

// decide applies the generation rules of Request (update false) or Update
// to the existing claim c. It returns noop for a duplicate.
func decide(c *claim, caller string, gen uint64, hash string, update bool) (noop bool, err error) {
	if c != nil && c.rec.Owner != caller {
		if update {
			return false, refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonNotOwner,
				"another caller owns this claim", nil)
		}
		return false, refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonAttachmentClaimedByAnotherCaller,
			"another caller holds a claim on this attachment", nil)
	}
	if !update {
		switch {
		case c == nil:
			return false, nil
		case c.rec.Releasing && gen > c.rec.Generation:
			return false, nil
		case gen == c.rec.Generation && hash == c.rec.SpecHash && !c.rec.Releasing:
			return true, nil
		case gen == c.rec.Generation && !c.rec.Releasing:
			return false, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonGenerationConflict,
				"the same generation was accepted with a different spec", genMD(c.rec.Generation))
		default:
			return false, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimExists,
				"the claim exists; use Update, or Request a newer generation once it is released",
				genMD(c.rec.Generation))
		}
	}
	switch {
	case c == nil || c.rec.Releasing:
		return false, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimNotFound,
			"no such claim; use Request", nil)
	case gen < c.rec.Generation:
		return false, refusal.New(codes.Aborted, workerv1alpha1.ReasonStaleGeneration,
			"a newer generation is accepted", genMD(c.rec.Generation))
	case gen == c.rec.Generation && hash == c.rec.SpecHash:
		return true, nil
	case gen == c.rec.Generation:
		return false, refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonGenerationConflict,
			"the same generation was accepted with a different spec", genMD(c.rec.Generation))
	}
	return false, nil
}

// admit authorizes a claim against trusted sources and the caller's
// capabilities. It writes nothing.
func (w *Worker) admit(ctx context.Context, caller auth.Caller, k module.ClaimKey,
	spec *workerv1alpha1.ClaimSpec) error {
	notAuthorized := func(msg string) error {
		return refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized, msg, nil)
	}
	if hc := workerv1alpha1.HandoffCapability(spec.GetHandoff()); !caller.Allowed(hc) {
		return refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed,
			caller.ServiceAccount+" may not use "+hc, nil)
	}
	att, ok, err := w.d.Sources.Attachment(ctx, k.AttachmentUID)
	if err != nil {
		return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "trusted sources unavailable", nil)
	}
	if !ok {
		if err := w.admitShardAttachment(ctx, caller, k, spec); err != nil {
			return err
		}
		return w.admitDestinations(ctx, caller, k, spec)
	}
	switch {
	case att.VPC != k.VPC:
		return notAuthorized("the claim's attachment is not in the claimed VPC")
	case att.Node != w.cfg.Node:
		return notAuthorized("the claim's attachment is not on this node")
	case !att.Admitted:
		return notAuthorized("the claim's attachment is not admitted")
	}
	return w.admitDestinations(ctx, caller, k, spec)
}

// admitShardAttachment authorizes a claim whose attachment is an EgressShard
// rather than a VPCAttachment or EdgeAttachment: the NAT shard's claim on a
// VPC it serves. Such a claim is allowed only when the allowlist lets the
// caller name an EgressShard, the claim is a veth_pair whose every
// destination is a shard, the EgressShard runs on this node, and the VPC has
// an admitted VPCAttachment on this node. A uid that names no EgressShard
// either is refused as a missing attachment.
func (w *Worker) admitShardAttachment(ctx context.Context, caller auth.Caller, k module.ClaimKey,
	spec *workerv1alpha1.ClaimSpec) error {
	es, ok, err := w.d.Sources.EgressShardByUID(ctx, k.AttachmentUID)
	if err != nil {
		return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "trusted sources unavailable", nil)
	}
	if !ok {
		return refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized,
			"the claim's attachment does not exist", nil)
	}
	if !caller.EgressShardClaims {
		return refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed,
			caller.ServiceAccount+" may not name an EgressShard as a claim's attachment", nil)
	}
	if spec.GetHandoff() != workerv1alpha1.Handoff_HANDOFF_VETH_PAIR {
		return malformed("a claim whose attachment is an EgressShard must use the veth_pair handoff")
	}
	for i, d := range spec.GetDestinations() {
		if _, isShard := d.GetTarget().(*workerv1alpha1.Destination_Shard); !isShard {
			return malformed(fmt.Sprintf(
				"destination %d: a claim whose attachment is an EgressShard may name only shards", i))
		}
	}
	if msg, err := w.shardAuthority(ctx, k, es); err != nil {
		return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "trusted sources unavailable", nil)
	} else if msg != "" {
		return refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized, msg, nil)
	}
	return nil
}

// shardAuthority checks the trusted facts that let EgressShard es serve as
// claim k's attachment, and returns why not, or "" when they hold. Worker
// checks them at admission and again on every reconcile, so the claim is
// withdrawn when the shard moves or the VPC leaves the node.
func (w *Worker) shardAuthority(ctx context.Context, k module.ClaimKey, es sources.EgressShard) (string, error) {
	if es.Node != w.cfg.Node {
		return "the claim's EgressShard does not run on this node", nil
	}
	tenants, err := w.d.Sources.VPCAttachments(ctx, k.VPC, w.cfg.Node)
	if err != nil {
		return "", err
	}
	if len(tenants) == 0 {
		return "the claimed VPC has no admitted VPCAttachment on this node", nil
	}
	return "", nil
}

// admitDestinations authorizes a claim's destinations and the capabilities
// they need.
func (w *Worker) admitDestinations(ctx context.Context, caller auth.Caller, k module.ClaimKey,
	spec *workerv1alpha1.ClaimSpec) error {
	notAuthorized := func(msg string) error {
		return refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized, msg, nil)
	}
	own, err := w.d.Sources.Locator(ctx, w.cfg.Node)
	if err != nil {
		return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "trusted sources unavailable", nil)
	}
	needFabric := spec.GetMode() == workerv1alpha1.Mode_MODE_FABRIC
	for _, d := range spec.GetDestinations() {
		if sh, isShard := d.GetTarget().(*workerv1alpha1.Destination_Shard); isShard {
			es, found, err := w.d.Sources.EgressShard(ctx, sh.Shard.GetName())
			if err != nil {
				return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "trusted sources unavailable", nil)
			}
			if !found {
				return notAuthorized("destination shard " + sh.Shard.GetName() + " does not exist")
			}
			// A shard serves every VPC, so it has no VPC to compare. One on
			// another node is reached over the fabric.
			if spec.GetMode() != workerv1alpha1.Mode_MODE_LOCAL && es.Node != w.cfg.Node {
				needFabric = true
			}
			continue
		}
		t, ok := d.GetTarget().(*workerv1alpha1.Destination_Attachment)
		if !ok {
			continue
		}
		dst, ok, err := w.d.Sources.Attachment(ctx, t.Attachment.GetUid())
		if err != nil {
			return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "trusted sources unavailable", nil)
		}
		// Two VPCs may use the same addresses, so only VPC identity is
		// compared.
		if !ok {
			return notAuthorized("destination " + t.Attachment.GetUid() + " does not exist")
		}
		if dst.VPC != k.VPC {
			return notAuthorized("destination " + t.Attachment.GetUid() + " is in another VPC")
		}
		if spec.GetMode() == workerv1alpha1.Mode_MODE_LOCAL {
			continue
		}
		// A destination on another node needs fabric.srv6 even while its
		// locator is unknown, so the check cannot be skipped during
		// bring-up. Reconciliation checks the recorded capabilities again
		// when the destination resolves.
		if dst.Node != w.cfg.Node {
			needFabric = true
			continue
		}
		loc, err := w.d.Sources.Locator(ctx, dst.Node)
		if err != nil {
			return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "trusted sources unavailable", nil)
		}
		if own.IsValid() && loc.IsValid() && loc != own {
			needFabric = true
		}
	}
	if needFabric && !caller.Allowed(workerv1alpha1.CapabilityFabricSRv6) {
		return refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed,
			caller.ServiceAccount+" may not use "+workerv1alpha1.CapabilityFabricSRv6, nil)
	}
	return nil
}

// put runs Request (update false) or Update.
func (w *Worker) put(ctx context.Context, caller auth.Caller, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec, update bool) (*workerv1alpha1.ClaimStatus, error) {
	if w.shutting.Load() {
		return nil, w.refuse(errShuttingDown())
	}
	k, err := w.validateKey(key)
	if err != nil {
		return nil, w.refuse(err)
	}
	if err := validateSpec(gen, spec); err != nil {
		return nil, w.refuse(err)
	}
	hash := specHash(spec)

	lock := w.keyLock(k)
	lock.Lock()
	defer lock.Unlock()

	w.mu.Lock()
	c := w.claims[k]
	noop, err := decide(c, caller.ServiceAccount, gen, hash, update)
	heldBy := heldPod(c, caller)
	if err == nil && noop {
		st := proto.Clone(c.status).(*workerv1alpha1.ClaimStatus)
		rec := c.rec
		w.mu.Unlock()
		if err := w.followPod(k, rec, caller, heldBy); err != nil {
			return nil, err
		}
		return st, nil
	}
	if err == nil {
		if s, ok := w.scopes[k.VPC]; ok && s.resyncing {
			err = refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing,
				"the VPC scope is being reconciled after a restart", nil)
		}
	}
	if err == nil && c == nil && w.countOwned(caller.ServiceAccount) >= w.cfg.ClaimLimit {
		err = refusal.New(codes.ResourceExhausted, workerv1alpha1.ReasonClaimLimit,
			fmt.Sprintf("a caller may hold at most %d claims", w.cfg.ClaimLimit), nil)
	}
	w.mu.Unlock()
	if err == nil && heldBy != "" {
		err = w.heldByAnotherPod(heldBy)
	}
	if err != nil {
		return nil, w.refuse(err)
	}

	// Authorization reads trusted sources. It records nothing and takes no
	// ticket, so a refusal leaves the host and the store untouched.
	if err := w.admit(ctx, caller, k, spec); err != nil {
		w.log.Info("refused claim", "caller", caller.ServiceAccount, "vpc", k.VPC,
			"attachment", k.AttachmentUID, "generation", gen, "reason", refusal.Reason(err))
		return nil, w.refuse(err)
	}

	raw, err := protojson.Marshal(spec)
	if err != nil {
		return nil, refusal.New(codes.Internal, workerv1alpha1.ReasonMalformedSpec, "encode spec", nil)
	}
	rec := store.Record{Node: k.Node, VPC: k.VPC, AttachmentUID: k.AttachmentUID, Owner: caller.ServiceAccount,
		PodUID: caller.PodUID, Capabilities: caller.Capabilities, Generation: gen, SpecHash: hash, Spec: raw}
	if err := w.d.Store.Put(rec); err != nil {
		w.log.Error("record claim", "error", err)
		return nil, refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "cannot record the claim durably", nil)
	}

	w.mu.Lock()
	prev := w.claims[k]
	nc := &claim{rec: rec, spec: proto.Clone(spec).(*workerv1alpha1.ClaimSpec)}
	var observed uint64
	if prev != nil && !prev.rec.Releasing {
		observed = prev.status.GetObservedGeneration()
	}
	nc.status = w.initialStatus(nc, observed)
	if prev != nil && !prev.rec.Releasing {
		// Keep reporting what the previous generation achieved until the
		// new one is reconciled; observed_generation says which it is.
		nc.status.Conditions = prev.status.GetConditions()
		nc.status.Destinations = prev.status.GetDestinations()
	}
	w.claims[k] = nc
	w.scope(k.VPC)
	w.publish(nc)
	st := proto.Clone(nc.status).(*workerv1alpha1.ClaimStatus)
	w.mu.Unlock()
	updateClaimGauge(w)
	w.queue.Add(k.VPC)
	return st, nil
}

// heldPod returns the pod claim c's link serves when caller calls from
// another pod of its owner, and "" otherwise. A routed link serves one pod: a
// call from another pod moves the claim only once the pod it serves is gone.
func heldPod(c *claim, caller auth.Caller) string {
	if c == nil || c.rec.Releasing || !podBound(c.spec) || caller.PodUID == "" || c.rec.PodUID == "" ||
		c.rec.PodUID == caller.PodUID {
		return ""
	}
	return c.rec.PodUID
}

// followPod handles a duplicate Request from another pod of the owner of the
// claim at k: refused while heldBy, the pod the claim serves, runs, and moving
// the claim to the caller's pod once it is gone. With heldBy empty it does
// nothing.
func (w *Worker) followPod(k module.ClaimKey, rec store.Record, caller auth.Caller, heldBy string) error {
	if heldBy == "" {
		return nil
	}
	if err := w.heldByAnotherPod(heldBy); err != nil {
		return w.refuse(err)
	}
	// The owner calls from a new pod, as after its pod was replaced.
	// Nothing else changes, but the routed link follows the pod.
	if err := w.repod(k, rec, caller.PodUID); err != nil {
		w.log.Error("record the claim's new pod", "error", err)
		return refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "cannot record the claim durably", nil)
	}
	return nil
}

// podBound reports whether a claim's handoff serves one pod: a routed link,
// which the socket handoff also uses.
func podBound(spec *workerv1alpha1.ClaimSpec) bool {
	h := spec.GetHandoff()
	return h == workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK || h == workerv1alpha1.Handoff_HANDOFF_SOCKET
}

// heldByAnotherPod refuses a call from another pod while the claim's pod,
// podUID, still runs.
func (w *Worker) heldByAnotherPod(podUID string) error {
	if w.d.PodAlive == nil || !w.d.PodAlive(podUID) {
		return nil
	}
	return refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonClaimHeldByAnotherPod,
		"the claim's link serves another pod of its owner, which still runs", nil)
}

// repod records podUID as the pod the owner of the claim at k calls from,
// when the claim is still rec, and requeues its scope. The caller holds k's
// key lock.
func (w *Worker) repod(k module.ClaimKey, rec store.Record, podUID string) error {
	rec.PodUID = podUID
	if err := w.d.Store.Put(rec); err != nil {
		return err
	}
	w.mu.Lock()
	if c := w.claims[k]; c != nil && c.rec.Generation == rec.Generation && !c.rec.Releasing {
		c.rec.PodUID = podUID
	}
	w.mu.Unlock()
	w.queue.Add(k.VPC)
	return nil
}

// countOwned counts the live claims of caller. w.mu must be held.
func (w *Worker) countOwned(caller string) int {
	n := 0
	for _, c := range w.claims {
		if c.rec.Owner == caller {
			n++
		}
	}
	return n
}

// release runs Release.
func (w *Worker) release(caller auth.Caller, key *workerv1alpha1.ClaimKey, gen uint64) (
	*workerv1alpha1.ClaimStatus, error) {
	if w.shutting.Load() {
		return nil, w.refuse(errShuttingDown())
	}
	k, err := w.validateKey(key)
	if err != nil {
		return nil, w.refuse(err)
	}
	lock := w.keyLock(k)
	lock.Lock()
	defer lock.Unlock()

	w.mu.Lock()
	c := w.claims[k]
	switch {
	case c == nil:
		w.mu.Unlock()
		return nil, nil
	case c.rec.Owner != caller.ServiceAccount:
		err = refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonNotOwner, "another caller owns this claim", nil)
	case gen < c.rec.Generation:
		err = refusal.New(codes.Aborted, workerv1alpha1.ReasonStaleGeneration,
			"a newer generation is accepted", genMD(c.rec.Generation))
	case gen > c.rec.Generation:
		err = refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonGenerationConflict,
			"generation is newer than the claim's", genMD(c.rec.Generation))
	case c.rec.Releasing:
		st := proto.Clone(c.status).(*workerv1alpha1.ClaimStatus)
		w.mu.Unlock()
		return st, nil
	case w.scope(k.VPC).resyncing:
		err = refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing,
			"the VPC scope is being reconciled after a restart", nil)
	}
	w.mu.Unlock()
	if err != nil {
		return nil, w.refuse(err)
	}
	st, err := w.withdrawLocked(k, gen, store.WithdrawClaim, workerv1alpha1.ReasonReleased)
	if err != nil {
		return nil, err
	}
	w.fenceIfRepairing(k.VPC)
	return st, nil
}

// withdraw durably marks the claim at gen releasing and queues its scope.
// The record is deleted once read-back confirms no programmed state of the
// claim remains.
func (w *Worker) withdraw(k module.ClaimKey, gen uint64, scope, reason string) error {
	lock := w.keyLock(k)
	lock.Lock()
	defer lock.Unlock()
	_, err := w.withdrawLocked(k, gen, scope, reason)
	return err
}

// withdrawLocked is withdraw for a caller holding the key's lock.
func (w *Worker) withdrawLocked(k module.ClaimKey, gen uint64, scope, reason string) (
	*workerv1alpha1.ClaimStatus, error) {
	w.mu.Lock()
	c := w.claims[k]
	if c == nil || c.rec.Generation != gen || c.rec.Releasing {
		w.mu.Unlock()
		return nil, nil
	}
	rec := c.rec
	w.mu.Unlock()
	rec.Releasing, rec.Withdrawal, rec.WithdrawReason = true, scope, reason
	if err := w.d.Store.Put(rec); err != nil {
		w.log.Error("record withdrawal", "error", err)
		return nil, refusal.New(codes.Unavailable, workerv1alpha1.ReasonResyncing, "cannot record the release durably", nil)
	}
	w.mu.Lock()
	if cur := w.claims[k]; cur == c {
		c.rec = rec
		w.setWithdrawing(c)
		w.publish(c)
	}
	st := proto.Clone(c.status).(*workerv1alpha1.ClaimStatus)
	w.mu.Unlock()
	w.log.Info("withdrawing claim", "owner", rec.Owner, "vpc", k.VPC, "attachment", k.AttachmentUID,
		"generation", gen, "scope", scope, "reason", reason)
	w.queue.Add(k.VPC)
	return st, nil
}

// fenceIfRepairing fences a scope whose last commit failed, so a repair that
// holds a ticket while preparing its snapshot cannot commit state that still
// includes a released claim. It takes the scope over again in one step, which
// advances the generation and requires a snapshot, so the next reconcile
// commits one from current desired state.
func (w *Worker) fenceIfRepairing(vpc string) {
	w.mu.Lock()
	s := w.scopes[vpc]
	repairing := s != nil && s.repair
	w.mu.Unlock()
	if !repairing {
		return
	}
	if _, err := w.d.Fence.Takeover(module.Scope{VPC: vpc}.Name(), w.owner, workerOrUnowned); err != nil {
		w.log.Error("fence scope for release", "vpc", vpc, "error", err)
	}
}

// refuse counts a refusal and returns it.
func (w *Worker) refuse(err error) error {
	countRefusal(refusal.Reason(err))
	return err
}
