// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"go.miloapis.com/instrumentation/labels"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/diag"
	"go.datum.net/galactic/internal/worker/module"
)

// Diagnostics intervals.
const (
	// DefaultStatusInterval is how often Worker refreshes its gauges and,
	// when a status changed, its status snapshot.
	DefaultStatusInterval = 5 * time.Second
	// statusRewrite is how often the snapshot is written although no claim
	// status changed, so capability and fence changes reach it.
	statusRewrite = time.Minute
)

// Diagnostics returns Worker's operator view of the node.
func (w *Worker) Diagnostics() diag.Snapshot {
	s := diag.Snapshot{Time: w.d.Now().UTC(), Node: w.cfg.Node, Owner: w.owner}
	for _, c := range w.d.Modules.Capabilities() {
		s.Capabilities = append(s.Capabilities, diag.Capability{Name: c.Name, Available: c.Available,
			Reason: c.Reason, Message: c.Message})
	}
	byVPC := map[string]*diag.Scope{}
	scope := func(vpc string) *diag.Scope {
		if sc, ok := byVPC[vpc]; ok {
			return sc
		}
		sc := &diag.Scope{VPC: vpc}
		byVPC[vpc] = sc
		return sc
	}
	w.mu.Lock()
	for vpc, st := range w.scopes {
		sc := scope(vpc)
		sc.Resyncing, sc.Repair, sc.LastDrift = st.resyncing, st.repair, st.lastDrift
	}
	for _, c := range w.claims {
		sc := scope(c.rec.VPC)
		sc.Claims = append(sc.Claims, claimDiag(c))
	}
	w.mu.Unlock()
	for _, sc := range byVPC {
		// Peek, not Read: diagnostics never wait on, or delay, a writer.
		if rec, err := w.d.Fence.Peek(module.Scope{VPC: sc.VPC}.Name()); err == nil {
			sc.Fence = rec
		}
		slices.SortFunc(sc.Claims, func(a, b diag.Claim) int { return strings.Compare(a.Key, b.Key) })
		s.Scopes = append(s.Scopes, *sc)
	}
	slices.SortFunc(s.Scopes, func(a, b diag.Scope) int { return strings.Compare(a.VPC, b.VPC) })
	return s
}

// claimDiag is c's operator view. w.mu must be held.
func claimDiag(c *claim) diag.Claim {
	st := c.status
	d := diag.Claim{Key: c.key().String(), Owner: c.rec.Owner, Handoff: handoffName(c.spec.GetHandoff()),
		Generation: c.rec.Generation, ObservedGeneration: st.GetObservedGeneration()}
	for _, cd := range st.GetConditions() {
		d.Conditions = append(d.Conditions, diag.Condition{Type: cd.GetType(),
			Status: strings.TrimPrefix(cd.GetStatus().String(), "CONDITION_STATUS_"), Reason: cd.GetReason(),
			Message: cd.GetMessage()})
	}
	if ws := st.GetWithdrawalScope(); ws != workerv1alpha1.WithdrawalScope_WITHDRAWAL_SCOPE_UNSPECIFIED {
		d.Withdrawal = strings.ToLower(strings.TrimPrefix(ws.String(), "WITHDRAWAL_SCOPE_"))
	}
	for _, ds := range st.GetDestinations() {
		dd := diag.Destination{ID: module.DestinationID(ds.GetDestination()), Resolved: ds.GetResolved(),
			Programmed: ds.GetProgrammed(), Ready: ds.GetReady(), ForwardReady: ds.GetForwardReady(),
			ReturnReady: ds.GetReturnReady(), Reason: ds.GetReason(), Message: ds.GetMessage()}
		if ds.GetMode() != workerv1alpha1.Mode_MODE_UNSPECIFIED {
			dd.Locality = modeName(ds.GetMode())
			dd.Capability = module.RequiredCapability(c.spec.GetHandoff(), ds.GetMode())
		}
		d.Destinations = append(d.Destinations, dd)
	}
	for _, h := range st.GetHandoffInterfaces() {
		d.HandoffInterfaces = append(d.HandoffInterfaces, h.GetRole()+"="+h.GetName())
	}
	return d
}

func handoffName(h workerv1alpha1.Handoff) string {
	return strings.ToLower(strings.TrimPrefix(h.String(), "HANDOFF_"))
}

// runDiagnostics refreshes the gauges every StatusInterval and writes the
// status snapshot when a claim's status changed, or every statusRewrite,
// until ctx is done.
func (w *Worker) runDiagnostics(ctx context.Context) {
	var lastWrite time.Time
	refresh := func() {
		// Take the flag before building the snapshot, so a status published
		// while it is built marks the next pass dirty again.
		dirty := w.statusDirty.Swap(false)
		s := w.Diagnostics()
		updateDiagnosticGauges(s)
		if w.cfg.StatusFile == "" {
			return
		}
		if !dirty && time.Since(lastWrite) < statusRewrite {
			return
		}
		if err := diag.Write(w.cfg.StatusFile, s); err != nil {
			w.statusDirty.Store(true)
			w.log.Warn("write the status snapshot", "path", w.cfg.StatusFile, "error", err)
			return
		}
		lastWrite = time.Now()
	}
	refresh()
	w.every(ctx, w.cfg.StatusInterval, refresh)
}

// logReadyChange logs a claim whose Ready condition changed status or
// reason, so the log records each failure and its recovery. w.mu must be
// held; before is the condition as it was.
func (w *Worker) logReadyChange(c *claim, before *workerv1alpha1.Condition) {
	after := readyCondition(c.status)
	if after == nil || (before != nil && before.GetStatus() == after.GetStatus() &&
		before.GetReason() == after.GetReason()) {
		return
	}
	attrs := make([]any, 0, 10)
	attrs = append(attrs, "claim", c.key().String(), "caller", c.rec.Owner, "generation", c.rec.Generation,
		labels.Reason, after.GetReason())
	if after.GetStatus() == condTrue {
		w.log.Info("claim is ready", attrs...)
		return
	}
	w.log.Info("claim is not ready", append(attrs, "message", after.GetMessage())...)
}

// desiredDigest identifies a scope's desired state, as the modules are
// handed it.
func desiredDigest(desired map[workerv1alpha1.Mode][]module.Claim) string {
	b, err := json.Marshal(desired)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// drift is one module's repair of host state that changed under Worker.
type drift struct {
	module, detail string
}

// checkDrift returns the digest of desired and the drift the planned changes
// repair: those a module reports as drift, planned against the desired state
// the scope last committed, in a scope that does not require a snapshot.
// Worker records them once the commit succeeds.
func (w *Worker) checkDrift(vpc string, desired map[workerv1alpha1.Mode][]module.Claim, resync bool,
	mods []module.Module, changes []module.Change) (string, []drift) {
	digest := desiredDigest(desired)
	w.mu.Lock()
	unchanged := digest != "" && w.scope(vpc).committed == digest
	w.mu.Unlock()
	if !unchanged || resync {
		return digest, nil
	}
	var out []drift
	for i, m := range mods {
		d, ok := changes[i].(module.DriftDescriber)
		if !ok || changes[i].Empty() {
			continue
		}
		if detail, ok := d.Drift(); ok {
			out = append(out, drift{module: m.Name(), detail: detail})
		}
	}
	return digest, out
}

// noteDrift records drift a commit repaired.
func (w *Worker) noteDrift(vpc string, drifts []drift) {
	for _, d := range drifts {
		detail, name := d.detail, d.module
		driftRepairsTotal.WithLabelValues(name).Inc()
		w.log.Info("repaired host state that changed under Worker", "vpc", vpc, "module", name,
			"detail", detail)
		w.mu.Lock()
		w.scope(vpc).lastDrift = &diag.Drift{Time: w.d.Now().UTC(), Module: name, Detail: detail}
		w.mu.Unlock()
		w.statusDirty.Store(true)
	}
}

// cloneCondition copies c, which may be nil, since setCond can change a
// condition in place.
func cloneCondition(c *workerv1alpha1.Condition) *workerv1alpha1.Condition {
	if c == nil {
		return nil
	}
	return proto.Clone(c).(*workerv1alpha1.Condition)
}

func readyCondition(st *workerv1alpha1.ClaimStatus) *workerv1alpha1.Condition {
	for _, c := range st.GetConditions() {
		if c.GetType() == workerv1alpha1.ConditionReady {
			return c
		}
	}
	return nil
}
