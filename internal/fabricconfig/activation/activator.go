// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package activation applies FabricRouterRevisions to a node's FRR with
// replay protection, a durable journal and a machine-bound checkpoint. It
// stages and validates a candidate without writing FRR, applies an
// activation in journaled stages, recovers to an authorized target when an
// activation fails, resumes correctly after a crash at any stage, and
// restores the last committed configuration at boot without the API while
// that configuration's boot authorization lasts.
//
// It has no Kubernetes I/O of its own: the agent hands it revisions and
// activations read from the API, and reports what it returns.
package activation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
	"go.datum.net/galactic/internal/fabric/routing/revision"
)

// FRR is the agent's view of the node's FRR daemons.
type FRR interface {
	// Check validates a configuration file without applying it.
	Check(ctx context.Context, path string) error
	// Changes lists the lines a reload to path would add and remove.
	Changes(ctx context.Context, path string) (added, removed []string, err error)
	// Reload applies path.
	Reload(ctx context.Context, path string) error
	// Running returns the running configuration.
	Running(ctx context.Context) (string, error)
}

// Locker serializes every writer of FRR on the node: reloads, neighbor
// resets, recovery and maintenance.
type Locker interface {
	Lock(ctx context.Context) (unlock func(), err error)
}

// Health judges an applied configuration: required static routes in the
// FIB and required sessions Established. A nil error means healthy.
type Health func(ctx context.Context, rendered string) error

// Errors an activation can be refused with.
var (
	// ErrStale is an epoch below the journal's mark for the deployment,
	// or an equal epoch for a different activation.
	ErrStale = errors.New("stale activation")
	// ErrFailedEpoch is a retry of an epoch that already failed; a retry
	// needs a new epoch.
	ErrFailedEpoch = errors.New("epoch already failed")
	// ErrRecoveryConflict is a deployment UID the journal is not bound to,
	// or a corrupt journal; nothing is applied until an operator rebinds.
	ErrRecoveryConflict = errors.New("recovery conflict")
	// ErrDigestMismatch is a revision that is not the one promoted.
	ErrDigestMismatch = errors.New("revision does not match the activation")
	// ErrNoEligibleRecovery means a failed activation has no authorized
	// configuration to return to.
	ErrNoEligibleRecovery = errors.New("no eligible recovery target")
)

// Outcome is where an activation ended.
type Outcome string

const (
	// OutcomeCommitted means applied, observed healthy and checkpointed.
	OutcomeCommitted Outcome = "Committed"
	// OutcomeRecovered means the activation failed and the recovery target
	// was restored.
	OutcomeRecovered Outcome = "Recovered"
	// OutcomeDegraded means the activation failed and could not be
	// recovered; the agent pauses.
	OutcomeDegraded Outcome = "Degraded"
)

// Result is one activation's end state.
type Result struct {
	Outcome Outcome
	// Detail explains a failure.
	Detail string
}

// Staged is a validated, unapplied candidate.
type Staged struct {
	Class          networkv1alpha1.FabricChangeClass
	Added, Removed []string
	Rendered       string
}

// Activator runs activations for one node. It has a single caller: the
// agent holding the node's FRR writer lock runs one activation at a time.
type Activator struct {
	// Dir is the state directory: journal, identity and checkpoint.
	Dir string
	FRR FRR
	// Lock serializes FRR writers; nil means no other writer exists.
	Lock   Locker
	Health Health
	// Now reads the clock; nil is time.Now.
	Now func() time.Time
	// Fault, when set, is called at each crash boundary; an error stops the
	// activation there, as a crash would. Tests only.
	Fault func(point string) error

	journal *Journal
}

// Crash boundaries a Fault can stop at.
const (
	FaultAfterAccepted  = "after-accepted"
	FaultAfterReload    = "after-reload"
	FaultAfterApplied   = "after-applied"
	FaultAfterCommitted = "after-committed"
	FaultDuringRecovery = "during-recovery"
	FaultAfterRecovery  = "after-recovery-checkpoint"
)

func (a *Activator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Activator) fault(point string) error {
	if a.Fault == nil {
		return nil
	}
	return a.Fault(point)
}

// Open reads the journal. A corrupt journal returns ErrRecoveryConflict.
func (a *Activator) Open() error {
	j, err := OpenJournal(filepath.Join(a.Dir, "journal.log"), a.now)
	if errors.Is(err, ErrCorrupt) {
		return fmt.Errorf("%w: %w", ErrRecoveryConflict, err)
	}
	if err != nil {
		return err
	}
	a.journal = j
	return nil
}

// Journal exposes the journal for status reporting.
func (a *Activator) Journal() *Journal { return a.journal }

// render verifies a revision and writes its configuration to a file mode
// 0600 in the state directory.
func (a *Activator) render(rev *networkv1alpha1.FabricRouterRevision, name string) (string, string, error) {
	res, err := revision.Verify(rev)
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(a.Dir, name)
	if err := writeAtomic(path, []byte(res.Config)); err != nil {
		return "", "", err
	}
	return res.Config, path, nil
}

// Stage validates a candidate and reports what applying it would change.
// It never writes FRR.
func (a *Activator) Stage(ctx context.Context, rev *networkv1alpha1.FabricRouterRevision) (Staged, error) {
	rendered, path, err := a.render(rev, "candidate.conf")
	if err != nil {
		return Staged{}, err
	}
	if err := a.FRR.Check(ctx, path); err != nil {
		return Staged{}, fmt.Errorf("candidate %s fails validation: %w", rev.Name, err)
	}
	added, removed, err := a.FRR.Changes(ctx, path)
	if err != nil {
		return Staged{}, err
	}
	added, removed = withoutHostname(added), withoutHostname(removed)
	return Staged{Class: Classify(added, removed), Added: added, Removed: removed, Rendered: rendered}, nil
}

// withoutHostname drops hostname changes. FRR keeps running under the
// host's name whatever its configuration's hostname says, so a reload
// reports the hostname as changed every time and never changes it.
func withoutHostname(changes []string) []string {
	return slices.DeleteFunc(changes, func(c string) bool {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(c), "no "))
		return len(f) > 0 && f[0] == "hostname"
	})
}

// Classify sorts a reload's changes by what they disturb. A change is a
// line, or a line under its contexts, "<context> :: ... :: <line>".
func Classify(added, removed []string) networkv1alpha1.FabricChangeClass {
	if len(added) == 0 && len(removed) == 0 {
		return networkv1alpha1.FabricChangeNone
	}
	class := networkv1alpha1.FabricChangeNonDisruptive
	for _, change := range append(append([]string(nil), added...), removed...) {
		line := change
		if i := strings.LastIndex(change, " :: "); i >= 0 {
			line = change[i+len(" :: "):]
		}
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "no "))
		switch {
		case len(f) >= 2 && f[0] == "frr" && f[1] == "defaults":
			return networkv1alpha1.FabricChangeRestartRequired
		case len(f) >= 3 && f[0] == "neighbor" && sessionVerb(f[2]):
			class = networkv1alpha1.FabricChangeSessionReset
		case len(f) >= 3 && f[0] == "router" && f[1] == "bgp":
			class = networkv1alpha1.FabricChangeSessionReset
		}
	}
	return class
}

// sessionVerb is a neighbor setting whose change resets the session.
func sessionVerb(verb string) bool {
	switch verb {
	case "remote-as", "peer-group", "update-source", "ebgp-multihop", "password", "port", "timers":
		return true
	}
	return false
}

// Settings are the deployment's activation settings for one epoch.
type Settings struct {
	// ApplyTimeout bounds one reload; zero is unbounded.
	ApplyTimeout time.Duration
	// Stabilization is how long Health must keep passing before commit.
	Stabilization time.Duration
	// BootLifetime is how long a commit authorizes offline boot.
	BootLifetime time.Duration
}

// Request is one activation and what it may fall back to.
type Request struct {
	Activation Activation
	Revision   *networkv1alpha1.FabricRouterRevision
	Settings   Settings
	Recovery   Recovery
	// RecoveryRevision is the content of Recovery.TargetRevision, when the
	// deployment names one.
	RecoveryRevision *networkv1alpha1.FabricRouterRevision
	// Credentials maps each Secret name the recovery target's peers use to
	// that Secret's current UID; a name missing here is not restorable.
	Credentials map[string]string
	// RequiresAPI marks a revision with credentials that cannot be
	// restored offline.
	RequiresAPI bool
}

// Admit applies the replay rules: a new epoch above the deployment's mark,
// or a redelivery of the exact activation already accepted.
func (a *Activator) Admit(act Activation) (redelivery bool, err error) {
	if err := a.checkIdentity(act); err != nil {
		return false, err
	}
	if bound := a.journal.BoundDeployment(); bound != "" && bound != act.DeploymentUID {
		return false, fmt.Errorf("%w: journal bound to deployment %s, asked for %s",
			ErrRecoveryConflict, bound, act.DeploymentUID)
	}
	high, ok := a.journal.HighWater(act.DeploymentUID)
	switch {
	case !ok || act.Epoch > high:
		return false, nil
	case act.Epoch < high:
		return false, fmt.Errorf("%w: epoch %d below accepted %d", ErrStale, act.Epoch, high)
	}
	rec, _ := a.journal.LastForEpoch(act.DeploymentUID, act.Epoch)
	if rec.Activation != act {
		return false, fmt.Errorf("%w: epoch %d was accepted for %s", ErrStale, act.Epoch, rec.describe())
	}
	if a.journal.Failed(act.DeploymentUID, act.Epoch) {
		return false, fmt.Errorf("%w: epoch %d", ErrFailedEpoch, act.Epoch)
	}
	return true, nil
}

// checkIdentity refuses an activation with an empty identity field, or for
// another Node or cluster than the state directory is bound to.
func (a *Activator) checkIdentity(act Activation) error {
	if act.DeploymentUID == "" || act.NodeUID == "" || act.ClusterID == "" {
		return fmt.Errorf("%w: activation names no deployment, Node or cluster", ErrIdentityMismatch)
	}
	id, err := readIdentity(a.Dir)
	if err != nil {
		return err
	}
	if act.NodeUID != id.NodeUID || act.ClusterID != id.ClusterID {
		return fmt.Errorf("%w: activation for Node %s in cluster %s, bound to Node %s in cluster %s",
			ErrIdentityMismatch, act.NodeUID, act.ClusterID, id.NodeUID, id.ClusterID)
	}
	return nil
}

// checkRevision refuses a revision that is not the one act promotes.
func checkRevision(req Request) error {
	act := req.Activation
	if req.Revision == nil || req.Revision.Spec.ActivationDependencyDigest != act.DependencyHash ||
		req.Revision.Name != act.Revision {
		return fmt.Errorf("%w: %s", ErrDigestMismatch, act.Revision)
	}
	return nil
}

// Activate runs one activation through its journaled stages.
func (a *Activator) Activate(ctx context.Context, req Request) (Result, error) {
	act := req.Activation
	if err := checkRevision(req); err != nil {
		return Result{}, err
	}
	redelivery, err := a.Admit(act)
	if errors.Is(err, ErrFailedEpoch) && a.journal.NeedsRecovery(act.DeploymentUID, act.Epoch) {
		// The epoch failed and a crash stopped its recovery: finish it.
		return a.Resume(ctx, req)
	}
	if err != nil {
		return Result{}, err
	}
	if redelivery {
		return a.Resume(ctx, req)
	}
	rendered, path, err := a.render(req.Revision, "active.conf")
	if err != nil {
		return Result{}, err
	}
	if err := a.FRR.Check(ctx, path); err != nil {
		return Result{}, fmt.Errorf("revision %s fails validation: %w", act.Revision, err)
	}
	previous := ""
	if cp, err := ReadCheckpoint(a.Dir); err == nil {
		previous = cp.Activation.Revision
	}
	rec := Record{Type: RecordAccepted, Activation: act, PreviousGood: previous, Recovery: &req.Recovery}
	if _, err := a.journal.Append(rec); err != nil {
		return Result{}, err
	}
	if err := a.fault(FaultAfterAccepted); err != nil {
		return Result{}, err
	}
	return a.apply(ctx, req, rendered, path)
}

// apply reloads, observes and commits; a failure recovers.
func (a *Activator) apply(ctx context.Context, req Request, rendered, path string) (Result, error) {
	act := req.Activation
	if err := a.reload(ctx, path, req.Settings.ApplyTimeout); err != nil {
		if ctx.Err() != nil {
			// Shutdown, not a failure: resume decides from FRR's state.
			return Result{}, err
		}
		if _, jerr := a.journal.Append(Record{Type: RecordApplyFailed, Activation: act,
			Detail: err.Error()}); jerr != nil {
			return Result{}, jerr
		}
		return a.recover(ctx, req, "reload: "+err.Error())
	}
	if err := a.fault(FaultAfterReload); err != nil {
		return Result{}, err
	}
	if _, err := a.journal.Append(Record{Type: RecordApplied, Activation: act}); err != nil {
		return Result{}, err
	}
	if err := a.fault(FaultAfterApplied); err != nil {
		return Result{}, err
	}
	return a.observeAndCommit(ctx, req, rendered)
}

func (a *Activator) reload(ctx context.Context, path string, timeout time.Duration) error {
	if a.Lock != nil {
		unlock, err := a.Lock.Lock(ctx)
		if err != nil {
			return err
		}
		defer unlock()
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return a.FRR.Reload(ctx, path)
}

// observeAndCommit checks the running configuration and health through the
// stabilization window, then journals the commit and writes the checkpoint.
func (a *Activator) observeAndCommit(ctx context.Context, req Request, rendered string) (Result, error) {
	act := req.Activation
	if diff, err := a.runningDiff(ctx, rendered); err != nil {
		return Result{}, err
	} else if len(diff) > 0 {
		return a.fail(ctx, req, "running configuration differs: "+strings.Join(head(diff, 5), "; "))
	}
	deadline := a.now().Add(req.Settings.Stabilization)
	for {
		if a.Health != nil {
			if err := a.Health(ctx, rendered); err != nil {
				if ctx.Err() != nil {
					return Result{}, err
				}
				return a.fail(ctx, req, "unhealthy: "+err.Error())
			}
		}
		if !a.now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(minDuration(time.Second, deadline.Sub(a.now()))):
		}
	}
	if _, err := a.journal.Append(Record{Type: RecordCommitted, Activation: act}); err != nil {
		return Result{}, err
	}
	if err := a.fault(FaultAfterCommitted); err != nil {
		return Result{}, err
	}
	if err := a.checkpoint(req, act, req.Revision, rendered); err != nil {
		return Result{}, err
	}
	return Result{Outcome: OutcomeCommitted}, nil
}

// checkpoint records rev, running as act, as what boot may restore.
func (a *Activator) checkpoint(req Request, act Activation, rev *networkv1alpha1.FabricRouterRevision,
	rendered string) error {
	sum := sha256.Sum256([]byte(rendered))
	id, err := readIdentity(a.Dir)
	if err != nil {
		return err
	}
	names := credentialNames(rev)
	uids := make([]string, 0, len(names))
	requiresAPI := req.RequiresAPI
	for _, name := range names {
		uid, ok := req.Credentials[name]
		if !ok {
			// Revocation by UID could never match it offline.
			requiresAPI = true
		}
		uids = append(uids, uid)
	}
	return WriteCheckpoint(a.Dir, Checkpoint{
		Nonce:      id.Nonce,
		Activation: act, Config: rendered, ConfigDigest: hex.EncodeToString(sum[:]), Recovery: &req.Recovery,
		Originates: originations(rev), CredentialUIDs: uids,
		SemanticsVersion: compile.SemanticsVersion, FRRVersion: compile.FRRVersion,
		BootAuthorizedUntil: a.now().Add(req.Settings.BootLifetime).UTC(), RequiresAPI: requiresAPI,
	})
}

// fail journals an observed failure of an applied activation and recovers.
func (a *Activator) fail(ctx context.Context, req Request, detail string) (Result, error) {
	if _, err := a.journal.Append(Record{Type: RecordApplyFailed, Activation: req.Activation,
		Detail: detail}); err != nil {
		return Result{}, err
	}
	return a.recover(ctx, req, detail)
}

// recover restores the recorded recovery target, if it is eligible.
func (a *Activator) recover(ctx context.Context, req Request, detail string) (Result, error) {
	if err := Eligible(req.Recovery, req.RecoveryRevision, req.Credentials); err != nil {
		return Result{Outcome: OutcomeDegraded, Detail: detail + "; " + err.Error()}, nil
	}
	if err := a.fault(FaultDuringRecovery); err != nil {
		return Result{}, err
	}
	rendered, path, err := a.render(req.RecoveryRevision, "recovery.conf")
	if err != nil {
		return Result{Outcome: OutcomeDegraded, Detail: detail + "; recovery target: " + err.Error()}, nil
	}
	if err := a.reload(ctx, path, req.Settings.ApplyTimeout); err != nil {
		if ctx.Err() != nil {
			return Result{}, err
		}
		return Result{Outcome: OutcomeDegraded, Detail: detail + "; recovery reload: " + err.Error()}, nil
	}
	// The checkpoint goes first: a crash before the Recovered record
	// resumes into this recovery again, which rewrites it.
	restored := req.Activation
	restored.Revision, restored.DependencyHash = req.RecoveryRevision.Name, req.Recovery.TargetDigest
	if err := a.checkpoint(req, restored, req.RecoveryRevision, rendered); err != nil {
		return Result{}, err
	}
	if err := a.fault(FaultAfterRecovery); err != nil {
		return Result{}, err
	}
	if _, err := a.journal.Append(Record{
		Type: RecordRecovered, Activation: req.Activation, Detail: "restored " + req.RecoveryRevision.Name,
	}); err != nil {
		return Result{}, err
	}
	return Result{Outcome: OutcomeRecovered, Detail: detail}, nil
}

// Eligible reports why a recovery target may not be restored: none named,
// the router retired, content other than the authorized digest, a revoked
// prefix it originates, or a credential it uses that is revoked or cannot
// be resolved. credentials maps Secret names to their current UIDs.
func Eligible(rec Recovery, rev *networkv1alpha1.FabricRouterRevision, credentials map[string]string) error {
	switch {
	case rec.Retired:
		return fmt.Errorf("%w: router retired", ErrNoEligibleRecovery)
	case rec.TargetRevision == "" || rev == nil:
		return ErrNoEligibleRecovery
	case rev.Name != rec.TargetRevision:
		return fmt.Errorf("%w: have %s, authorized %s", ErrNoEligibleRecovery, rev.Name, rec.TargetRevision)
	case rev.Spec.ActivationDependencyDigest != rec.TargetDigest:
		return fmt.Errorf("%w: %s has digest %s, authorized %s",
			ErrNoEligibleRecovery, rev.Name, rev.Spec.ActivationDependencyDigest, rec.TargetDigest)
	}
	if p := revokedOrigination(rec, originations(rev)); p != "" {
		return fmt.Errorf("%w: %s originates revoked %s", ErrNoEligibleRecovery, rev.Name, p)
	}
	for _, name := range credentialNames(rev) {
		uid, ok := credentials[name]
		switch {
		case !ok:
			return fmt.Errorf("%w: %s uses credential %s, which cannot be resolved", ErrNoEligibleRecovery,
				rev.Name, name)
		case slices.Contains(rec.RevokedCredentials, uid):
			return fmt.Errorf("%w: %s uses revoked credential %s", ErrNoEligibleRecovery, rev.Name, name)
		}
	}
	if _, err := revision.Verify(rev); err != nil {
		return fmt.Errorf("%w: %w", ErrNoEligibleRecovery, err)
	}
	return nil
}

// StartAllowed reports why a node may not start FRR from rev, the active
// revision of act read from the API, when no checkpoint may be restored:
// the state directory belongs to another Node or cluster, the journal is
// bound to another deployment, the epoch is behind the journal or already
// failed, or the newest journaled recovery or asked, the deployment's
// recovery authorization, retired the router or revokes a prefix rev
// originates or a credential it uses. credentials maps the Secret names rev
// uses to their current UIDs; with a journaled recovery, a credential
// missing from it is refused too.
func (a *Activator) StartAllowed(act Activation, rev *networkv1alpha1.FabricRouterRevision,
	credentials map[string]string, asked Recovery) error {
	if a.journal == nil {
		return fmt.Errorf("%w: the journal is unreadable", ErrRecoveryConflict)
	}
	if err := checkRevision(Request{Activation: act, Revision: rev}); err != nil {
		return err
	}
	if err := a.checkIdentity(act); err != nil {
		return err
	}
	if bound := a.journal.BoundDeployment(); bound != "" && bound != act.DeploymentUID {
		return fmt.Errorf("%w: journal bound to deployment %s", ErrRecoveryConflict, bound)
	}
	if high, ok := a.journal.HighWater(act.DeploymentUID); ok && act.Epoch < high {
		return fmt.Errorf("%w: epoch %d below accepted %d", ErrStale, act.Epoch, high)
	}
	if a.journal.Failed(act.DeploymentUID, act.Epoch) {
		return fmt.Errorf("%w: epoch %d", ErrFailedEpoch, act.Epoch)
	}
	if rec, ok := a.journal.LastForEpoch(act.DeploymentUID, act.Epoch); ok && rec.Activation != act {
		return fmt.Errorf("%w: epoch %d was accepted for %s", ErrStale, act.Epoch, rec.describe())
	}
	journaled, ok := a.journal.LatestRecovery()
	rec := mergeRecovery(journaled, asked)
	if rec.Retired {
		return fmt.Errorf("%w: the router is retired", ErrNoEligibleRecovery)
	}
	if p := revokedOrigination(rec, originations(rev)); p != "" {
		return fmt.Errorf("%s originates revoked %s", rev.Name, p)
	}
	for _, name := range credentialNames(rev) {
		uid, found := credentials[name]
		if (ok && !found) || (found && slices.Contains(rec.RevokedCredentials, uid)) {
			return fmt.Errorf("%s uses credential %s, which is revoked or cannot be resolved", rev.Name, name)
		}
	}
	return nil
}

// mergeRecovery keeps the journaled target and adds any revocation or
// retirement asked for since.
func mergeRecovery(journaled, asked Recovery) Recovery {
	out := journaled
	out.RevokedPrefixes = union(journaled.RevokedPrefixes, asked.RevokedPrefixes)
	out.RevokedCredentials = union(journaled.RevokedCredentials, asked.RevokedCredentials)
	out.Retired = journaled.Retired || asked.Retired
	return out
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// originations lists the prefixes a revision originates.
func originations(rev *networkv1alpha1.FabricRouterRevision) []string {
	var out []string
	for _, adv := range rev.Spec.Configuration.Advertisements {
		for _, p := range adv.Spec.Prefixes {
			out = append(out, string(p))
		}
		if adv.Spec.Aggregation != nil {
			out = append(out, adv.Spec.Aggregation.Prefix)
		}
	}
	return out
}

// credentialNames lists the Secrets a revision's peers authenticate with.
func credentialNames(rev *networkv1alpha1.FabricRouterRevision) []string {
	var out []string
	for _, p := range rev.Spec.Configuration.Peers {
		if ref := p.Spec.AuthSecretRef; ref != nil && !slices.Contains(out, ref.Name) {
			out = append(out, ref.Name)
		}
	}
	return out
}

// revokedOrigination returns the first of originated that rec revokes: a
// revoked prefix or any prefix inside one. A prefix that does not parse on
// either side is treated as revoked.
func revokedOrigination(rec Recovery, originated []string) string {
	revoked := make([]netip.Prefix, 0, len(rec.RevokedPrefixes))
	for _, p := range rec.RevokedPrefixes {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return p
		}
		revoked = append(revoked, pfx.Masked())
	}
	if len(revoked) == 0 {
		return ""
	}
	for _, p := range originated {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return p
		}
		for _, r := range revoked {
			if pfx.Bits() >= r.Bits() && r.Contains(pfx.Addr()) {
				return p
			}
		}
	}
	return ""
}

// Resume finishes an activation interrupted by a crash, following the
// last journal record for its epoch.
func (a *Activator) Resume(ctx context.Context, req Request) (Result, error) {
	act := req.Activation
	if err := checkRevision(req); err != nil {
		return Result{}, err
	}
	if err := a.checkIdentity(act); err != nil {
		return Result{}, err
	}
	rec, ok := a.journal.LastForEpoch(act.DeploymentUID, act.Epoch)
	if !ok {
		return Result{}, fmt.Errorf("epoch %d of deployment %s was never accepted", act.Epoch, act.DeploymentUID)
	}
	if high, _ := a.journal.HighWater(act.DeploymentUID); act.Epoch != high {
		return Result{}, fmt.Errorf("%w: epoch %d below accepted %d", ErrStale, act.Epoch, high)
	}
	if rec.Activation != act {
		return Result{}, fmt.Errorf("%w: epoch %d was accepted for %s", ErrStale, act.Epoch, rec.describe())
	}
	// The recovery target is fixed with the epoch; revocations only grow,
	// so those journaled and those asked for now both apply.
	if accepted, ok := a.journal.Accepted(act.DeploymentUID, act.Epoch); ok && accepted.Recovery != nil {
		req.Recovery = mergeRecovery(*accepted.Recovery, req.Recovery)
	}
	rendered, path, err := a.render(req.Revision, "active.conf")
	if err != nil {
		return Result{}, err
	}
	switch rec.Type {
	case RecordCommitted:
		// A crash between the commit and the checkpoint leaves the
		// checkpoint on the previous revision.
		if cp, err := ReadCheckpoint(a.Dir); err != nil || cp.Activation != act {
			if err := a.checkpoint(req, act, req.Revision, rendered); err != nil {
				return Result{}, err
			}
		}
		return Result{Outcome: OutcomeCommitted}, nil
	case RecordRecovered:
		return Result{Outcome: OutcomeRecovered, Detail: rec.Detail}, nil
	case RecordApplyFailed:
		return a.recover(ctx, req, "resumed after a failed apply: "+rec.Detail)
	case RecordApplied:
		return a.observeAndCommit(ctx, req, rendered)
	case RecordAccepted:
		diff, err := a.runningDiff(ctx, rendered)
		if err != nil {
			return Result{}, err
		}
		if len(diff) == 0 {
			if _, err := a.journal.Append(Record{Type: RecordApplied, Activation: act}); err != nil {
				return Result{}, err
			}
			return a.observeAndCommit(ctx, req, rendered)
		}
		if rec.PreviousGood == "" || a.runningIsCheckpoint(ctx) {
			// Still on the previous configuration: the accepted epoch
			// never failed, so apply it again under the same epoch.
			return a.apply(ctx, req, rendered, path)
		}
		if _, err := a.journal.Append(Record{
			Type: RecordApplyFailed, Activation: act, Detail: "running configuration matches neither side after a crash",
		}); err != nil {
			return Result{}, err
		}
		return a.recover(ctx, req, "running configuration matches neither side after a crash")
	}
	return Result{}, fmt.Errorf("cannot resume from a %s record", rec.Type)
}

// Activated reports whether the node ever accepted an activation or holds a
// checkpoint. Before that, the CRD source has nothing of its own to run.
func (a *Activator) Activated() bool {
	if a.journal == nil {
		return true
	}
	for _, rec := range a.journal.Records() {
		if rec.Type == RecordAccepted {
			return true
		}
	}
	_, err := ReadCheckpoint(a.Dir)
	return !errors.Is(err, os.ErrNotExist)
}

// Reassert reloads the checkpoint when FRR runs anything else, as after a
// return to the CRD source or a change made outside the agent. It reports
// whether FRR runs the checkpoint afterwards.
func (a *Activator) Reassert(ctx context.Context, timeout time.Duration) (bool, error) {
	cp, err := ReadCheckpoint(a.Dir)
	if err != nil {
		return false, err
	}
	diff, err := a.runningDiff(ctx, cp.Config)
	if err != nil {
		return false, err
	}
	if len(diff) == 0 {
		return true, nil
	}
	path := filepath.Join(a.Dir, "reassert.conf")
	if err := writeAtomic(path, []byte(cp.Config)); err != nil {
		return false, err
	}
	if err := a.FRR.Check(ctx, path); err != nil {
		return false, err
	}
	if err := a.reload(ctx, path, timeout); err != nil {
		return false, err
	}
	diff, err = a.runningDiff(ctx, cp.Config)
	return err == nil && len(diff) == 0, err
}

// runningIsCheckpoint reports whether FRR runs the last committed
// configuration.
func (a *Activator) runningIsCheckpoint(ctx context.Context) bool {
	cp, err := ReadCheckpoint(a.Dir)
	if err != nil {
		return false
	}
	diff, err := a.runningDiff(ctx, cp.Config)
	return err == nil && len(diff) == 0
}

func (a *Activator) runningDiff(ctx context.Context, rendered string) ([]string, error) {
	running, err := a.FRR.Running(ctx)
	if err != nil {
		return nil, err
	}
	return frrtext.Diff(normalizeRunning(rendered), normalizeRunning(running)), nil
}

// RunningKey identifies what a running configuration means, ignoring what
// normalizeRunning drops, such as the VRF devices on the host.
func RunningKey(running string) string {
	data, _ := json.Marshal(normalizeRunning(running)) // a map of maps of ints always marshals
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// normalizeRunning drops the lines FRR adds to or omits from a displayed
// configuration that carry no routing meaning: the hostname, which FRR
// reports as the host's, the banner, vtysh's own integrated-config setting,
// the closing end, and an empty block for each VRF device on the host,
// which zebra shows whether or not any configuration names it.
func normalizeRunning(text string) frrtext.Config {
	var keep []string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "hostname ") || strings.HasPrefix(t, "Building configuration") ||
			strings.HasPrefix(t, "Current configuration") || t == "service integrated-vtysh-config" ||
			(t == "end" && line == t) {
			continue
		}
		if strings.HasPrefix(line, "vrf ") && i+1 < len(lines) && strings.TrimSpace(lines[i+1]) == "exit-vrf" {
			i++
			continue
		}
		keep = append(keep, line)
	}
	return frrtext.Normalize(strings.Join(keep, "\n"))
}

// BootDecision is what an agent starting without the API may do.
type BootDecision struct {
	// Apply is the configuration to restore, empty when none may be.
	Apply string
	// Reason explains the decision.
	Reason string
}

// Boot decides whether the checkpoint may be restored without the API: it
// needs a readable journal, and the checkpoint must verify, belong to this
// machine and to the Node, cluster and state directory it was written for,
// come from this compiler and FRR version, carry no credential the API must
// supply, be within its boot authorization by a clock that has not moved
// backwards past the journal, and be allowed by the newest recovery the
// journal accepted: not retired, originating no revoked prefix and using no
// revoked credential.
//
// id is what the agent knows of itself; without the API only MachineID.
func (a *Activator) Boot(id Identity) BootDecision { return a.boot(id, false) }

// BootOnline is Boot for an agent that reached the API and found this
// node's deployment bound to the journal: the boot authorization's lifetime
// and the clock bound only how long a checkpoint is trusted without the
// API, so they are not checked. Every other check is.
func (a *Activator) BootOnline(id Identity) BootDecision { return a.boot(id, true) }

func (a *Activator) boot(id Identity, online bool) BootDecision {
	if a.journal == nil {
		return BootDecision{Reason: "Bootstrapping: the journal is unreadable"}
	}
	recorded, err := BindIdentity(a.Dir, id)
	if err != nil {
		return BootDecision{Reason: "Bootstrapping: " + err.Error()}
	}
	cp, err := ReadCheckpoint(a.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return BootDecision{Reason: "Bootstrapping: no checkpoint"}
	}
	if err != nil {
		return BootDecision{Reason: "Bootstrapping: " + err.Error()}
	}
	now := a.now()
	switch {
	case cp.Nonce != recorded.Nonce || cp.Activation.NodeUID != recorded.NodeUID ||
		cp.Activation.ClusterID != recorded.ClusterID:
		return BootDecision{Reason: "Bootstrapping: the checkpoint was written for another Node, cluster or state"}
	case cp.SemanticsVersion != compile.SemanticsVersion || cp.FRRVersion != compile.FRRVersion:
		return BootDecision{Reason: "Bootstrapping: the checkpoint is from another compiler or FRR version"}
	case cp.RequiresAPI:
		return BootDecision{Reason: "Bootstrapping: the checkpoint needs credentials from the API"}
	case !online && now.Before(a.journal.LatestTime()):
		return BootDecision{Reason: "Bootstrapping: the clock is behind the journal"}
	case !online && !now.Before(cp.BootAuthorizedUntil):
		return BootDecision{Reason: "Bootstrapping: boot authorization expired at " + cp.BootAuthorizedUntil.String()}
	}
	if rec, ok := a.journal.LatestRecovery(); ok {
		revoked := revokedOrigination(rec, cp.Originates)
		switch {
		case rec.Retired:
			return BootDecision{Reason: "Bootstrapping: the router is retired"}
		case revoked != "":
			return BootDecision{Reason: "Bootstrapping: the checkpoint originates revoked " + revoked}
		}
		for _, uid := range cp.CredentialUIDs {
			if slices.Contains(rec.RevokedCredentials, uid) {
				return BootDecision{Reason: "Bootstrapping: the checkpoint uses a revoked credential"}
			}
		}
	}
	return BootDecision{Apply: cp.Config, Reason: "restoring committed " + cp.Activation.Revision}
}

func head(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
