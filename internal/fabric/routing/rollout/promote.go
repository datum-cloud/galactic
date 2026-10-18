// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rollout is the fabric rollout manager. It gives every fabric
// router a FabricRouterDeployment, keeps the deployment's candidate on the
// router's newest revision, and runs FabricReleaseAuthorizations: it starts
// one release per routing domain at a time, promotes the revisions each
// names within the rollout policy's concurrency, and records the outcome
// the node agents report. It never writes FRR.
package rollout

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Policy defaults, matching the FabricRolloutPolicy schema's.
const (
	defaultMaxUnavailable     = 1
	defaultFailureDomainLabel = "topology.kubernetes.io/zone"
	defaultStabilization      = 60
	defaultApplyTimeout       = 60
	minHeartbeatTimeout       = 60
	defaultOfflineBoot        = 604800
)

// effectivePolicy fills a policy's unset fields with their defaults; nil is
// every default.
func effectivePolicy(p *networkv1alpha1.FabricRolloutPolicy) networkv1alpha1.FabricRolloutPolicySpec {
	var spec networkv1alpha1.FabricRolloutPolicySpec
	if p != nil {
		spec = p.Spec
	}
	if spec.MaxUnavailable <= 0 {
		spec.MaxUnavailable = defaultMaxUnavailable
	}
	if spec.FailureDomainLabel == "" {
		spec.FailureDomainLabel = defaultFailureDomainLabel
	}
	if spec.StabilizationSeconds <= 0 {
		spec.StabilizationSeconds = defaultStabilization
	}
	if spec.ApplyTimeoutSeconds <= 0 {
		spec.ApplyTimeoutSeconds = defaultApplyTimeout
	}
	if spec.HeartbeatTimeoutSeconds < minHeartbeatTimeout {
		// The agent writes an unchanged status every 30s; anything shorter
		// would read every healthy router as silent.
		spec.HeartbeatTimeoutSeconds = minHeartbeatTimeout
	}
	if spec.OfflineBootSeconds <= 0 {
		spec.OfflineBootSeconds = defaultOfflineBoot
	}
	return spec
}

// activationSettings resolves the settings one promotion of rev carries:
// the policy's timers, every peer with an IP address except the optional
// and maintenance ones, and every static route.
func activationSettings(policy networkv1alpha1.FabricRolloutPolicySpec,
	rev *networkv1alpha1.FabricRouterRevision) *networkv1alpha1.FabricActivationSettings {
	excluded := map[string]bool{}
	for _, p := range append(slices.Clone(policy.OptionalPeers), policy.MaintenancePeers...) {
		excluded[p.Name] = true
	}
	out := &networkv1alpha1.FabricActivationSettings{
		StabilizationSeconds: policy.StabilizationSeconds,
		ApplyTimeoutSeconds:  policy.ApplyTimeoutSeconds,
		OfflineBootSeconds:   policy.OfflineBootSeconds,
	}
	for _, p := range rev.Spec.Configuration.Peers {
		a, err := netip.ParseAddr(p.Spec.Address)
		if err != nil || excluded[p.Name] {
			continue
		}
		if s := a.String(); !slices.Contains(out.RequiredPeers, s) {
			out.RequiredPeers = append(out.RequiredPeers, s)
		}
	}
	for _, r := range rev.Spec.Configuration.StaticRoutes {
		p, err := netip.ParsePrefix(r.Spec.Destination)
		if err != nil {
			continue
		}
		if s := p.Masked().String(); !slices.Contains(out.RequiredStaticRoutes, s) {
			out.RequiredStaticRoutes = append(out.RequiredStaticRoutes, s)
		}
	}
	slices.Sort(out.RequiredPeers)
	slices.Sort(out.RequiredStaticRoutes)
	return out
}

// committed reports whether the deployment's active epoch is committed, by
// its status.
func committed(d *networkv1alpha1.FabricRouterDeployment) bool {
	return d.Spec.ActiveRevisionRef != nil && d.Status.AppliedEpoch == d.Spec.ActivationEpoch &&
		d.Status.AppliedRevision == d.Spec.ActiveRevisionRef.Name &&
		d.Status.AppliedDigest == d.Spec.ActivationDependencyDigest
}

// Committed reports whether a deployment's status reports its active
// epoch committed.
func Committed(d *networkv1alpha1.FabricRouterDeployment) bool { return committed(d) }

// promote returns d's spec promoted to rev under auth: the next epoch, the
// revision and its digest, the authorization, the activation settings, and
// a recovery to the revision d runs now when that is committed (otherwise
// the recovery d already had). A recovery target that is rev itself is
// dropped, and a re-activation has none: the target it had could be newer
// than the revision, abandoned by a rollback. Revocations carry over; an
// emergency withdrawal adds the prefixes it withdraws. The caller checks
// the recovery target is still eligible.
func promote(d *networkv1alpha1.FabricRouterDeployment, rev *networkv1alpha1.FabricRouterRevision,
	auth *networkv1alpha1.FabricReleaseAuthorization, target networkv1alpha1.FabricReleaseTarget,
	settings *networkv1alpha1.FabricActivationSettings) networkv1alpha1.FabricRouterDeploymentSpec {
	spec := *d.Spec.DeepCopy()
	recovery := &networkv1alpha1.FabricRecovery{}
	if d.Spec.Recovery != nil {
		recovery = d.Spec.Recovery.DeepCopy()
	}
	if committed(d) {
		recovery.TargetRevisionRef = &networkv1alpha1.LocalObjectRef{Name: d.Spec.ActiveRevisionRef.Name}
		recovery.TargetDependencyDigest = d.Spec.ActivationDependencyDigest
	}
	if target.Reactivate || (recovery.TargetRevisionRef != nil && recovery.TargetRevisionRef.Name == rev.Name) {
		// Recovery to the revision being promoted would restore the
		// failure; a re-activation's earlier target may be one a rollback
		// abandoned.
		recovery.TargetRevisionRef, recovery.TargetDependencyDigest = nil, ""
	}
	if auth.Spec.Type == networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal {
		for _, p := range auth.Spec.WithdrawnPrefixes {
			if !slices.Contains(recovery.RevokedPrefixes, p) {
				recovery.RevokedPrefixes = append(recovery.RevokedPrefixes, p)
			}
		}
	}
	if target.Retire {
		recovery.Retired = true
	}
	spec.ActivationEpoch = d.Spec.ActivationEpoch + 1
	spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: rev.Name}
	spec.ActivationDependencyDigest = rev.Spec.ActivationDependencyDigest
	spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: auth.Name, UID: string(auth.UID)}
	spec.Activation = settings
	spec.Recovery = recovery
	return spec
}

// Busy reports whether a deployment's current epoch is still activating,
// so nothing should move it until the epoch finishes.
func Busy(d *networkv1alpha1.FabricRouterDeployment) bool { return busy(d) }

// busy reports whether a deployment's current epoch, under any release,
// is still activating: promoted, and neither committed nor finished
// failing, nor refused by its agent.
func busy(d *networkv1alpha1.FabricRouterDeployment) bool {
	if d.Spec.ActivationEpoch == 0 || committed(d) || refused(d) || handedBack(d) {
		return false
	}
	for _, e := range d.Status.Epochs {
		if e.Epoch != d.Spec.ActivationEpoch {
			continue
		}
		switch e.Stage {
		case networkv1alpha1.FabricStageRecovered, networkv1alpha1.FabricStageDegraded:
			return false
		case networkv1alpha1.FabricStageApplyFailed:
			// Recovery follows a failed apply; it is over only when the
			// agent found nothing to recover to.
			return !degradedFinal(d)
		}
	}
	return true
}

// handedBack reports whether the agent has handed the node back to its
// ConfigMap: nothing activates there, whatever its last epoch reported.
func handedBack(d *networkv1alpha1.FabricRouterDeployment) bool {
	eff := d.Status.EffectiveSource
	return d.Spec.Source != networkv1alpha1.FabricConfigSourceCRD && eff != "" &&
		eff != networkv1alpha1.FabricConfigSourceCRD
}

// refused reports whether the agent refused the current promotion for
// good, before accepting it: its release ended or never covered it. The
// agent accepts nothing without reporting it, so a refusal reported for
// this generation, with no outcome for its epoch, means nothing activates.
func refused(d *networkv1alpha1.FabricRouterDeployment) bool {
	for _, e := range d.Status.Epochs {
		if e.Epoch == d.Spec.ActivationEpoch {
			return false
		}
	}
	c := meta.FindStatusCondition(d.Status.Conditions, networkv1alpha1.FabricConditionAccepted)
	return c != nil && c.Status == metav1.ConditionFalse && c.Reason == networkv1alpha1.FabricReasonPromotionRefused &&
		c.ObservedGeneration == d.Generation
}

// degradedFinal reports whether the agent found no eligible recovery for
// the active epoch, so its failure is final.
func degradedFinal(d *networkv1alpha1.FabricRouterDeployment) bool {
	for _, c := range d.Status.Conditions {
		if c.Type == networkv1alpha1.FabricConditionDegraded && c.Status == metav1.ConditionTrue &&
			c.Reason == networkv1alpha1.FabricReasonNoEligibleRecovery && c.ObservedGeneration == d.Generation {
			return true
		}
	}
	return false
}

// runs reports whether a deployment already runs target, committed.
func runs(d *networkv1alpha1.FabricRouterDeployment, target networkv1alpha1.FabricReleaseTarget) bool {
	return committed(d) && d.Spec.ActiveRevisionRef.Name == target.Revision &&
		d.Spec.ActivationDependencyDigest == target.ActivationDependencyDigest
}

// revokedOrigination returns the first prefix rev originates that revoked
// covers, or that does not parse.
func revokedOrigination(revoked []string, rev *networkv1alpha1.FabricRouterRevision) string {
	var covers []netip.Prefix
	for _, r := range revoked {
		if p, err := netip.ParsePrefix(r); err == nil {
			covers = append(covers, p.Masked())
		}
	}
	if len(covers) == 0 {
		return ""
	}
	var originated []string
	for _, adv := range rev.Spec.Configuration.Advertisements {
		for _, p := range adv.Spec.Prefixes {
			originated = append(originated, string(p))
		}
		if adv.Spec.Aggregation != nil {
			originated = append(originated, adv.Spec.Aggregation.Prefix)
		}
	}
	for _, o := range originated {
		p, err := netip.ParsePrefix(o)
		if err != nil {
			return o
		}
		for _, c := range covers {
			if p.Bits() >= c.Bits() && c.Contains(p.Addr()) {
				return o
			}
		}
	}
	return ""
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

// credentialProblem says why rev may not use its credentials: a Secret
// that cannot be resolved, which revocation by UID could never match, or
// one whose UID revoked holds. It returns empty when there is none.
// credentials maps Secret names to their current UIDs.
func credentialProblem(revoked []networkv1alpha1.FabricObjectIdentity, rev *networkv1alpha1.FabricRouterRevision,
	credentials map[string]string) string {
	for _, n := range credentialNames(rev) {
		uid, ok := credentials[n]
		if !ok {
			return "uses credential " + n + ", which cannot be resolved"
		}
		for _, r := range revoked {
			if r.UID == uid {
				return fmt.Sprintf("uses credential %s (Secret UID %s), which is revoked", n, uid)
			}
		}
	}
	return ""
}

// targetState is where one release target stands.
type targetState int

const (
	// targetWaiting has not been promoted under the release.
	targetWaiting targetState = iota
	// targetActivating is promoted and not yet committed or failed.
	targetActivating
	// targetCommitted is promoted and committed.
	targetCommitted
	// targetFailed is promoted and failed, recovered or not.
	targetFailed
	// targetSilent is promoted and its agent stopped reporting.
	targetSilent
	// targetBlocked is not promoted because the deployment is still
	// activating another release's epoch.
	targetBlocked
	// targetSuperseded was moved on by a later release; this release
	// leaves it alone.
	targetSuperseded
)

// stateOf reads a target's state from its deployment.
func stateOf(d *networkv1alpha1.FabricRouterDeployment, auth *networkv1alpha1.FabricReleaseAuthorization,
	target networkv1alpha1.FabricReleaseTarget, heartbeat time.Duration, now time.Time) targetState {
	ref := d.Spec.AuthorizationRef
	if ref == nil || ref.UID != string(auth.UID) || d.Spec.ActiveRevisionRef == nil ||
		d.Spec.ActiveRevisionRef.Name != target.Revision {
		switch {
		case runs(d, target) && !target.Reactivate:
			// Already committed on this revision and digest; a
			// re-activation promotes it again.
			return targetCommitted
		case busy(d):
			return targetBlocked
		}
		return targetWaiting
	}
	for _, e := range d.Status.Epochs {
		if e.Epoch != d.Spec.ActivationEpoch {
			continue
		}
		switch e.Stage {
		case networkv1alpha1.FabricStageCommitted:
			if committed(d) {
				return targetCommitted
			}
		case networkv1alpha1.FabricStageApplyFailed, networkv1alpha1.FabricStageRecovered,
			networkv1alpha1.FabricStageDegraded:
			return targetFailed
		}
	}
	if hb := d.Status.HeartbeatTime; hb == nil || now.Sub(hb.Time) > heartbeat {
		return targetSilent
	}
	return targetActivating
}

// recovered reports whether a failed target is back on what it recovered
// to: its epoch journaled Recovered and its applied revision is the
// recovery target.
func recovered(d *networkv1alpha1.FabricRouterDeployment) bool {
	r := d.Spec.Recovery
	if r == nil || r.TargetRevisionRef == nil {
		return false
	}
	for _, e := range d.Status.Epochs {
		if e.Epoch == d.Spec.ActivationEpoch && e.Stage == networkv1alpha1.FabricStageRecovered {
			return d.Status.AppliedRevision == r.TargetRevisionRef.Name
		}
	}
	return false
}
