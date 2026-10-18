// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/revision"
	"go.datum.net/galactic/internal/fabricconfig/activation"
)

const (
	defaultDeploymentInterval = 5 * time.Second
	// maxEpochStatus bounds status.epochs, as its schema does.
	maxEpochStatus = 16
	// maxStagedDiff bounds status.staged.diff, as its schema does.
	maxStagedDiff = 8192

	reasonHandoffPending   = "HandoffPending"
	reasonNotAuthorized    = "NotAuthorized"
	reasonRevisionNotFound = "RevisionNotFound"
	reasonActivating       = "Activating"
	reasonStaged           = "Staged"
	reasonRejected         = "Rejected"
	reasonPersistFailed    = "PersistFailed"
	reasonReassertFailed   = "ReassertFailed"
)

// DeploymentAgent activates the node's FabricRouterDeployment through an
// activation.Activator, owns the node's configuration source, and reports
// what it staged, applied and committed in the deployment's status.
type DeploymentAgent struct {
	// Client reads deployments, revisions, release authorizations and
	// Secret metadata, and writes deployment status.
	Client    client.Client
	Namespace string
	NodeName  string
	// NodeUID and ClusterID identify this node; the activator's state
	// directory is bound to them.
	NodeUID   string
	ClusterID string
	// MachineID is the host's machine ID.
	MachineID string

	Activator *activation.Activator
	// BGP reads session and route state for the health check.
	BGP BGP
	// Gate is set to the effective source the journal records.
	Gate *SourceGate
	// Lock is the node's FRR writer lock, held while the source changes
	// and while frr.conf is persisted. Nil means no other writer exists.
	Lock Locker
	// IdentityErr, when set, is why the state directory could not be bound
	// to this Node and cluster. The agent then acts on nothing and reports
	// RecoveryConflict until an operator resets the state.
	IdentityErr error
	// ConfigDir receives each committed or recovered configuration as
	// frr.conf, so a restarted pod starts from it.
	ConfigDir string

	// Interval is the time between syncs. Zero selects 5s.
	Interval time.Duration
	// Version is the agent build reported in status.
	Version string
	// Now reads the clock; nil is time.Now.
	Now func() time.Time
	// Metrics counts activations and staging runs. Nil disables them.
	Metrics *AgentMetrics
	// Booted is where the last configuration BootConfig returned came
	// from.
	Booted BootSource
	// ConfigMapsRetired keeps the node on the CRD source without reading
	// any ConfigMap: a deployment asking for another source is reported,
	// never handed off, and BootConfig starts a node with nothing
	// activated from its deployment's active revision.
	ConfigMapsRetired bool

	// staged is the candidate last staged and the running configuration it
	// was staged against, so an unchanged candidate is not restaged every
	// sync, and is restaged once FRR runs something else.
	staged string
	// written is the status last written, to skip unchanged writes.
	written *networkv1alpha1.FabricRouterDeploymentStatus
	// inSync is whether FRR was last seen running the checkpoint.
	inSync bool
	// counter remembers which outcomes the current epoch was counted with.
	counter activationCounter
	// Resolve, when NodeUID is not known yet, reads this node's identity
	// from the API and binds the state directory to it, setting NodeUID,
	// ClusterID and IdentityErr.
	Resolve func(ctx context.Context) error
}

// heartbeatInterval is how often an otherwise unchanged status is written.
const heartbeatInterval = 30 * time.Second

func (d *DeploymentAgent) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Run syncs every Interval until ctx ends.
func (d *DeploymentAgent) Run(ctx context.Context) {
	interval := d.Interval
	if interval <= 0 {
		interval = defaultDeploymentInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	last := ""
	for {
		err := d.Sync(ctx)
		switch {
		case err == nil:
			last = ""
		case ctx.Err() == nil && err.Error() != last:
			// Log a persisting error once, not every interval.
			last = err.Error()
			slog.Error("could not sync fabric router deployment", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sync makes one pass: it finds the node's deployment, settles the source,
// stages the candidate, activates the active revision when the source is
// CRD, and writes status.
func (d *DeploymentAgent) Sync(ctx context.Context) error {
	journal := d.Activator.Journal()
	d.inSync = false
	if d.NodeUID == "" {
		d.Gate.Set(JournalSource(journal))
		if d.Resolve == nil {
			return errors.New("this node's identity is unknown")
		}
		if err := d.Resolve(ctx); err != nil {
			return fmt.Errorf("resolve this node's identity: %w", err)
		}
	}
	dep, err := d.find(ctx)
	if err != nil {
		return err
	}
	if dep == nil {
		// Without a deployment the source stays where the journal left it:
		// a node on CRD returns to its ConfigMap only through a handoff.
		d.Gate.Set(JournalSource(journal))
		return nil
	}
	status := dep.Status.DeepCopy()
	status.ObservedGeneration = dep.Generation
	status.ClusterID = d.ClusterID
	status.AgentVersion = d.Version

	if d.IdentityErr != nil {
		d.Gate.Set(JournalSource(journal))
		setCondition(status, dep, networkv1alpha1.FabricConditionRecoveryConflict, metav1.ConditionTrue,
			networkv1alpha1.FabricReasonRecoveryConflict,
			"the node's activation state belongs to another Node, cluster or machine: "+d.IdentityErr.Error())
		return errors.Join(d.IdentityErr, d.writeStatus(ctx, dep, status))
	}
	if err := d.bind(dep, status); err != nil {
		d.Gate.Set(JournalSource(journal))
		return errors.Join(err, d.writeStatus(ctx, dep, status))
	}
	pending, err := d.settleSource(ctx, dep, status)
	if err != nil {
		return errors.Join(err, d.writeStatus(ctx, dep, status))
	}
	if JournalSource(journal) == networkv1alpha1.FabricConfigSourceConfigMap {
		// A node on its ConfigMap stages nothing: Shadow is where an
		// operator asks for the candidate to be validated and diffed.
		d.unstage(status)
	} else {
		d.stage(ctx, dep, status)
	}
	if JournalSource(journal) != networkv1alpha1.FabricConfigSourceCRD {
		// Degraded describes an activation; off CRD the node runs its
		// ConfigMap, and status.epochs keeps what happened.
		meta.RemoveStatusCondition(&status.Conditions, networkv1alpha1.FabricConditionDegraded)
	}
	switch {
	case JournalSource(journal) == networkv1alpha1.FabricConfigSourceCRD && dep.Spec.ActivationEpoch > 0:
		d.activate(ctx, dep, status)
	case !pending:
		setCondition(status, dep, networkv1alpha1.FabricConditionAccepted, metav1.ConditionFalse,
			networkv1alpha1.FabricReasonWaitingForPromotion,
			"no active revision on the CRD source")
	}
	d.report(status, dep)
	return d.writeStatus(ctx, dep, status)
}

// find returns the deployment targeting this node, nil when there is none.
// Two deployments for one node is an error: neither is acted on.
func (d *DeploymentAgent) find(ctx context.Context) (*networkv1alpha1.FabricRouterDeployment, error) {
	var list networkv1alpha1.FabricRouterDeploymentList
	if err := d.Client.List(ctx, &list, client.InNamespace(d.Namespace),
		client.MatchingFieldsSelector{Selector: fields.OneTermEqualSelector("spec.target.nodeName", d.NodeName)},
	); err != nil {
		return nil, fmt.Errorf("list fabric router deployments: %w", err)
	}
	var mine []networkv1alpha1.FabricRouterDeployment
	for _, dep := range list.Items {
		if dep.Spec.Target.NodeUID == d.NodeUID {
			mine = append(mine, dep)
		}
	}
	switch len(mine) {
	case 0:
		return nil, nil
	case 1:
		return &mine[0], nil
	}
	return nil, fmt.Errorf("%d fabric router deployments target node %s", len(mine), d.NodeName)
}

// bind checks the journal belongs to this deployment, rebinding it when
// the deployment approves it.
func (d *DeploymentAgent) bind(dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) error {
	journal := d.Activator.Journal()
	uid := string(dep.UID)
	bound := journal.BoundDeployment()
	if bound != "" && bound != uid {
		if rb := dep.Spec.Rebind; rb != nil && rb.FromDeploymentUID == bound {
			if err := journal.Rebind(bound, uid); err != nil {
				return err
			}
			slog.Info("rebound activation journal", "from", bound, "to", uid, "approvedBy", rb.ApprovedBy)
		} else {
			msg := fmt.Sprintf("the node's journal is bound to deployment %s; set spec.rebind to accept this one",
				bound)
			status.BoundDeploymentUID = bound
			setCondition(status, dep, networkv1alpha1.FabricConditionRecoveryConflict, metav1.ConditionTrue,
				networkv1alpha1.FabricReasonRecoveryConflict, msg)
			return fmt.Errorf("%w: %s", activation.ErrRecoveryConflict, msg)
		}
	}
	status.BoundDeploymentUID = uid
	setCondition(status, dep, networkv1alpha1.FabricConditionRecoveryConflict, metav1.ConditionFalse, "Bound",
		"the node's journal is bound to this deployment")
	return nil
}

// settleSource moves the node to the deployment's source. Leaving CRD needs
// the handoff's ConfigMap to be the one the node has now, by UID and
// version; until then the node stays on CRD and pending is true.
func (d *DeploymentAgent) settleSource(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) (pending bool, err error) {
	err = withLock(ctx, d.Lock, func() error {
		pending, err = d.settleSourceLocked(ctx, dep, status)
		return err
	})
	return pending, err
}

func (d *DeploymentAgent) settleSourceLocked(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) (pending bool, err error) {
	journal := d.Activator.Journal()
	current, want := JournalSource(journal), dep.Spec.Source
	if d.ConfigMapsRetired {
		return d.settleRetiredLocked(dep, status)
	}
	if current == networkv1alpha1.FabricConfigSourceCRD && want != networkv1alpha1.FabricConfigSourceCRD {
		if err := d.checkHandoff(ctx, dep); err != nil {
			setCondition(status, dep, networkv1alpha1.FabricConditionAccepted, metav1.ConditionFalse,
				reasonHandoffPending, err.Error())
			d.Gate.Set(current)
			status.EffectiveSource = current
			return true, nil
		}
	}
	// The ConfigMap a handoff named stays pinned, across restarts, until
	// the node returns to CRD.
	handoff := journal.Handoff()
	switch {
	case want == networkv1alpha1.FabricConfigSourceCRD:
		handoff = ""
	case current == networkv1alpha1.FabricConfigSourceCRD:
		handoff = dep.Spec.SourceHandoff.ConfigMap.UID
	}
	if err := journal.SetSourceHandoff(string(want), handoff); err != nil {
		return false, err
	}
	d.Gate.SetHandoff(journal.Handoff())
	d.Gate.Set(want)
	status.EffectiveSource = want
	return false, nil
}

// settleRetiredLocked keeps the node on CRD, the only source it can run
// with its ConfigMap path retired. A deployment asking for another source
// is reported as pending, and no handoff is checked: that would read the
// ConfigMap.
func (d *DeploymentAgent) settleRetiredLocked(dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) (pending bool, err error) {
	crd := networkv1alpha1.FabricConfigSourceCRD
	if err := d.Activator.Journal().SetSourceHandoff(string(crd), ""); err != nil {
		return false, err
	}
	d.Gate.SetHandoff("")
	d.Gate.Set(crd)
	status.EffectiveSource = crd
	if dep.Spec.Source == crd {
		return false, nil
	}
	setCondition(status, dep, networkv1alpha1.FabricConditionAccepted, metav1.ConditionFalse,
		networkv1alpha1.FabricReasonConfigMapRetired,
		fmt.Sprintf("the node's ConfigMap path is retired, so it stays on CRD rather than move to %s", dep.Spec.Source))
	return true, nil
}

func (d *DeploymentAgent) checkHandoff(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment) error {
	h := dep.Spec.SourceHandoff
	if h == nil {
		return errors.New("leaving the CRD source needs spec.sourceHandoff")
	}
	if h.ConfigMap.Name != ConfigMapName(d.NodeName) {
		return fmt.Errorf("handoff names ConfigMap %s, not this node's %s", h.ConfigMap.Name, ConfigMapName(d.NodeName))
	}
	var cm corev1.ConfigMap
	if err := d.Client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: h.ConfigMap.Name}, &cm); err != nil {
		return fmt.Errorf("read handoff ConfigMap: %w", err)
	}
	if string(cm.UID) != h.ConfigMap.UID || cm.ResourceVersion != h.ResourceVersion {
		return fmt.Errorf("ConfigMap %s is at UID %s version %s, the handoff names UID %s version %s",
			cm.Name, cm.UID, cm.ResourceVersion, h.ConfigMap.UID, h.ResourceVersion)
	}
	return nil
}

// unstage clears what an earlier stage reported.
func (d *DeploymentAgent) unstage(status *networkv1alpha1.FabricRouterDeploymentStatus) {
	status.Staged = nil
	d.staged = ""
	meta.RemoveStatusCondition(&status.Conditions, networkv1alpha1.FabricConditionStaged)
}

// stage validates the candidate revision without applying it.
func (d *DeploymentAgent) stage(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) {
	ref := dep.Spec.CandidateRevisionRef
	if ref == nil {
		d.unstage(status)
		return
	}
	reported := status.Staged != nil && status.Staged.Revision == ref.Name
	running, err := d.Activator.FRR.Running(ctx)
	if err != nil && reported && strings.HasPrefix(d.staged, ref.Name+"@") {
		// FRR could not say what it runs; what was staged still stands.
		return
	}
	key := ref.Name
	if err == nil {
		key += "@" + activation.RunningKey(running)
	}
	if key == d.staged && reported {
		return
	}
	rev, err := d.revision(ctx, ref.Name)
	if err != nil {
		d.countStage(StageRevisionNotFound)
		setCondition(status, dep, networkv1alpha1.FabricConditionStaged, metav1.ConditionFalse,
			reasonRevisionNotFound, err.Error())
		return
	}
	staged, err := d.Activator.Stage(ctx, rev)
	if err != nil {
		d.countStage(StageRejected)
		setCondition(status, dep, networkv1alpha1.FabricConditionStaged, metav1.ConditionFalse, reasonRejected,
			err.Error())
		return
	}
	d.countStage(StageStaged)
	diff := strings.Join(append(prefixed("+ ", staged.Added), prefixed("- ", staged.Removed)...), "\n")
	if len(diff) > maxStagedDiff {
		diff = diff[:maxStagedDiff]
	}
	status.Staged = &networkv1alpha1.FabricStagedRevision{
		Revision: rev.Name, Digest: rev.Spec.ActivationDependencyDigest, Class: staged.Class,
		LinesAdded:   int32(len(staged.Added)),   //nolint:gosec // bounded by the revision cap
		LinesRemoved: int32(len(staged.Removed)), //nolint:gosec // bounded by the revision cap
		Diff:         diff, ValidatedAt: metav1.NewTime(d.now()),
	}
	d.staged = key
	setCondition(status, dep, networkv1alpha1.FabricConditionStaged, metav1.ConditionTrue, reasonStaged,
		fmt.Sprintf("%s validated: %s, %d lines added, %d removed", rev.Name, staged.Class, len(staged.Added),
			len(staged.Removed)))
}

// activate runs the deployment's active epoch.
func (d *DeploymentAgent) activate(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) {
	act := activation.Activation{
		ClusterID: d.ClusterID, NodeUID: d.NodeUID, DeploymentUID: string(dep.UID), Epoch: dep.Spec.ActivationEpoch,
		Revision: dep.Spec.ActiveRevisionRef.Name, DependencyHash: dep.Spec.ActivationDependencyDigest,
	}
	accepted := func(s metav1.ConditionStatus, reason, msg string) {
		setCondition(status, dep, networkv1alpha1.FabricConditionAccepted, s, reason, msg)
	}
	journal := d.Activator.Journal()
	if rec, ok := journal.LastForEpoch(act.DeploymentUID, act.Epoch); ok && rec.Activation == act &&
		(rec.Type == activation.RecordCommitted || rec.Type == activation.RecordRecovered) {
		// Finished. FRR must still run the checkpoint, and frr.conf hold
		// it: a return to CRD, a change made outside the agent or a crash
		// before the last persist leaves them behind.
		d.reassert(ctx, dep, status)
		return
	}
	if _, ok := journal.Accepted(act.DeploymentUID, act.Epoch); !ok {
		// Authorization gates the first acceptance; a redelivery resumes
		// what was already authorized.
		if err := d.authorized(ctx, dep); err != nil {
			// The rollout manager stops waiting on a refused promotion.
			reason := reasonNotAuthorized
			if errors.Is(err, errRefused) {
				reason = networkv1alpha1.FabricReasonPromotionRefused
				d.count(act.DeploymentUID, act.Epoch, OutcomeRefused, 0)
			}
			accepted(metav1.ConditionFalse, reason, err.Error())
			return
		}
	}
	req, err := d.request(ctx, dep, act)
	if err != nil {
		accepted(metav1.ConditionFalse, reasonRevisionNotFound, err.Error())
		return
	}
	accepted(metav1.ConditionTrue, reasonActivating, fmt.Sprintf("activating %s at epoch %d", act.Revision, act.Epoch))
	// Report the activation as it starts: it can take the apply timeout
	// and the stabilization window.
	if err := d.writeStatus(ctx, dep, status); err != nil {
		slog.Warn("could not report the activation starting", "error", err)
	}
	start := d.now()
	res, err := d.Activator.Activate(ctx, req)
	degraded := func(s metav1.ConditionStatus, reason, msg string) {
		setCondition(status, dep, networkv1alpha1.FabricConditionDegraded, s, reason, msg)
	}
	switch {
	case err != nil:
		// A failed epoch comes back as ErrFailedEpoch on every later
		// sync; it was counted when it failed. A shutdown is no outcome.
		if ctx.Err() == nil && !errors.Is(err, activation.ErrFailedEpoch) {
			d.count(act.DeploymentUID, act.Epoch, errorOutcome(err), 0)
		}
		accepted(metav1.ConditionFalse, activationReason(err), err.Error())
		return
	case res.Outcome == activation.OutcomeCommitted:
		d.count(act.DeploymentUID, act.Epoch, OutcomeCommitted, d.now().Sub(start))
		d.inSync = true
		msg := fmt.Sprintf("%s committed at epoch %d", act.Revision, act.Epoch)
		accepted(metav1.ConditionTrue, networkv1alpha1.FabricReasonCommitted, msg)
		degraded(metav1.ConditionFalse, networkv1alpha1.FabricReasonCommitted, msg)
	case res.Outcome == activation.OutcomeRecovered:
		d.count(act.DeploymentUID, act.Epoch, OutcomeRecovered, d.now().Sub(start))
		d.inSync = true
		accepted(metav1.ConditionFalse, networkv1alpha1.FabricReasonFailedEpoch,
			fmt.Sprintf("epoch %d failed and was recovered", act.Epoch))
		degraded(metav1.ConditionTrue, "Recovered", res.Detail)
	default:
		d.count(act.DeploymentUID, act.Epoch, OutcomeDegraded, d.now().Sub(start))
		accepted(metav1.ConditionFalse, networkv1alpha1.FabricReasonFailedEpoch, fmt.Sprintf("epoch %d failed", act.Epoch))
		degraded(metav1.ConditionTrue, networkv1alpha1.FabricReasonNoEligibleRecovery, res.Detail)
		return
	}
	d.persist(ctx, dep, status)
}

// reassert brings FRR and frr.conf back to the checkpoint.
func (d *DeploymentAgent) reassert(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) {
	var timeout time.Duration
	if s := dep.Spec.Activation; s != nil {
		timeout = time.Duration(s.ApplyTimeoutSeconds) * time.Second
	}
	ok, err := d.Activator.Reassert(ctx, timeout)
	d.inSync = ok
	if err != nil || !ok {
		msg := "FRR does not run the committed checkpoint and could not be brought back to it"
		if err != nil {
			msg += ": " + err.Error()
		}
		setCondition(status, dep, networkv1alpha1.FabricConditionDegraded, metav1.ConditionTrue, reasonReassertFailed, msg)
		return
	}
	if c := meta.FindStatusCondition(status.Conditions, networkv1alpha1.FabricConditionDegraded); c != nil &&
		c.Reason == reasonReassertFailed {
		setCondition(status, dep, networkv1alpha1.FabricConditionDegraded, metav1.ConditionFalse,
			networkv1alpha1.FabricReasonCommitted, "FRR runs the committed checkpoint")
	}
	d.persist(ctx, dep, status)
}

// persist writes the checkpoint's configuration to ConfigDir under the
// writer lock, so a restarted pod starts from what runs. A failure is
// reported as Degraded: FRR runs the right configuration, but a restart
// would not start from it.
func (d *DeploymentAgent) persist(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) {
	err := withLock(ctx, d.Lock, func() error {
		cp, err := activation.ReadCheckpoint(d.Activator.Dir)
		if err != nil {
			return err
		}
		if current, err := os.ReadFile(filepath.Join(d.ConfigDir, KeyFRRConf)); err == nil && string(current) == cp.Config {
			return nil
		}
		return writeFile(d.ConfigDir, KeyFRRConf, cp.Config)
	})
	if err == nil {
		if c := meta.FindStatusCondition(status.Conditions, networkv1alpha1.FabricConditionDegraded); c != nil &&
			c.Reason == reasonPersistFailed {
			setCondition(status, dep, networkv1alpha1.FabricConditionDegraded, metav1.ConditionFalse,
				networkv1alpha1.FabricReasonCommitted, "frr.conf matches the checkpoint")
		}
		return
	}
	{
		setCondition(status, dep, networkv1alpha1.FabricConditionDegraded, metav1.ConditionTrue, reasonPersistFailed,
			"FRR runs the checkpoint, but frr.conf could not be written: "+err.Error())
	}
}

// authorized checks the deployment's release authorization covers its
// active revision. Only a started release authorizes.
func (d *DeploymentAgent) authorized(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment) error {
	return d.authorizedIn(ctx, dep, false)
}

// authorizedIn is authorized, also accepting a release whose outcome is
// Unknown when unreported is set, for a node booting with nothing
// activated: it has never reported and cannot until it starts, and a
// promoted router that does not report makes its release Unknown.
func (d *DeploymentAgent) authorizedIn(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	unreported bool) error {
	ref := dep.Spec.AuthorizationRef
	if ref == nil {
		return fmt.Errorf("%w: the promotion names no release authorization", errRefused)
	}
	var auth networkv1alpha1.FabricReleaseAuthorization
	if err := d.Client.Get(ctx, types.NamespacedName{Namespace: dep.Namespace, Name: ref.Name}, &auth); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: release authorization %s is gone", errRefused, ref.Name)
		}
		return fmt.Errorf("read release authorization %s: %w", ref.Name, err)
	}
	if string(auth.UID) != ref.UID {
		return fmt.Errorf("%w: release authorization %s is UID %s, the promotion names %s", errRefused, ref.Name,
			auth.UID, ref.UID)
	}
	switch auth.Status.Phase {
	case networkv1alpha1.FabricReleasePhaseStarted:
	case networkv1alpha1.FabricReleasePhaseUnknown:
		if !unreported {
			return fmt.Errorf("release authorization %s is %q, not Started", ref.Name, auth.Status.Phase)
		}
	case networkv1alpha1.FabricReleasePhaseCompleted, networkv1alpha1.FabricReleasePhaseFailed,
		networkv1alpha1.FabricReleasePhaseCancelled:
		// A release never starts again once it ends.
		return fmt.Errorf("%w: release authorization %s is %s", errRefused, ref.Name, auth.Status.Phase)
	default:
		// Only a started release activates; a pending or unknown one
		// authorizes nothing yet.
		return fmt.Errorf("release authorization %s is %q, not Started", ref.Name, auth.Status.Phase)
	}
	for _, t := range auth.Spec.Deployments {
		if t.Deployment == dep.Name && t.DeploymentUID == string(dep.UID) &&
			t.Revision == dep.Spec.ActiveRevisionRef.Name &&
			t.ActivationDependencyDigest == dep.Spec.ActivationDependencyDigest {
			return nil
		}
	}
	return fmt.Errorf("%w: release authorization %s does not cover %s at digest %s on this deployment",
		errRefused, ref.Name, dep.Spec.ActiveRevisionRef.Name, dep.Spec.ActivationDependencyDigest)
}

// errRefused is a promotion no release authorization will ever allow, as
// authorizations are immutable and a finished release never restarts.
var errRefused = errors.New("refused")

// request assembles an activation request from the deployment.
func (d *DeploymentAgent) request(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	act activation.Activation) (activation.Request, error) {
	rev, err := d.revision(ctx, act.Revision)
	if err != nil {
		return activation.Request{}, err
	}
	req := activation.Request{Activation: act, Revision: rev, Credentials: map[string]string{}}
	var peers, routes []string
	if s := dep.Spec.Activation; s != nil {
		req.Settings = activation.Settings{
			ApplyTimeout:  time.Duration(s.ApplyTimeoutSeconds) * time.Second,
			Stabilization: time.Duration(s.StabilizationSeconds) * time.Second,
			BootLifetime:  time.Duration(s.OfflineBootSeconds) * time.Second,
		}
		peers, routes = s.RequiredPeers, s.RequiredStaticRoutes
	}
	d.Activator.Health = d.health(peers, routes)
	if r := dep.Spec.Recovery; r != nil {
		req.Recovery = activation.Recovery{
			TargetDigest: r.TargetDependencyDigest, RevokedPrefixes: r.RevokedPrefixes, Retired: r.Retired,
		}
		for _, c := range r.RevokedCredentials {
			req.Recovery.RevokedCredentials = append(req.Recovery.RevokedCredentials, c.UID)
		}
		if r.TargetRevisionRef != nil {
			req.Recovery.TargetRevision = r.TargetRevisionRef.Name
			// A missing target leaves recovery ineligible, not the
			// activation refused; any other read error refuses it.
			target, err := d.revision(ctx, r.TargetRevisionRef.Name)
			switch {
			case err == nil:
				req.RecoveryRevision = target
			case !apierrors.IsNotFound(err):
				return activation.Request{}, err
			}
		}
	}
	for _, r := range []*networkv1alpha1.FabricRouterRevision{rev, req.RecoveryRevision} {
		if r == nil {
			continue
		}
		for _, p := range r.Spec.Configuration.Peers {
			if ref := p.Spec.AuthSecretRef; ref != nil {
				if r == rev {
					req.RequiresAPI = true
				}
				uid, err := d.secretUID(ctx, ref.Name)
				switch {
				case err == nil:
					req.Credentials[ref.Name] = uid
				case !apierrors.IsNotFound(err):
					return activation.Request{}, fmt.Errorf("read Secret %s: %w", ref.Name, err)
				}
			}
		}
	}
	return req, nil
}

func (d *DeploymentAgent) revision(ctx context.Context, name string) (*networkv1alpha1.FabricRouterRevision, error) {
	var rev networkv1alpha1.FabricRouterRevision
	if err := d.Client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: name}, &rev); err != nil {
		return nil, fmt.Errorf("read revision %s: %w", name, err)
	}
	return &rev, nil
}

func (d *DeploymentAgent) secretUID(ctx context.Context, name string) (string, error) {
	var md metav1.PartialObjectMetadata
	md.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
	if err := d.Client.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: name}, &md); err != nil {
		return "", err
	}
	return string(md.UID), nil
}

// health returns a check that every required peer is Established and every
// required static route is installed.
func (d *DeploymentAgent) health(peers, routes []string) activation.Health {
	return func(ctx context.Context, _ string) error {
		if len(peers) > 0 {
			out, err := d.BGP.Neighbors(ctx)
			if err != nil {
				return fmt.Errorf("read BGP neighbors: %w", err)
			}
			if err := requirePeers(out, peers); err != nil {
				return err
			}
		}
		if len(routes) > 0 {
			return d.requireRoutes(ctx, routes)
		}
		return nil
	}
}

func requirePeers(out []byte, peers []string) error {
	neighbors, err := parseNeighbors(out)
	if err != nil {
		return fmt.Errorf("parse BGP neighbors: %w", err)
	}
	state := map[string]string{}
	for _, n := range neighbors {
		if a, err := netip.ParseAddr(n.Peer); err == nil {
			state[a.String()] = n.BGPState
		}
	}
	var down []string
	for _, p := range peers {
		a, err := netip.ParseAddr(p)
		if err != nil || state[a.String()] != stateEstablished {
			down = append(down, p)
		}
	}
	if len(down) > 0 {
		return fmt.Errorf("required peers not Established: %s", strings.Join(down, ", "))
	}
	return nil
}

func (d *DeploymentAgent) requireRoutes(ctx context.Context, routes []string) error {
	installed := map[netip.Prefix]bool{}
	for _, afi := range []string{"ip", "ipv6"} {
		out, err := d.BGP.Routes(ctx, afi)
		if err != nil {
			return fmt.Errorf("read %s routes: %w", afi, err)
		}
		prefixes, err := installedPrefixes(out)
		if err != nil {
			return fmt.Errorf("parse %s routes: %w", afi, err)
		}
		for _, p := range prefixes {
			installed[p] = true
		}
	}
	var missing []string
	for _, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil || !installed[p.Masked()] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required static routes not installed: %s", strings.Join(missing, ", "))
	}
	return nil
}

// report fills status from the journal and checkpoint.
func (d *DeploymentAgent) report(status *networkv1alpha1.FabricRouterDeploymentStatus,
	dep *networkv1alpha1.FabricRouterDeployment) {
	journal := d.Activator.Journal()
	uid := string(dep.UID)
	if high, ok := journal.HighWater(uid); ok {
		status.JournalHighWater = high
	}
	status.Epochs = status.Epochs[:0]
	for _, e := range journal.Epochs(uid, maxEpochStatus) {
		es := networkv1alpha1.FabricEpochStatus{Epoch: e.Epoch, Revision: e.Revision, Stage: stageOf(e.Stage),
			Detail: truncate(e.Detail, 1024)}
		if e.Recovery != nil {
			es.RecoveryTarget = e.Recovery.TargetRevision
			es.RevokedPrefixes = int32(len(e.Recovery.RevokedPrefixes)) //nolint:gosec // bounded by the schema
		}
		if es.Epoch > 0 {
			status.Epochs = append(status.Epochs, es)
		}
	}
	if cp, err := activation.ReadCheckpoint(d.Activator.Dir); err == nil && cp.Activation.DeploymentUID == uid {
		status.AppliedEpoch = cp.Activation.Epoch
		status.AppliedRevision = cp.Activation.Revision
		status.AppliedDigest = cp.Activation.DependencyHash
		until := metav1.NewTime(cp.BootAuthorizedUntil)
		status.BootAuthorizedUntil = &until
		status.RequiresAPI = cp.RequiresAPI
	}
	if status.EffectiveSource == networkv1alpha1.FabricConfigSourceCRD && dep.Spec.ActivationEpoch > 0 &&
		status.AppliedEpoch == dep.Spec.ActivationEpoch && status.AppliedRevision == dep.Spec.ActiveRevisionRef.Name &&
		d.inSync {
		setCondition(status, dep, networkv1alpha1.FabricConditionReady, metav1.ConditionTrue,
			networkv1alpha1.FabricReasonCommitted,
			"the active revision is committed")
	} else {
		setCondition(status, dep, networkv1alpha1.FabricConditionReady, metav1.ConditionFalse,
			networkv1alpha1.FabricReasonWaitingForPromotion,
			"the active revision is not committed")
	}
}

// writeStatus writes status onto the deployment as it is now, with
// optimistic locking; the agent owns the whole status. An unchanged status
// is written only every heartbeatInterval.
func (d *DeploymentAgent) writeStatus(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	status *networkv1alpha1.FabricRouterDeploymentStatus) error {
	if d.written != nil && statusEqual(*d.written, *status) && d.written.HeartbeatTime != nil &&
		d.now().Sub(d.written.HeartbeatTime.Time) < heartbeatInterval {
		return nil
	}
	now := metav1.NewTime(d.now())
	status.HeartbeatTime = &now
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current networkv1alpha1.FabricRouterDeployment
		if err := d.Client.Get(ctx, client.ObjectKeyFromObject(dep), &current); err != nil {
			return err
		}
		if current.UID != dep.UID {
			// Deleted and recreated since it was read: not this one.
			return nil
		}
		updated := current.DeepCopy()
		updated.Status = *status
		patch := client.MergeFromWithOptions(&current, client.MergeFromWithOptimisticLock{})
		return d.Client.Status().Patch(ctx, updated, patch)
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err == nil {
		d.written = status.DeepCopy()
	}
	return err
}

// statusEqual compares two statuses ignoring the heartbeat and condition
// transition times.
func statusEqual(a, b networkv1alpha1.FabricRouterDeploymentStatus) bool {
	a.HeartbeatTime, b.HeartbeatTime = nil, nil
	for _, s := range []*networkv1alpha1.FabricRouterDeploymentStatus{&a, &b} {
		s.Conditions = slices.Clone(s.Conditions)
		for i := range s.Conditions {
			s.Conditions[i].LastTransitionTime = metav1.Time{}
		}
	}
	return equality.Semantic.DeepEqual(a, b)
}

// JournalSource is the journal's source, ConfigMap when it records none.
func JournalSource(j *activation.Journal) networkv1alpha1.FabricConfigSource {
	if s := j.Source(); s != "" {
		return networkv1alpha1.FabricConfigSource(s)
	}
	return networkv1alpha1.FabricConfigSourceConfigMap
}

func stageOf(t activation.RecordType) networkv1alpha1.FabricActivationStage {
	switch t {
	case activation.RecordAccepted:
		return networkv1alpha1.FabricStageAccepted
	case activation.RecordApplied:
		return networkv1alpha1.FabricStageApplied
	case activation.RecordApplyFailed:
		return networkv1alpha1.FabricStageApplyFailed
	case activation.RecordCommitted:
		return networkv1alpha1.FabricStageCommitted
	case activation.RecordRecovered:
		return networkv1alpha1.FabricStageRecovered
	}
	return networkv1alpha1.FabricStageDegraded
}

func activationReason(err error) string {
	switch {
	case errors.Is(err, activation.ErrStale):
		return networkv1alpha1.FabricReasonStaleActivation
	case errors.Is(err, activation.ErrFailedEpoch):
		return networkv1alpha1.FabricReasonFailedEpoch
	case errors.Is(err, activation.ErrDigestMismatch):
		return networkv1alpha1.FabricReasonDigestMismatch
	case errors.Is(err, activation.ErrRecoveryConflict), errors.Is(err, activation.ErrIdentityMismatch):
		return networkv1alpha1.FabricReasonRecoveryConflict
	}
	return reasonRejected
}

func setCondition(status *networkv1alpha1.FabricRouterDeploymentStatus, dep *networkv1alpha1.FabricRouterDeployment,
	condType string, s metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: condType, Status: s, Reason: reason, Message: truncate(msg, 32768), ObservedGeneration: dep.Generation,
	})
}

func prefixed(p string, lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, p+l)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// installedPrefixes lists the prefixes in `show ip[v6] route json` with an
// installed route.
func installedPrefixes(out []byte) ([]netip.Prefix, error) {
	var prefixes map[string][]zebraRoute
	if err := json.Unmarshal(out, &prefixes); err != nil {
		return nil, err
	}
	var installed []netip.Prefix
	for k, routes := range prefixes {
		p, err := netip.ParsePrefix(k)
		if err != nil {
			continue
		}
		if slices.ContainsFunc(routes, func(r zebraRoute) bool { return r.Installed }) {
			installed = append(installed, p.Masked())
		}
	}
	return installed, nil
}

// ErrNotActivated means the node never accepted an activation and holds no
// checkpoint, so although its journal records the CRD source it has nothing
// of its own to start from: it starts from its ConfigMap.
var ErrNotActivated = errors.New("no activation accepted yet")

// BootConfig chooses the configuration a node on the CRD source starts FRR
// with: the checkpoint when boot may restore it offline; with the API, the
// checkpoint again when the deployment is bound to the journal and nothing
// since forbids it; otherwise the active revision, verified, authorized
// and allowed by the journal and the deployment's recovery authorization
// (not retired, originating no revoked prefix and using no revoked
// credential). It records which of the three in Booted. It
// returns ErrNotActivated for a node with nothing activated yet, and an
// error when nothing may start yet.
//
// With ConfigMapsRetired a node with nothing activated, whether its journal
// records CRD or no source at all, starts from its deployment's active
// revision under the same checks, its deployment on CRD and its release
// Started, or Unknown since the node has never reported; until it may, the
// error wraps ErrNotActivated. A journal recording another source returns
// a fatal error wrapping ErrConfigMapsRetired: only a node on CRD may start.
func (d *DeploymentAgent) BootConfig(ctx context.Context, machineID string) (config, reason string, err error) {
	fresh := !d.Activator.Activated()
	if d.ConfigMapsRetired {
		if src := d.Activator.Journal().Source(); src != "" && src != string(networkv1alpha1.FabricConfigSourceCRD) {
			return "", "", fatal(fmt.Errorf("%w: node %s's journal records the %s source, and only a node on CRD may "+
				"start", ErrConfigMapsRetired, d.NodeName, src))
		}
	} else if fresh {
		return "", "", ErrNotActivated
	}
	if d.IdentityErr != nil {
		return "", "", d.IdentityErr
	}
	config, reason, err = d.bootConfig(ctx, machineID, fresh)
	if err != nil && fresh {
		return "", "", fmt.Errorf("%w on node %s, and with its ConfigMap retired it starts only from its "+
			"deployment's active revision: %w", ErrNotActivated, d.NodeName, err)
	}
	return config, reason, err
}

// bootConfig is BootConfig past its source and identity checks. fresh is a
// node with nothing activated, which needs its deployment on CRD and is the
// only one a release whose outcome is Unknown authorizes.
func (d *DeploymentAgent) bootConfig(ctx context.Context, machineID string, fresh bool) (config, reason string,
	err error) {
	id := activation.Identity{MachineID: machineID, NodeUID: d.NodeUID, ClusterID: d.ClusterID}
	decision := d.Activator.Boot(id)
	if decision.Apply != "" {
		d.Booted = BootCheckpointOffline
		return decision.Apply, decision.Reason, nil
	}
	dep, err := d.find(ctx)
	if err != nil {
		return "", "", fmt.Errorf("%s; %w", decision.Reason, err)
	}
	if dep == nil {
		return "", "", fmt.Errorf("%s; node %s has no deployment", decision.Reason, d.NodeName)
	}
	if fresh && dep.Spec.Source != networkv1alpha1.FabricConfigSourceCRD {
		return "", "", fmt.Errorf("%s; deployment %s is on the %s source, not CRD", decision.Reason, dep.Name,
			dep.Spec.Source)
	}
	if d.Activator.Journal().BoundDeployment() == string(dep.UID) {
		if online := d.Activator.BootOnline(id); online.Apply != "" {
			d.Booted = BootCheckpointOnline
			return online.Apply, online.Reason + " with the API", nil
		}
	}
	if dep.Spec.ActivationEpoch == 0 {
		return "", "", fmt.Errorf("%s; node %s has no active revision", decision.Reason, d.NodeName)
	}
	if err := d.authorizedIn(ctx, dep, fresh); err != nil {
		if _, accepted := d.Activator.Journal().Accepted(string(dep.UID), dep.Spec.ActivationEpoch); !accepted {
			return "", "", fmt.Errorf("%s; %w", decision.Reason, err)
		}
	}
	act := activation.Activation{
		ClusterID: d.ClusterID, NodeUID: d.NodeUID, DeploymentUID: string(dep.UID), Epoch: dep.Spec.ActivationEpoch,
		Revision: dep.Spec.ActiveRevisionRef.Name, DependencyHash: dep.Spec.ActivationDependencyDigest,
	}
	req, err := d.request(ctx, dep, act)
	if err != nil {
		return "", "", err
	}
	if err := d.Activator.StartAllowed(act, req.Revision, req.Credentials, req.Recovery); err != nil {
		return "", "", fmt.Errorf("%s; %w", decision.Reason, err)
	}
	res, err := revision.Verify(req.Revision)
	if err != nil {
		return "", "", err
	}
	d.Booted = BootActiveRevision
	return res.Config, fmt.Sprintf("%s; starting from active revision %s at epoch %d",
		decision.Reason, req.Revision.Name, dep.Spec.ActivationEpoch), nil
}
