// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FabricConfigSource names which writer owns a node's FRR configuration.
//
// +kubebuilder:validation:Enum=ConfigMap;Shadow;CRD
type FabricConfigSource string

const (
	// FabricConfigSourceConfigMap applies the node's rendered ConfigMap.
	FabricConfigSourceConfigMap FabricConfigSource = "ConfigMap"
	// FabricConfigSourceShadow applies the ConfigMap and stages the typed
	// revision beside it, reporting the difference without writing it.
	FabricConfigSourceShadow FabricConfigSource = "Shadow"
	// FabricConfigSourceCRD applies the active FabricRouterRevision.
	FabricConfigSourceCRD FabricConfigSource = "CRD"
)

// Deployment condition types the node agent reports.
const (
	FabricConditionAccepted         = "Accepted"
	FabricConditionStaged           = "Staged"
	FabricConditionProgrammed       = "Programmed"
	FabricConditionReady            = "Ready"
	FabricConditionDegraded         = "Degraded"
	FabricConditionRecoveryConflict = "RecoveryConflict"
	FabricConditionBootstrapping    = "Bootstrapping"
)

// Deployment condition reasons the node agent reports.
const (
	FabricReasonStaleActivation    = "StaleActivation"
	FabricReasonFailedEpoch        = "FailedEpoch"
	FabricReasonDigestMismatch     = "DigestMismatch"
	FabricReasonNoEligibleRecovery = "NoEligibleRecovery"
	FabricReasonRecoveryTargetUsed = "RecoveryTargetUsed"
	FabricReasonRecoveryConflict   = "RecoveryConflict"
	FabricReasonCommitted          = "Committed"
)

// FabricRouterDeployment is the single activation point of one fabric
// router: the revision a node agent stages and the revision it runs. The
// rollout manager writes its spec and promotes a revision by raising the
// activation epoch together with the active revision, its digest, the
// release it is promoted under, the activation settings and the recovery
// authorization, in one update; the node agent writes its status. It is
// named after the router, and created at epoch zero.
//
// Admission checks the shape of a promotion, not that its authorization
// exists and covers this deployment, revision and digest: the rollout
// manager checks that before writing, and the node agent again before
// applying.
//
// The agent binds its journal to the deployment's UID. Deleting and
// recreating a deployment does not reset its epochs: the agent refuses the
// new UID with RecoveryConflict until spec.rebind names the old one.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=frdep
// +kubebuilder:printcolumn:name="NODE",type="string",JSONPath=".spec.target.nodeName"
// +kubebuilder:printcolumn:name="SOURCE",type="string",JSONPath=".spec.source"
// +kubebuilder:printcolumn:name="ACTIVE",type="string",JSONPath=".spec.activeRevisionRef.name"
// +kubebuilder:printcolumn:name="EPOCH",type="integer",JSONPath=".spec.activationEpoch"
// +kubebuilder:printcolumn:name="APPLIED",type="string",JSONPath=".status.appliedRevision"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.routerRef.name",message="a deployment is named after its router"
type FabricRouterDeployment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   FabricRouterDeploymentSpec   `json:"spec"`
	Status FabricRouterDeploymentStatus `json:"status,omitempty"`
}

// FabricRouterDeploymentSpec is what the rollout manager asks of a node.
//
// Rules that hold on every write:
// +kubebuilder:validation:XValidation:rule="has(self.activeRevisionRef) == has(self.activationDependencyDigest)",message="the active revision and its digest are set together"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch == 0 ? !has(self.activeRevisionRef) : (has(self.activeRevisionRef) && has(self.authorizationRef) && has(self.activation))",message="an epoch above zero names the active revision, its authorization and its activation settings; epoch zero has no active revision"
// +kubebuilder:validation:XValidation:rule="!has(self.activeRevisionRef) || !has(self.activationDependencyDigest) || self.activeRevisionRef.name.endsWith('-' + self.activationDependencyDigest.substring(0, 10))",message="the active revision's name carries its digest"
// +kubebuilder:validation:XValidation:rule="!has(self.sourceHandoff) || self.source == 'ConfigMap'",message="sourceHandoff applies only to the ConfigMap source"
// +kubebuilder:validation:XValidation:rule="!has(self.fence) || self.fence.nodeUID != self.target.nodeUID",message="the fence names the node the router left, not its target"
// +kubebuilder:validation:XValidation:rule="!has(self.recovery) || !has(self.recovery.targetRevisionRef) || !has(self.activeRevisionRef) || self.recovery.targetRevisionRef.name != self.activeRevisionRef.name",message="the recovery target is not the revision it recovers from"
// Transition rules:
// +kubebuilder:validation:XValidation:rule="oldSelf.hasValue() || self.activationEpoch == 0",message="a deployment is created at epoch zero",optionalOldSelf=true
// +kubebuilder:validation:XValidation:rule="self.routerRef == oldSelf.routerRef",message="routerRef is immutable"
// +kubebuilder:validation:XValidation:rule="self.target == oldSelf.target || (has(self.fence) && self.fence.nodeUID == oldSelf.target.nodeUID)",message="the router moves to another node only after its current node is fenced"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch == oldSelf.activationEpoch || self.activationEpoch == oldSelf.activationEpoch + 1",message="activationEpoch rises by one per promotion"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch != oldSelf.activationEpoch || (has(self.activeRevisionRef) ? (has(oldSelf.activeRevisionRef) && self.activeRevisionRef == oldSelf.activeRevisionRef) : !has(oldSelf.activeRevisionRef))",message="activeRevisionRef changes only with a new epoch"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch != oldSelf.activationEpoch || (has(self.activationDependencyDigest) ? (has(oldSelf.activationDependencyDigest) && self.activationDependencyDigest == oldSelf.activationDependencyDigest) : !has(oldSelf.activationDependencyDigest))",message="activationDependencyDigest changes only with a new epoch"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch != oldSelf.activationEpoch || (has(self.authorizationRef) ? (has(oldSelf.authorizationRef) && self.authorizationRef == oldSelf.authorizationRef) : !has(oldSelf.authorizationRef))",message="authorizationRef changes only with a new epoch"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch != oldSelf.activationEpoch || (has(self.activation) ? (has(oldSelf.activation) && self.activation == oldSelf.activation) : !has(oldSelf.activation))",message="activation changes only with a new epoch"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch != oldSelf.activationEpoch || (has(self.recovery) ? (has(oldSelf.recovery) && self.recovery == oldSelf.recovery) : !has(oldSelf.recovery))",message="recovery changes only with a new epoch"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch == oldSelf.activationEpoch || (oldSelf.source == 'CRD' && self.source == 'CRD' && !(has(self.suspended) && self.suspended))",message="a promotion needs a deployment already on the CRD source and unsuspended"
// +kubebuilder:validation:XValidation:rule="self.activationEpoch == oldSelf.activationEpoch || !has(oldSelf.recovery) || !has(oldSelf.recovery.retired) || !oldSelf.recovery.retired",message="a retired router is not promoted after its retiring epoch"
// +kubebuilder:validation:XValidation:rule="self.target == oldSelf.target || self.activationEpoch == oldSelf.activationEpoch",message="a move to another node and a promotion are separate updates"
// +kubebuilder:validation:XValidation:rule="oldSelf.source != 'CRD' || self.source == 'CRD' || (self.source == 'ConfigMap' && has(self.sourceHandoff))",message="a node leaves the CRD source only for its ConfigMap, naming the ConfigMap version"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.recovery) || !has(oldSelf.recovery.revokedPrefixes) || (has(self.recovery) && has(self.recovery.revokedPrefixes) && oldSelf.recovery.revokedPrefixes.all(p, p in self.recovery.revokedPrefixes))",message="revoked prefixes stay revoked"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.recovery) || !has(oldSelf.recovery.revokedCredentials) || (has(self.recovery) && has(self.recovery.revokedCredentials) && oldSelf.recovery.revokedCredentials.all(c, self.recovery.revokedCredentials.exists(n, n.uid == c.uid)))",message="revoked credentials stay revoked"
type FabricRouterDeploymentSpec struct {
	// RouterRef is the BGPRouter this deployment activates.
	RouterRef FabricObjectIdentity `json:"routerRef"`

	// Target is the Node the router runs on, by name and UID.
	Target FabricNodeIdentity `json:"target"`

	// Source is the writer of the node's FRR configuration. Once a node is
	// on CRD it returns only to ConfigMap, with sourceHandoff.
	// +kubebuilder:default=ConfigMap
	Source FabricConfigSource `json:"source"`

	// SourceHandoff names the ConfigMap version the agent verifies before
	// handing the node back from CRD to ConfigMap.
	// +optional
	SourceHandoff *FabricSourceHandoff `json:"sourceHandoff,omitempty"`

	// CandidateRevisionRef is the revision the agent stages and validates
	// without applying.
	// +optional
	CandidateRevisionRef *LocalObjectRef `json:"candidateRevisionRef,omitempty"`

	// ActiveRevisionRef is the revision the agent applies at
	// activationEpoch.
	// +optional
	ActiveRevisionRef *LocalObjectRef `json:"activeRevisionRef,omitempty"`

	// ActivationEpoch numbers promotions. It rises by one with each new
	// active revision, and a retry of the same revision is a new epoch.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=9007199254740991
	ActivationEpoch int64 `json:"activationEpoch"`

	// ActivationDependencyDigest is the active revision's digest, so an
	// agent never applies a revision that differs from the one promoted.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	ActivationDependencyDigest string `json:"activationDependencyDigest,omitempty"`

	// AuthorizationRef is the FabricReleaseAuthorization the active epoch
	// was promoted under.
	// +optional
	AuthorizationRef *FabricObjectIdentity `json:"authorizationRef,omitempty"`

	// Activation holds the settings the agent applies the active epoch
	// with, copied from the router's rollout policy at promotion so the
	// agent needs nothing else.
	// +optional
	Activation *FabricActivationSettings `json:"activation,omitempty"`

	// Recovery is what the agent may restore, and what it must never
	// restore, if this activation fails. It changes only with the epoch.
	// +optional
	Recovery *FabricRecovery `json:"recovery,omitempty"`

	// Fence records that the router's previous node was cut off from the
	// fabric, which moving the router to another node requires.
	// +optional
	Fence *FabricFence `json:"fence,omitempty"`

	// Rebind lets the agent accept this deployment although its journal is
	// bound to another deployment UID, after an operator confirmed that
	// deployment is gone for good.
	// +optional
	Rebind *FabricRebind `json:"rebind,omitempty"`

	// Suspended stops promotion; the agent keeps running what it has.
	// +optional
	Suspended bool `json:"suspended,omitempty"`
}

// FabricObjectIdentity names an object by name and UID.
type FabricObjectIdentity struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	UID string `json:"uid"`
}

// FabricNodeIdentity names a Node by name and UID.
type FabricNodeIdentity struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	NodeName string `json:"nodeName"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	NodeUID string `json:"nodeUID"`
}

// FabricSourceHandoff names the ConfigMap version a node returns to.
type FabricSourceHandoff struct {
	// ConfigMap is the node's per-node ConfigMap, by name and UID.
	ConfigMap FabricObjectIdentity `json:"configMap"`
	// ResourceVersion is the ConfigMap version the agent may apply.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	ResourceVersion string `json:"resourceVersion"`
}

// FabricActivationSettings are the rollout policy's settings for one
// epoch, resolved by the rollout manager.
type FabricActivationSettings struct {
	// StabilizationSeconds is how long an applied revision must stay
	// healthy before the agent commits it.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	StabilizationSeconds int32 `json:"stabilizationSeconds"`

	// ApplyTimeoutSeconds bounds one reload.
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=900
	ApplyTimeoutSeconds int32 `json:"applyTimeoutSeconds"`

	// OfflineBootSeconds is how long the committed configuration may be
	// restored at boot without the API.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=7776000
	OfflineBootSeconds int64 `json:"offlineBootSeconds"`

	// RequiredPeers are the peer addresses that must reach Established
	// for the activation to count as healthy.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="self.all(a, isIP(a))",message="required peers are IP addresses"
	RequiredPeers []string `json:"requiredPeers,omitempty"`

	// RequiredStaticRoutes are the prefixes that must be in the FIB.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(p, isCIDR(p))",message="required static routes are prefixes"
	RequiredStaticRoutes []string `json:"requiredStaticRoutes,omitempty"`
}

// FabricRecovery is what a failed activation may fall back to.
//
// +kubebuilder:validation:XValidation:rule="has(self.targetRevisionRef) == has(self.targetDependencyDigest)",message="a recovery target names its digest"
// +kubebuilder:validation:XValidation:rule="!has(self.targetRevisionRef) || !has(self.targetDependencyDigest) || self.targetRevisionRef.name.endsWith('-' + self.targetDependencyDigest.substring(0, 10))",message="the recovery target's name carries its digest"
type FabricRecovery struct {
	// TargetRevisionRef is the revision the agent restores on a confirmed
	// failure of this activation. Unset means no rollback: the agent
	// reports NoEligibleRecovery.
	// +optional
	TargetRevisionRef *LocalObjectRef `json:"targetRevisionRef,omitempty"`

	// TargetDependencyDigest is the recovery target's digest.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	TargetDependencyDigest string `json:"targetDependencyDigest,omitempty"`

	// RevokedPrefixes are prefixes no recovery target may originate. They
	// can be added, never removed.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(p, isCIDR(p))",message="revoked prefixes are prefixes"
	RevokedPrefixes []string `json:"revokedPrefixes,omitempty"`

	// RevokedCredentials are Secrets no recovery target may use. They can
	// be added, never removed.
	// +optional
	// +listType=map
	// +listMapKey=uid
	// +kubebuilder:validation:MaxItems=32
	RevokedCredentials []FabricObjectIdentity `json:"revokedCredentials,omitempty"`

	// Retired means the router is decommissioned; no revision may be
	// restored. It is set with the router's last promotion, which usually
	// withdraws everything. Since a retired router is never promoted again
	// and recovery changes only with a promotion, it cannot be cleared.
	// +optional
	Retired bool `json:"retired,omitempty"`
}

// FabricFence records that a node was cut off from the fabric.
type FabricFence struct {
	// NodeUID is the fenced node.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	NodeUID string `json:"nodeUID"`
	// Method is how it was fenced, such as a switch port shutdown.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Method string `json:"method"`
	// FencedBy is who confirmed it.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	FencedBy string `json:"fencedBy"`
	// FencedAt is when.
	FencedAt metav1.Time `json:"fencedAt"`
}

// FabricRebind approves accepting this deployment over a journal bound to
// another deployment UID.
type FabricRebind struct {
	// FromDeploymentUID is the deployment UID the agent's journal is bound
	// to; the agent rebinds only when it matches.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	FromDeploymentUID string `json:"fromDeploymentUID"`
	// ApprovedBy is who confirmed the old deployment is gone.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ApprovedBy string `json:"approvedBy"`
	// ApprovedAt is when.
	ApprovedAt metav1.Time `json:"approvedAt"`
}

// FabricChangeClass classifies what applying a candidate would disturb.
//
// +kubebuilder:validation:Enum=NoChange;NonDisruptive;SessionReset;RestartRequired
type FabricChangeClass string

const (
	FabricChangeNone            FabricChangeClass = "NoChange"
	FabricChangeNonDisruptive   FabricChangeClass = "NonDisruptive"
	FabricChangeSessionReset    FabricChangeClass = "SessionReset"
	FabricChangeRestartRequired FabricChangeClass = "RestartRequired"
)

// FabricActivationStage is the last journaled stage of an epoch.
//
// +kubebuilder:validation:Enum=Accepted;Applied;ApplyFailed;Committed;Recovered;Degraded
type FabricActivationStage string

const (
	FabricStageAccepted    FabricActivationStage = "Accepted"
	FabricStageApplied     FabricActivationStage = "Applied"
	FabricStageApplyFailed FabricActivationStage = "ApplyFailed"
	FabricStageCommitted   FabricActivationStage = "Committed"
	FabricStageRecovered   FabricActivationStage = "Recovered"
	FabricStageDegraded    FabricActivationStage = "Degraded"
)

// FabricRouterDeploymentStatus is what the node agent observed.
type FabricRouterDeploymentStatus struct {
	// ObservedGeneration is the spec generation the agent acted on.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// EffectiveSource is the writer the agent is actually honouring.
	// +optional
	EffectiveSource FabricConfigSource `json:"effectiveSource,omitempty"`

	// BoundDeploymentUID is the deployment UID the agent's journal is bound
	// to; a different UID here than the object's own is a RecoveryConflict.
	// +optional
	// +kubebuilder:validation:MaxLength=36
	BoundDeploymentUID string `json:"boundDeploymentUID,omitempty"`

	// ClusterID is the cluster the agent's state is bound to.
	// +optional
	// +kubebuilder:validation:MaxLength=36
	ClusterID string `json:"clusterID,omitempty"`

	// Staged reports the candidate the agent validated without applying.
	// +optional
	Staged *FabricStagedRevision `json:"staged,omitempty"`

	// AppliedEpoch, AppliedRevision and AppliedDigest are the last
	// activation the agent committed.
	// +optional
	AppliedEpoch int64 `json:"appliedEpoch,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	AppliedRevision string `json:"appliedRevision,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9a-f]{64})?$`
	AppliedDigest string `json:"appliedDigest,omitempty"`

	// JournalHighWater is the highest epoch the agent's journal accepted
	// for this deployment UID.
	// +optional
	JournalHighWater int64 `json:"journalHighWater,omitempty"`

	// Epochs reports the journal's last stage for the most recent epochs,
	// newest first, so the rollout manager knows a failed epoch is spent.
	// +optional
	// +listType=map
	// +listMapKey=epoch
	// +kubebuilder:validation:MaxItems=16
	Epochs []FabricEpochStatus `json:"epochs,omitempty"`

	// BootAuthorizedUntil is when the committed configuration stops being
	// restorable at boot without the API.
	// +optional
	BootAuthorizedUntil *metav1.Time `json:"bootAuthorizedUntil,omitempty"`

	// RequiresAPI means the committed configuration has sessions that need
	// credentials from the API and are not restored offline.
	// +optional
	RequiresAPI bool `json:"requiresAPI,omitempty"`

	// HeartbeatTime is the agent's last report.
	// +optional
	HeartbeatTime *metav1.Time `json:"heartbeatTime,omitempty"`

	// AgentVersion is the reporting agent's build.
	// +optional
	// +kubebuilder:validation:MaxLength=64
	AgentVersion string `json:"agentVersion,omitempty"`

	// Conditions are Accepted, Staged, Programmed, Ready, Degraded,
	// RecoveryConflict and Bootstrapping.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FabricEpochStatus is one epoch's journaled outcome.
type FabricEpochStatus struct {
	// +kubebuilder:validation:Minimum=1
	Epoch int64 `json:"epoch"`
	// +kubebuilder:validation:MaxLength=253
	Revision string                `json:"revision"`
	Stage    FabricActivationStage `json:"stage"`
	// RecoveryTarget is the recovery target journaled with the epoch.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	RecoveryTarget string `json:"recoveryTarget,omitempty"`
	// RevokedPrefixes counts the revoked prefixes journaled with it.
	// +optional
	RevokedPrefixes int32 `json:"revokedPrefixes,omitempty"`
	// Detail explains a failure.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Detail string `json:"detail,omitempty"`
}

// FabricStagedRevision is a validated, unapplied candidate.
type FabricStagedRevision struct {
	// Revision is the candidate's name.
	// +kubebuilder:validation:MaxLength=253
	Revision string `json:"revision"`
	// Digest is its activation dependency digest.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	Digest string `json:"digest"`
	// Class classifies what applying it would disturb.
	Class FabricChangeClass `json:"class"`
	// LinesAdded and LinesRemoved count the reload's changes.
	LinesAdded   int32 `json:"linesAdded"`
	LinesRemoved int32 `json:"linesRemoved"`
	// Diff is the reload's change list, truncated.
	// +optional
	// +kubebuilder:validation:MaxLength=8192
	Diff string `json:"diff,omitempty"`
	// ValidatedAt is when the agent validated it.
	ValidatedAt metav1.Time `json:"validatedAt"`
}

// FabricRouterDeploymentList is a list of FabricRouterDeployment resources.
// +kubebuilder:object:root=true
type FabricRouterDeploymentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricRouterDeployment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FabricRouterDeployment{}, &FabricRouterDeploymentList{})
}
