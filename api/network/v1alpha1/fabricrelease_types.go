// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FabricReleaseType is what a release authorizes.
//
// +kubebuilder:validation:Enum=Release;EmergencyWithdrawal
type FabricReleaseType string

const (
	// FabricReleaseTypeRelease authorizes ordinary promotions.
	FabricReleaseTypeRelease FabricReleaseType = "Release"
	// FabricReleaseTypeEmergencyWithdrawal authorizes only revisions that
	// withdraw the named originations, and may be issued while a release
	// is outstanding.
	FabricReleaseTypeEmergencyWithdrawal FabricReleaseType = "EmergencyWithdrawal"
)

// FabricReleasePhase is a release's progress.
//
// +kubebuilder:validation:Enum=Pending;Started;Completed;Failed;Cancelled;Unknown
type FabricReleasePhase string

const (
	FabricReleasePhasePending   FabricReleasePhase = "Pending"
	FabricReleasePhaseStarted   FabricReleasePhase = "Started"
	FabricReleasePhaseCompleted FabricReleasePhase = "Completed"
	FabricReleasePhaseFailed    FabricReleasePhase = "Failed"
	FabricReleasePhaseCancelled FabricReleasePhase = "Cancelled"
	FabricReleasePhaseUnknown   FabricReleasePhase = "Unknown"
)

// FabricReleaseAuthorization permits the rollout manager to promote named
// revisions in this cell, as part of one fleet release. Its spec is
// immutable. Within a routing domain at most one authorization is
// outstanding at a time, and fleet sequences only rise: the controller
// enforces that within a cell, keeping an outstanding authorization with a
// finalizer, and the fleet release tool across cells.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=frauth
// +kubebuilder:printcolumn:name="TYPE",type="string",JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="RELEASE",type="string",JSONPath=".spec.fleetReleaseID"
// +kubebuilder:printcolumn:name="SEQUENCE",type="integer",JSONPath=".spec.fleetSequence"
// +kubebuilder:printcolumn:name="PHASE",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type FabricReleaseAuthorization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   FabricReleaseAuthorizationSpec   `json:"spec"`
	Status FabricReleaseAuthorizationStatus `json:"status,omitempty"`
}

// FabricReleaseAuthorizationSpec is what a release permits.
//
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="a release authorization is immutable"
// +kubebuilder:validation:XValidation:rule="(self.type == 'EmergencyWithdrawal') == (has(self.withdrawnPrefixes) && size(self.withdrawnPrefixes) > 0)",message="an emergency withdrawal names the prefixes it withdraws, and only it does"
type FabricReleaseAuthorizationSpec struct {
	// Type is Release or EmergencyWithdrawal.
	Type FabricReleaseType `json:"type"`

	// RoutingDomain is the fabric the release belongs to.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	RoutingDomain string `json:"routingDomain"`

	// FleetReleaseID identifies the release across cells.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	FleetReleaseID string `json:"fleetReleaseID"`

	// FleetSequence orders releases in the routing domain.
	// +kubebuilder:validation:Minimum=1
	FleetSequence int64 `json:"fleetSequence"`

	// Deployments lists each deployment, revision and digest the release
	// may activate.
	// +listType=map
	// +listMapKey=deployment
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	Deployments []FabricReleaseTarget `json:"deployments"`

	// WithdrawnPrefixes are the originations an EmergencyWithdrawal
	// removes; its revisions may change nothing else.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(p, isCIDR(p))",message="withdrawn prefixes are prefixes"
	WithdrawnPrefixes []string `json:"withdrawnPrefixes,omitempty"`

	// FailureDomains are the failure domains the release touches.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=63
	FailureDomains []string `json:"failureDomains,omitempty"`

	// InputManifest pins the inputs of a release that changes several
	// mutable objects; a candidate whose inputs differ is not promoted.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=4096
	InputManifest []FabricRevisionInput `json:"inputManifest,omitempty"`

	// StartDeadline is the last time the release may start. Passing it
	// stops a start; it never ends a release whose outcome is unknown.
	// +optional
	StartDeadline *metav1.Time `json:"startDeadline,omitempty"`
}

// FabricReleaseTarget is one deployment a release may activate.
type FabricReleaseTarget struct {
	// Deployment is the FabricRouterDeployment's name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Deployment string `json:"deployment"`
	// DeploymentUID is its UID, so a recreated deployment is not covered.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	DeploymentUID string `json:"deploymentUID"`
	// Revision is the FabricRouterRevision to activate.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Revision string `json:"revision"`
	// ActivationDependencyDigest is that revision's digest.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	ActivationDependencyDigest string `json:"activationDependencyDigest"`
	// Retire decommissions the router with this promotion: its revision
	// is the last it runs, nothing is restored over it and no later
	// release promotes it.
	// +optional
	Retire bool `json:"retire,omitempty"`
	// Reactivate promotes the revision as a new epoch even when the
	// deployment already reports it committed, so a node that lost its
	// state starts from it again. Without it such a target counts as
	// committed at once and nothing is promoted. The promotion passes
	// every check an ordinary one does; its recovery target is the one
	// the deployment already has, never the revision itself.
	// +optional
	Reactivate bool `json:"reactivate,omitempty"`
}

// FabricReleaseAuthorizationStatus is a release's progress.
//
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || !(self.phase in ['Started', 'Completed', 'Failed']) || has(self.startedAt)",message="a started release records when it started"
// +kubebuilder:validation:XValidation:rule="!has(self.recoveryVerified) || !self.recoveryVerified || (has(self.phase) && self.phase == 'Failed')",message="only a failed release verifies recovery"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.recoveryVerified) || !oldSelf.recoveryVerified || (has(self.recoveryVerified) && self.recoveryVerified)",message="verified recovery stays verified"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.phase) ? (!has(self.phase) || self.phase in ['Pending', 'Started']) : (has(self.phase) && (self.phase == oldSelf.phase || (oldSelf.phase == 'Pending' && self.phase in ['Started', 'Cancelled']) || (oldSelf.phase == 'Started' && self.phase in ['Completed', 'Failed', 'Unknown']) || (oldSelf.phase == 'Unknown' && self.phase in ['Started', 'Completed', 'Failed'])))",message="a release moves only forward: Pending to Started or Cancelled, Started to Completed, Failed or Unknown, Unknown to a known phase"
type FabricReleaseAuthorizationStatus struct {
	// Phase is the release's progress. A release is outstanding while
	// Pending, Started or Unknown.
	// +optional
	Phase FabricReleasePhase `json:"phase,omitempty"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	FinishedAt *metav1.Time `json:"finishedAt,omitempty"`
	// RecoveryVerified is set on a Failed release once every touched
	// router is confirmed back on its recovery target.
	// +optional
	RecoveryVerified bool `json:"recoveryVerified,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Outstanding reports whether the release still blocks another in its
// routing domain.
func (s FabricReleaseAuthorizationStatus) Outstanding() bool {
	switch s.Phase {
	case FabricReleasePhaseCompleted, FabricReleasePhaseCancelled:
		return false
	case FabricReleasePhaseFailed:
		return !s.RecoveryVerified
	}
	return true
}

// FabricReleaseAuthorizationList is a list of FabricReleaseAuthorization resources.
// +kubebuilder:object:root=true
type FabricReleaseAuthorizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricReleaseAuthorization `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FabricReleaseAuthorization{}, &FabricReleaseAuthorizationList{})
}
