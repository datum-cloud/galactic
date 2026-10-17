// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const digestA, digestB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func startActivationAPI(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, 3)
	for _, name := range []string{"fabricrouterdeployments", "fabricreleaseauthorizations", "fabricrolloutpolicies"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "galactic.datumapis.com_"+name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		crds = append(crds, crd)
	}
	env := &envtest.Environment{CRDs: crds}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "fabric"}}); err != nil {
		t.Fatal(err)
	}
	return c
}

func newDeployment(name string) *networkv1alpha1.FabricRouterDeployment {
	return &networkv1alpha1.FabricRouterDeployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fabric", Name: name},
		Spec: networkv1alpha1.FabricRouterDeploymentSpec{
			RouterRef: networkv1alpha1.FabricObjectIdentity{Name: name, UID: "router-uid"},
			Target:    networkv1alpha1.FabricNodeIdentity{NodeName: "node-a", NodeUID: "node-uid"},
			Source:    networkv1alpha1.FabricConfigSourceCRD,
		},
	}
}

// promote raises d to epoch with the revision whose digest is digest,
// setting everything a promotion carries.
func promote(d *networkv1alpha1.FabricRouterDeployment, epoch int64, digest string) {
	d.Spec.ActivationEpoch = epoch
	d.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: d.Name + "-" + digest[:10]}
	d.Spec.ActivationDependencyDigest = digest
	d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: "release-1", UID: "release-uid"}
	d.Spec.Activation = &networkv1alpha1.FabricActivationSettings{
		StabilizationSeconds: 30, ApplyTimeoutSeconds: 60, OfflineBootSeconds: 86400,
	}
}

func fence(nodeUID string) *networkv1alpha1.FabricFence {
	return &networkv1alpha1.FabricFence{NodeUID: nodeUID, Method: "switch port shutdown", FencedBy: "oncall", FencedAt: metav1.Now()}
}

func handoff() *networkv1alpha1.FabricSourceHandoff {
	return &networkv1alpha1.FabricSourceHandoff{
		ConfigMap:       networkv1alpha1.FabricObjectIdentity{Name: "fabric-router.node-a", UID: "cm-uid"},
		ResourceVersion: "12",
	}
}

type deploymentCase struct {
	name string
	// setup runs before the create; mutate before the update. A nil mutate
	// checks the create alone.
	setup   func(*networkv1alpha1.FabricRouterDeployment)
	mutate  func(*networkv1alpha1.FabricRouterDeployment)
	wantErr string
}

// TestDeploymentAdmission: the API itself enforces the activation
// contract's invariants, on create and on every update.
func TestDeploymentAdmission(t *testing.T) {
	c := startActivationAPI(t)
	ctx := context.Background()
	type D = networkv1alpha1.FabricRouterDeployment

	cases := []deploymentCase{
		// Create.
		{name: "created at epoch zero"},
		{name: "created promoted", setup: func(d *D) { promote(d, 1, digestA) }, wantErr: "created at epoch zero"},
		{name: "named after another router", setup: func(d *D) { d.Spec.RouterRef.Name = "other" },
			wantErr: "named after its router"},
		{name: "created with a fence on its target", setup: func(d *D) { d.Spec.Fence = fence("node-uid") },
			wantErr: "not its target"},
		{name: "handoff on a non-ConfigMap source", setup: func(d *D) { d.Spec.SourceHandoff = handoff() },
			wantErr: "only to the ConfigMap source"},

		// Promotion.
		{name: "promotion to epoch 1", mutate: func(d *D) { promote(d, 1, digestA) }},
		{name: "epoch skips ahead", mutate: func(d *D) { promote(d, 2, digestA) }, wantErr: "rises by one"},
		{name: "promotion without a digest", mutate: func(d *D) {
			promote(d, 1, digestA)
			d.Spec.ActivationDependencyDigest = ""
		}, wantErr: "set together"},
		{name: "promotion without an authorization", mutate: func(d *D) {
			promote(d, 1, digestA)
			d.Spec.AuthorizationRef = nil
		}, wantErr: "its authorization"},
		{name: "promotion of a revision not named for its digest", mutate: func(d *D) {
			promote(d, 1, digestA)
			d.Spec.ActiveRevisionRef.Name = "renamed"
		}, wantErr: "carries its digest"},
		{name: "promotion while suspended", setup: func(d *D) { d.Spec.Suspended = true },
			mutate: func(d *D) { promote(d, 1, digestA) }, wantErr: "unsuspended"},
		{name: "promotion on the Shadow source", setup: func(d *D) { d.Spec.Source = networkv1alpha1.FabricConfigSourceShadow },
			mutate: func(d *D) { promote(d, 1, digestA) }, wantErr: "already on the CRD source"},
		{name: "promotion while entering the CRD source", setup: func(d *D) { d.Spec.Source = networkv1alpha1.FabricConfigSourceShadow },
			mutate: func(d *D) {
				d.Spec.Source = networkv1alpha1.FabricConfigSourceCRD
				promote(d, 1, digestA)
			}, wantErr: "already on the CRD source"},
		{name: "active revision at epoch zero", setup: func(d *D) { promote(d, 0, digestA) },
			wantErr: "epoch zero has no active revision"},

		// Identity.
		{name: "router replaced", mutate: func(d *D) { d.Spec.RouterRef.UID = "other" }, wantErr: "routerRef is immutable"},
		{name: "node replaced without a fence", mutate: func(d *D) { d.Spec.Target.NodeUID = "new-node" },
			wantErr: "after its current node is fenced"},
		{name: "node replaced fencing another node", mutate: func(d *D) {
			d.Spec.Target.NodeUID = "new-node"
			d.Spec.Fence = fence("some-node")
		}, wantErr: "after its current node is fenced"},
		{name: "node replaced with a promotion", mutate: func(d *D) {
			d.Spec.Target.NodeUID = "new-node"
			d.Spec.Fence = fence("node-uid")
			promote(d, 1, digestA)
		}, wantErr: "separate updates"},
		{name: "node replaced after a fence", mutate: func(d *D) {
			d.Spec.Target.NodeUID = "new-node"
			d.Spec.Fence = fence("node-uid")
		}},

		// Source.
		{name: "CRD to Shadow", mutate: func(d *D) { d.Spec.Source = networkv1alpha1.FabricConfigSourceShadow },
			wantErr: "leaves the CRD source only for its ConfigMap"},
		{name: "CRD to ConfigMap without a handoff", mutate: func(d *D) { d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap },
			wantErr: "leaves the CRD source only for its ConfigMap"},
		{name: "CRD to ConfigMap with a handoff", mutate: func(d *D) {
			d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
			d.Spec.SourceHandoff = handoff()
		}},

		{name: "candidate staged", mutate: func(d *D) {
			d.Spec.CandidateRevisionRef = &networkv1alpha1.LocalObjectRef{Name: "r-9"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDeployment(strings.ReplaceAll(strings.ToLower(tc.name), " ", "-"))
			if tc.setup != nil {
				tc.setup(d)
			}
			err := c.Create(ctx, d)
			if tc.mutate != nil {
				if err != nil {
					t.Fatalf("create: %v", err)
				}
				tc.mutate(d)
				err = c.Update(ctx, d)
			}
			checkAdmission(t, err, tc.wantErr)
		})
	}

	t.Run("epoch-bound fields", func(t *testing.T) {
		for _, tc := range []deploymentCase{
			{name: "active revision changed within an epoch", mutate: func(d *D) {
				d.Spec.ActiveRevisionRef.Name = "renamed-" + digestA[:10]
			}, wantErr: "activeRevisionRef changes only with a new epoch"},
			{name: "recovery changed within an epoch", mutate: func(d *D) {
				d.Spec.Recovery.Retired = true
			}, wantErr: "recovery changes only with a new epoch"},
			{name: "activation changed within an epoch", mutate: func(d *D) {
				d.Spec.Activation.StabilizationSeconds = 5
			}, wantErr: "activation changes only with a new epoch"},
			{name: "authorization changed within an epoch", mutate: func(d *D) {
				d.Spec.AuthorizationRef.UID = "another"
			}, wantErr: "authorizationRef changes only with a new epoch"},
			{name: "revocation dropped", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery = &networkv1alpha1.FabricRecovery{}
			}, wantErr: "revoked prefixes stay revoked"},
			{name: "credential revocation dropped", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery = &networkv1alpha1.FabricRecovery{RevokedPrefixes: []string{"192.0.2.0/24"}}
			}, wantErr: "revoked credentials stay revoked"},
			{name: "revocation added with the epoch", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery.RevokedPrefixes = append(d.Spec.Recovery.RevokedPrefixes, "198.51.100.0/24")
			}},
			{name: "digest changed within an epoch", mutate: func(d *D) {
				d.Spec.ActivationDependencyDigest = digestB
			}, wantErr: "activationDependencyDigest changes only with a new epoch"},
			{name: "required peer that is no address", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Activation.RequiredPeers = []string{"upstream-1"}
			}, wantErr: "required peers are IP addresses"},
			{name: "required static route that is no prefix", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Activation.RequiredStaticRoutes = []string{"192.0.2.1"}
			}, wantErr: "required static routes are prefixes"},
			{name: "recovery to the active revision", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery.TargetRevisionRef = &networkv1alpha1.LocalObjectRef{Name: d.Spec.ActiveRevisionRef.Name}
				d.Spec.Recovery.TargetDependencyDigest = digestB
			}, wantErr: "not the revision it recovers from"},
			{name: "recovery target not named for its digest", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery.TargetRevisionRef = &networkv1alpha1.LocalObjectRef{Name: "r-1"}
				d.Spec.Recovery.TargetDependencyDigest = digestA
			}, wantErr: "name carries its digest"},
			{name: "recovery to the previous revision", mutate: func(d *D) {
				previous := d.Spec.ActiveRevisionRef.Name
				promote(d, 2, digestB)
				d.Spec.Recovery.TargetRevisionRef = &networkv1alpha1.LocalObjectRef{Name: previous}
				d.Spec.Recovery.TargetDependencyDigest = digestA
			}},
			{name: "retired with its last promotion", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery.Retired = true
			}},
			{name: "recovery target without a digest", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery.TargetRevisionRef = &networkv1alpha1.LocalObjectRef{Name: "r-1"}
			}, wantErr: "names its digest"},
			{name: "revoked prefix that is no prefix", mutate: func(d *D) {
				promote(d, 2, digestB)
				d.Spec.Recovery.RevokedPrefixes = append(d.Spec.Recovery.RevokedPrefixes, "not-a-prefix")
			}, wantErr: "revoked prefixes are prefixes"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				d := newDeployment(strings.ReplaceAll(strings.ToLower(tc.name), " ", "-"))
				if err := c.Create(ctx, d); err != nil {
					t.Fatal(err)
				}
				promote(d, 1, digestA)
				d.Spec.Recovery = &networkv1alpha1.FabricRecovery{
					RevokedPrefixes:    []string{"192.0.2.0/24"},
					RevokedCredentials: []networkv1alpha1.FabricObjectIdentity{{Name: "md5", UID: "secret-uid"}},
				}
				if err := c.Update(ctx, d); err != nil {
					t.Fatalf("promotion to epoch 1: %v", err)
				}
				tc.mutate(d)
				checkAdmission(t, c.Update(ctx, d), tc.wantErr)
			})
		}
	})

	t.Run("retirement is sticky", func(t *testing.T) {
		d := newDeployment("retired")
		if err := c.Create(ctx, d); err != nil {
			t.Fatal(err)
		}
		promote(d, 1, digestA)
		d.Spec.Recovery = &networkv1alpha1.FabricRecovery{Retired: true}
		if err := c.Update(ctx, d); err != nil {
			t.Fatalf("retire: %v", err)
		}
		cleared := d.DeepCopy()
		cleared.Spec.Recovery.Retired = false
		checkAdmission(t, c.Update(ctx, cleared), "recovery changes only with a new epoch")
		promote(d, 2, digestB)
		checkAdmission(t, c.Update(ctx, d), "a retired router is not promoted")
	})

	t.Run("a stale fence does not cover a later move", func(t *testing.T) {
		d := newDeployment("moved-twice")
		if err := c.Create(ctx, d); err != nil {
			t.Fatal(err)
		}
		d.Spec.Target = networkv1alpha1.FabricNodeIdentity{NodeName: "node-b", NodeUID: "node-b-uid"}
		d.Spec.Fence = fence("node-uid")
		if err := c.Update(ctx, d); err != nil {
			t.Fatalf("first move: %v", err)
		}
		d.Spec.Target = networkv1alpha1.FabricNodeIdentity{NodeName: "node-c", NodeUID: "node-c-uid"}
		checkAdmission(t, c.Update(ctx, d), "after its current node is fenced")
	})

	t.Run("a second promotion and a CRD handoff back", func(t *testing.T) {
		d := newDeployment("lifecycle")
		if err := c.Create(ctx, d); err != nil {
			t.Fatal(err)
		}
		for i, digest := range []string{digestA, digestB} {
			promote(d, int64(i+1), digest)
			if err := c.Update(ctx, d); err != nil {
				t.Fatalf("promotion to epoch %d: %v", i+1, err)
			}
		}
		d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
		d.Spec.SourceHandoff = handoff()
		if err := c.Update(ctx, d); err != nil {
			t.Fatalf("handoff: %v", err)
		}
		promote(d, 3, digestA)
		checkAdmission(t, c.Update(ctx, d), "already on the CRD source")
	})
}

func checkAdmission(t *testing.T, err error, wantErr string) {
	t.Helper()
	switch {
	case wantErr == "" && err != nil:
		t.Fatalf("refused: %v", err)
	case wantErr != "" && err == nil:
		t.Fatal("admitted")
	case wantErr != "" && !strings.Contains(err.Error(), wantErr):
		t.Fatalf("refused for another reason: %v", err)
	}
}

func newRelease(name string) *networkv1alpha1.FabricReleaseAuthorization {
	return &networkv1alpha1.FabricReleaseAuthorization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fabric", Name: name},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type: networkv1alpha1.FabricReleaseTypeRelease, RoutingDomain: "fabric", FleetReleaseID: "r7", FleetSequence: 7,
			Deployments: []networkv1alpha1.FabricReleaseTarget{{
				Deployment: "edge-a", DeploymentUID: "deployment-uid",
				Revision: "edge-a-aaaaaaaaaa", ActivationDependencyDigest: digestA,
			}},
			StartDeadline: &metav1.Time{Time: time.Now().Add(time.Hour)},
		},
	}
}

func TestReleaseAuthorizationAdmission(t *testing.T) {
	c := startActivationAPI(t)
	ctx := context.Background()
	type R = networkv1alpha1.FabricReleaseAuthorization

	for _, tc := range []struct {
		name    string
		setup   func(*R)
		wantErr string
	}{
		{name: "release"},
		{name: "release authorizing nothing", setup: func(r *R) { r.Spec.Deployments = nil }, wantErr: "spec.deployments"},
		{name: "emergency withdrawal naming nothing", setup: func(r *R) {
			r.Spec.Type = networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal
		}, wantErr: "names the prefixes it withdraws"},
		{name: "emergency withdrawal", setup: func(r *R) {
			r.Spec.Type = networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal
			r.Spec.WithdrawnPrefixes = []string{"192.0.2.0/24"}
		}},
		{name: "release withdrawing prefixes", setup: func(r *R) { r.Spec.WithdrawnPrefixes = []string{"192.0.2.0/24"} },
			wantErr: "and only it does"},
		{name: "withdrawn prefix that is no prefix", setup: func(r *R) {
			r.Spec.Type = networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal
			r.Spec.WithdrawnPrefixes = []string{"edge"}
		}, wantErr: "withdrawn prefixes are prefixes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelease(strings.ReplaceAll(tc.name, " ", "-"))
			if tc.setup != nil {
				tc.setup(r)
			}
			checkAdmission(t, c.Create(ctx, r), tc.wantErr)
		})
	}

	t.Run("spec is immutable", func(t *testing.T) {
		r := newRelease("immutable")
		if err := c.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
		r.Spec.FleetSequence = 8
		checkAdmission(t, c.Update(ctx, r), "immutable")
	})

	t.Run("status transitions", func(t *testing.T) {
		started := metav1.Now()
		for _, tc := range []struct {
			name     string
			from, to networkv1alpha1.FabricReleaseAuthorizationStatus
			wantErr  string
		}{
			{"start", networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhasePending},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started}, ""},
			{"start without a time", networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhasePending},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted}, "records when it started"},
			{"cancel a pending release", networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhasePending},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseCancelled}, ""},
			{"cancel a started release",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseCancelled, StartedAt: &started},
				"moves only forward"},
			{"reopen a completed release",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseCompleted, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started},
				"moves only forward"},
			{"conditions before a phase", networkv1alpha1.FabricReleaseAuthorizationStatus{},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Conditions: []metav1.Condition{{
					Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: started,
				}}}, ""},
			{"complete a failed release",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseFailed, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseCompleted, StartedAt: &started},
				"moves only forward"},
			{"restart a started release",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhasePending, StartedAt: &started},
				"moves only forward"},
			{"clear the phase",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{StartedAt: &started},
				"moves only forward"},
			{"complete without starting",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhasePending},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseCompleted, StartedAt: &started},
				"moves only forward"},
			{"unknown back to pending",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseUnknown, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhasePending, StartedAt: &started},
				"moves only forward"},
			{"unknown resolved to completed",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseUnknown, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseCompleted, StartedAt: &started},
				""},
			{"verify recovery of a failed release",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseFailed, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseFailed, StartedAt: &started, RecoveryVerified: true},
				""},
			{"unverify recovery",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseFailed, StartedAt: &started, RecoveryVerified: true},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseFailed, StartedAt: &started},
				"stays verified"},
			{"verify recovery of a started release",
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started},
				networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted, StartedAt: &started, RecoveryVerified: true},
				"only a failed release verifies recovery"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := newRelease(strings.ReplaceAll(tc.name, " ", "-"))
				if err := c.Create(ctx, r); err != nil {
					t.Fatal(err)
				}
				r.Status = tc.from
				if err := c.Status().Update(ctx, r); err != nil {
					t.Fatalf("initial status: %v", err)
				}
				r.Status = tc.to
				checkAdmission(t, c.Status().Update(ctx, r), tc.wantErr)
			})
		}
	})
}

func TestReleaseOutstanding(t *testing.T) {
	for _, tc := range []struct {
		phase    networkv1alpha1.FabricReleasePhase
		verified bool
		want     bool
	}{
		{"", false, true},
		{networkv1alpha1.FabricReleasePhasePending, false, true},
		{networkv1alpha1.FabricReleasePhaseStarted, false, true},
		{networkv1alpha1.FabricReleasePhaseUnknown, false, true},
		{networkv1alpha1.FabricReleasePhaseFailed, false, true},
		{networkv1alpha1.FabricReleasePhaseFailed, true, false},
		{networkv1alpha1.FabricReleasePhaseCompleted, false, false},
		{networkv1alpha1.FabricReleasePhaseCancelled, false, false},
	} {
		s := networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: tc.phase, RecoveryVerified: tc.verified}
		if got := s.Outstanding(); got != tc.want {
			t.Errorf("phase %q verified %v: outstanding = %v, want %v", tc.phase, tc.verified, got, tc.want)
		}
	}
}

func TestRolloutPolicyAdmission(t *testing.T) {
	c := startActivationAPI(t)
	ctx := context.Background()
	type P = networkv1alpha1.FabricRolloutPolicy
	for _, tc := range []struct {
		name    string
		setup   func(*P)
		wantErr string
	}{
		{name: "defaults"},
		{name: "optional and maintenance peers", setup: func(p *P) {
			p.Spec.OptionalPeers = []networkv1alpha1.LocalObjectRef{{Name: "upstream-1"}}
			p.Spec.MaintenancePeers = []networkv1alpha1.LocalObjectRef{{Name: "upstream-2"}}
		}},
		{name: "peer both optional and in maintenance", setup: func(p *P) {
			p.Spec.OptionalPeers = []networkv1alpha1.LocalObjectRef{{Name: "upstream-1"}}
			p.Spec.MaintenancePeers = []networkv1alpha1.LocalObjectRef{{Name: "upstream-1"}}
		}, wantErr: "optional or in maintenance, not both"},
		{name: "failure domain label that is no label key", setup: func(p *P) {
			p.Spec.FailureDomainLabel = "not a label"
		}, wantErr: "spec.failureDomainLabel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &P{ObjectMeta: metav1.ObjectMeta{Namespace: "fabric", Name: strings.ReplaceAll(tc.name, " ", "-")}}
			if tc.setup != nil {
				tc.setup(p)
			}
			checkAdmission(t, c.Create(ctx, p), tc.wantErr)
		})
	}
}

// TestDeploymentSelectableByNode: the node agent lists only its own node's
// deployment with a spec.target.nodeName field selector.
func TestDeploymentSelectableByNode(t *testing.T) {
	c := startActivationAPI(t)
	ctx := context.Background()
	for _, node := range []string{"node-a", "node-b"} {
		d := newDeployment("router-" + node)
		d.Spec.Target = networkv1alpha1.FabricNodeIdentity{NodeName: node, NodeUID: node + "-uid"}
		if err := c.Create(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	var list networkv1alpha1.FabricRouterDeploymentList
	if err := c.List(ctx, &list, client.InNamespace("fabric"),
		client.MatchingFieldsSelector{Selector: fields.OneTermEqualSelector("spec.target.nodeName", "node-b")}); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != "router-node-b" {
		t.Fatalf("listed %d deployments for node-b", len(list.Items))
	}
}
