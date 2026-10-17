// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package activation

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// committed activates r1 at epoch 1 so later tests start from a node
// running a committed revision.
func committed(t *testing.T, a *Activator, r1 *networkv1alpha1.FabricRouterRevision) {
	t.Helper()
	res, err := a.Activate(context.Background(), Request{
		Activation: activationOf(r1, 1), Revision: r1, Settings: Settings{BootLifetime: time.Hour},
	})
	if err != nil || res.Outcome != OutcomeCommitted {
		t.Fatalf("activate epoch 1 = %+v, %v", res, err)
	}
}

func TestActivateCommits(t *testing.T) {
	r1, r2, _ := revisions(t)
	frr := &fakeFRR{}
	a := newActivator(t, t.TempDir(), frr, nil)
	committed(t, a, r1)

	req := Request{Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1), RecoveryRevision: r1,
		Settings: Settings{BootLifetime: time.Hour}}
	res, err := a.Activate(context.Background(), req)
	if err != nil || res.Outcome != OutcomeCommitted {
		t.Fatalf("activate = %+v, %v", res, err)
	}
	if frr.get() != rendered(t, r2) {
		t.Error("FRR does not run the activated revision")
	}
	want := []RecordType{RecordAccepted, RecordApplied, RecordCommitted, RecordAccepted, RecordApplied, RecordCommitted}
	if got := recordTypes(a.Journal()); !slices.Equal(got, want) {
		t.Errorf("journal = %v, want %v", got, want)
	}
	cp, err := ReadCheckpoint(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Activation != req.Activation || cp.Config != rendered(t, r2) {
		t.Errorf("checkpoint is %s, want %s", cp.Activation.Revision, r2.Name)
	}
	if !slices.Contains(cp.Originates, testPrefix) {
		t.Errorf("checkpoint originations %v miss the fixture's network", cp.Originates)
	}
	if rec, _ := a.Journal().LastForEpoch(testDeployment, 2); rec.Type != RecordCommitted {
		t.Fatalf("epoch 2 ends %s", rec.Type)
	}
	if accepted := a.Journal().Records()[3]; accepted.PreviousGood != r1.Name {
		t.Errorf("accepted record names %q as previous good, want %s", accepted.PreviousGood, r1.Name)
	}

	// A redelivery of a committed activation does nothing.
	reloads := frr.reloads
	if res, err := a.Activate(context.Background(), req); err != nil || res.Outcome != OutcomeCommitted {
		t.Fatalf("redelivery = %+v, %v", res, err)
	}
	if frr.reloads != reloads {
		t.Error("a redelivered commit reloaded FRR")
	}
}

func TestAdmit(t *testing.T) {
	r1, r2, r3 := revisions(t)
	a := newActivator(t, t.TempDir(), &fakeFRR{}, nil)
	committed(t, a, r1)

	other := activationOf(r2, 2)
	other.DeploymentUID = "recreated"
	for _, tc := range []struct {
		name       string
		act        Activation
		redelivery bool
		err        error
	}{
		{"next epoch", activationOf(r2, 2), false, nil},
		{"epoch skipping ahead", activationOf(r2, 5), false, nil},
		{"redelivery of the accepted epoch", activationOf(r1, 1), true, nil},
		{"older epoch", activationOf(r2, 0), false, ErrStale},
		{"same epoch, another revision", activationOf(r3, 1), false, ErrStale},
		{"another cluster", withActivation(activationOf(r2, 2), func(x *Activation) { x.ClusterID = otherID }),
			false, ErrIdentityMismatch},
		{"for another Node", withActivation(activationOf(r2, 2), func(x *Activation) { x.NodeUID = otherID }),
			false, ErrIdentityMismatch},
		{"no deployment", withActivation(activationOf(r2, 2), func(x *Activation) { x.DeploymentUID = "" }),
			false, ErrIdentityMismatch},
		{"recreated deployment", other, false, ErrRecoveryConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redelivery, err := a.Admit(tc.act)
			if !errors.Is(err, tc.err) || (tc.err == nil && err != nil) {
				t.Fatalf("Admit = %v, want %v", err, tc.err)
			}
			if redelivery != tc.redelivery {
				t.Errorf("redelivery = %v, want %v", redelivery, tc.redelivery)
			}
		})
	}

	t.Run("an exact redelivery of an older epoch", func(t *testing.T) {
		if _, err := a.Activate(context.Background(), Request{Activation: activationOf(r2, 2),
			Revision: r2}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Admit(activationOf(r1, 1)); !errors.Is(err, ErrStale) {
			t.Fatalf("Admit of epoch 1 after epoch 2 = %v, want ErrStale", err)
		}
	})

	t.Run("after a rebind", func(t *testing.T) {
		if err := a.Journal().Rebind(testDeployment, "recreated"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Admit(other); err != nil {
			t.Fatalf("Admit after rebind = %v", err)
		}
		if _, err := a.Admit(activationOf(r2, 9)); !errors.Is(err, ErrRecoveryConflict) {
			t.Errorf("the old deployment is still admitted: %v", err)
		}
	})
}

func TestActivateRefusesAnotherRevision(t *testing.T) {
	r1, r2, _ := revisions(t)
	frr := &fakeFRR{}
	a := newActivator(t, t.TempDir(), frr, nil)
	for name, act := range map[string]Activation{
		"another digest": func() Activation {
			x := activationOf(r1, 1)
			x.DependencyHash = r2.Spec.ActivationDependencyDigest
			return x
		}(),
		"another name": func() Activation { x := activationOf(r1, 1); x.Revision = r2.Name; return x }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := a.Activate(context.Background(), Request{Activation: act, Revision: r1}); !errors.Is(err,
				ErrDigestMismatch) {
				t.Fatalf("Activate = %v, want ErrDigestMismatch", err)
			}
		})
	}
	t.Run("edited content", func(t *testing.T) {
		tampered := r1.DeepCopy()
		tampered.Spec.Configuration = *r2.Spec.Configuration.DeepCopy()
		if _, err := a.Activate(context.Background(), Request{Activation: activationOf(r1, 1),
			Revision: tampered}); err == nil {
			t.Fatal("a revision whose content no longer matches its digests was applied")
		}
	})
	if len(a.Journal().Records()) != 0 || frr.reloads != 0 {
		t.Error("a refused activation reached the journal or FRR")
	}
}

func TestActivateRefusesInvalidCandidate(t *testing.T) {
	r1, _, _ := revisions(t)
	frr := &fakeFRR{checkErr: errors.New("line 3: unknown command")}
	a := newActivator(t, t.TempDir(), frr, nil)
	if _, err := a.Activate(context.Background(), Request{Activation: activationOf(r1, 1), Revision: r1}); err == nil {
		t.Fatal("a configuration FRR rejects was applied")
	}
	if len(a.Journal().Records()) != 0 || frr.reloads != 0 {
		t.Error("a rejected configuration reached the journal or FRR")
	}
}

// TestActivateFailureRecovers: a failed reload, a running configuration that
// differs, or failing health each journal the epoch as failed and restore
// the recovery target, which becomes the checkpoint.
func TestActivateFailureRecovers(t *testing.T) {
	type breaker func(t *testing.T, f *fakeFRR, a *Activator, bad string) time.Duration
	isActive := func(path string) bool { return strings.HasSuffix(path, "active.conf") }
	for _, tc := range []struct {
		name   string
		breaks breaker
		detail string
	}{
		{"reload fails", func(_ *testing.T, f *fakeFRR, _ *Activator, _ string) time.Duration {
			f.reloadErr = func(path string) error {
				if isActive(path) {
					return errors.New("bgpd refused the change")
				}
				return nil
			}
			return time.Minute
		}, "bgpd refused"},
		{"reload times out", func(_ *testing.T, f *fakeFRR, _ *Activator, _ string) time.Duration {
			f.reloadErr = func(path string) error {
				if isActive(path) {
					time.Sleep(50 * time.Millisecond)
				}
				return nil
			}
			return 10 * time.Millisecond
		}, "deadline"},
		{"running configuration differs", func(_ *testing.T, f *fakeFRR, _ *Activator, bad string) time.Duration {
			f.reloadWrites = func(s string) string {
				if s == bad {
					return strings.Replace(s, "advertisement-interval 20", "advertisement-interval 25", 1)
				}
				return s
			}
			return time.Minute
		}, "running configuration differs"},
		{"unhealthy", func(_ *testing.T, _ *fakeFRR, a *Activator, bad string) time.Duration {
			a.Health = func(_ context.Context, cfg string) error {
				if cfg == bad {
					return errors.New("peer 203.0.113.1 not Established")
				}
				return nil
			}
			return time.Minute
		}, "not Established"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r1, r2, _ := revisions(t)
			frr := &fakeFRR{}
			a := newActivator(t, t.TempDir(), frr, nil)
			committed(t, a, r1)
			timeout := tc.breaks(t, frr, a, rendered(t, r2))

			req := Request{
				Activation: activationOf(r2, 2), Revision: r2, Recovery: recoveryTo(r1), RecoveryRevision: r1,
				Settings: Settings{ApplyTimeout: timeout, BootLifetime: time.Hour},
			}
			res, err := a.Activate(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != OutcomeRecovered || !strings.Contains(res.Detail, tc.detail) {
				t.Fatalf("outcome %+v, want Recovered mentioning %q", res, tc.detail)
			}
			if frr.get() != rendered(t, r1) {
				t.Error("FRR does not run the recovery target")
			}
			if !a.Journal().Failed(testDeployment, 2) {
				t.Error("the failed epoch is not journaled as failed")
			}
			cp, err := ReadCheckpoint(a.Dir)
			if err != nil || cp.Activation.Revision != r1.Name || cp.Config != rendered(t, r1) {
				t.Errorf("checkpoint after recovery = %s, %v", cp.Activation.Revision, err)
			}
			if _, err := a.Activate(context.Background(), req); !errors.Is(err, ErrFailedEpoch) {
				t.Errorf("retrying the failed epoch = %v, want ErrFailedEpoch", err)
			}
		})
	}
}

func TestActivateWithoutRecoveryDegrades(t *testing.T) {
	r1, r2, _ := revisions(t)
	frr := &fakeFRR{}
	a := newActivator(t, t.TempDir(), frr, nil)
	committed(t, a, r1)
	frr.reloadErr = func(string) error { return errors.New("bgpd refused the change") }
	res, err := a.Activate(context.Background(), Request{Activation: activationOf(r2, 2), Revision: r2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeDegraded || !strings.Contains(res.Detail, ErrNoEligibleRecovery.Error()) {
		t.Fatalf("outcome %+v, want Degraded with no eligible recovery", res)
	}
	if !a.Journal().Failed(testDeployment, 2) {
		t.Error("the failed epoch is not journaled as failed")
	}
}

func TestEligible(t *testing.T) {
	r1, r2, _ := revisions(t)
	withSecret := r1.DeepCopy()
	withSecret.Spec.Configuration.Peers[0].Spec.AuthSecretRef = &networkv1alpha1.LocalSecretRef{Name: "md5"}

	for _, tc := range []struct {
		name  string
		rec   Recovery
		rev   *networkv1alpha1.FabricRouterRevision
		creds map[string]string
		want  string
	}{
		{"authorized target", recoveryTo(r1), r1, nil, ""},
		{"none named", Recovery{}, r1, nil, "no eligible"},
		{"target missing", recoveryTo(r1), nil, nil, "no eligible"},
		{"another revision", recoveryTo(r1), r2, nil, "authorized"},
		{"another digest", Recovery{TargetRevision: r1.Name, TargetDigest: r2.Spec.ActivationDependencyDigest}, r1,
			nil, "digest"},
		{"router retired", Recovery{TargetRevision: r1.Name, TargetDigest: r1.Spec.ActivationDependencyDigest,
			Retired: true}, r1, nil, "retired"},
		{"revoked prefix",
			func() Recovery { x := recoveryTo(r1); x.RevokedPrefixes = []string{testPrefix}; return x }(),
			r1, nil, "originates revoked 192.0.2.0/24"},
		{"revoked prefix spelled differently", func() Recovery {
			x := recoveryTo(r1)
			x.RevokedPrefixes = []string{"2001:0db8:0100:0001::/64"}
			return x
		}(), r1, nil, originatesRevoked},
		{"revoked aggregate",
			func() Recovery { x := recoveryTo(r1); x.RevokedPrefixes = []string{"198.51.100.0/24"}; return x }(),
			r1, nil, originatesRevoked},
		{"revoked covering prefix",
			func() Recovery { x := recoveryTo(r1); x.RevokedPrefixes = []string{"192.0.2.0/23"}; return x }(),
			r1, nil, originatesRevoked + " " + testPrefix},
		{"revoked prefix inside an originated one",
			func() Recovery { x := recoveryTo(r1); x.RevokedPrefixes = []string{"192.0.2.0/25"}; return x }(),
			r1, nil, ""},
		{"unrelated revocation",
			func() Recovery { x := recoveryTo(r1); x.RevokedPrefixes = []string{"10.0.0.0/8"}; return x }(),
			r1, nil, ""},
		{"credential that cannot be resolved", Recovery{TargetRevision: r1.Name,
			TargetDigest: r1.Spec.ActivationDependencyDigest},
			withSecret, nil, "cannot be resolved"},
		{"revoked credential", Recovery{TargetRevision: r1.Name, TargetDigest: r1.Spec.ActivationDependencyDigest,
			RevokedCredentials: []string{"secret-uid-1"}},
			withSecret, map[string]string{"md5": "secret-uid-1"}, "revoked credential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Eligible(tc.rec, tc.rev, tc.creds)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Eligible = %v", err)
			case tc.want != "" && (err == nil || !errors.Is(err,
				ErrNoEligibleRecovery) || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Eligible = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStage(t *testing.T) {
	r1, r2, _ := revisions(t)
	frr := &fakeFRR{}
	a := newActivator(t, t.TempDir(), frr, nil)
	committed(t, a, r1)
	before := frr.get()
	staged, err := a.Stage(context.Background(), r2)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Class != networkv1alpha1.FabricChangeNonDisruptive || len(staged.Added) == 0 || len(staged.Removed) == 0 {
		t.Errorf("staged = %+v", staged)
	}
	if frr.get() != before || len(a.Journal().Records()) != 3 {
		t.Error("staging changed FRR or the journal")
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		added, removed []string
		want           networkv1alpha1.FabricChangeClass
	}{
		{nil, nil, networkv1alpha1.FabricChangeNone},
		{[]string{"ip prefix-list P seq 10 permit 192.0.2.0/24"}, nil, networkv1alpha1.FabricChangeNonDisruptive},
		{[]string{" neighbor 203.0.113.1 advertisement-interval 20"}, nil, networkv1alpha1.FabricChangeNonDisruptive},
		{[]string{" neighbor 203.0.113.1 remote-as 64496"}, nil, networkv1alpha1.FabricChangeSessionReset},
		{nil, []string{" no neighbor 203.0.113.1 update-source 192.0.2.10"}, networkv1alpha1.FabricChangeSessionReset},
		{[]string{"router bgp 64500"}, []string{"router bgp 64501"}, networkv1alpha1.FabricChangeSessionReset},
		{[]string{"router bgp 64500 :: neighbor UPSTREAM advertisement-interval 20"}, nil,
			networkv1alpha1.FabricChangeNonDisruptive},
		{[]string{"router bgp 64500 :: neighbor UPSTREAM ebgp-multihop 3"}, nil,
			networkv1alpha1.FabricChangeSessionReset},
		{nil, []string{"router bgp 64500 :: address-family ipv4 unicast :: no network 192.0.2.0/24"},
			networkv1alpha1.FabricChangeNonDisruptive},
		{nil, []string{"router bgp 64500 :: no neighbor UPSTREAM remote-as 64496"},
			networkv1alpha1.FabricChangeSessionReset},
		{[]string{"frr defaults datacenter"}, nil, networkv1alpha1.FabricChangeRestartRequired},
	} {
		if got := Classify(tc.added, tc.removed); got != tc.want {
			t.Errorf("Classify(%v, %v) = %s, want %s", tc.added, tc.removed, got, tc.want)
		}
	}
}
