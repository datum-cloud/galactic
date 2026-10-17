// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
	"go.datum.net/galactic/internal/fabric/routing/revision"
	"go.datum.net/galactic/internal/fabricconfig/activation"
)

const (
	depNamespace = "galactic-system"
	depNode      = "edge-a"
	depNodeUID   = "node-uid"
	depCluster   = "cluster-uid"
	depMachine   = "machine-id"
	depUID       = "deployment-uid"
	authUID      = "release-uid"
	cmUID        = "cm-uid"
)

// fixtureRevision imports the routing package's edge fixture, with edit
// applied, and builds its revision for depNodeUID.
func fixtureRevision(t *testing.T, edit func(string) string) *networkv1alpha1.FabricRouterRevision {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fabric", "routing", "testdata", "edge-a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if edit != nil {
		text = edit(text)
	}
	o, err := frrimport.Import(strings.NewReader(text), frrimport.Options{
		Namespace: depNamespace, NodeName: depNode, RouterClassName: "fabric-frr",
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Router.UID = "router-uid"
	in, err := bundle.FromImport(o, "fabric-frr").Input(depNode)
	if err != nil {
		t.Fatal(err)
	}
	rev, _, err := revision.Build(in, depNodeUID)
	if err != nil {
		t.Fatal(err)
	}
	rev.Namespace = depNamespace
	return rev
}

func interval(n string) func(string) string {
	return func(s string) string {
		return strings.Replace(s, "advertisement-interval 30", "advertisement-interval "+n, 1)
	}
}

// fakeRouter is FRR and BGP for the deployment agent: its running
// configuration is the last file reloaded.
type fakeRouter struct {
	mu        sync.Mutex
	running   string
	reloads   int
	peerState string
	reloadErr error
}

func (f *fakeRouter) Check(_ context.Context, path string) error {
	_, err := os.ReadFile(path)
	return err
}

func (f *fakeRouter) Changes(_ context.Context, path string) (added, removed []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	for _, l := range frrtext.Diff(frrtext.Normalize(f.get()), frrtext.Normalize(string(data))) {
		if rest, ok := strings.CutPrefix(l, "+ "); ok {
			added = append(added, rest)
		} else if rest, ok := strings.CutPrefix(l, "- "); ok {
			removed = append(removed, rest)
		}
	}
	return added, removed, nil
}

func (f *fakeRouter) Reload(_ context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	if f.reloadErr != nil {
		return f.reloadErr
	}
	f.running = string(data)
	return nil
}

func (f *fakeRouter) Running(context.Context) (string, error) { return f.get(), nil }

func (f *fakeRouter) get() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeRouter) Neighbors(context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := f.peerState
	if state == "" {
		state = stateEstablished
	}
	return json.Marshal(map[string]any{"203.0.113.1": map[string]string{"bgpState": state}})
}

func (f *fakeRouter) Routes(context.Context, string) ([]byte, error) { return []byte("{}"), nil }

func (f *fakeRouter) ResetNeighbor(context.Context, string) error { return nil }

type harness struct {
	t      *testing.T
	client client.Client
	frr    *fakeRouter
	agent  *DeploymentAgent
	dir    string
	revs   []*networkv1alpha1.FabricRouterRevision
}

func newHarness(t *testing.T, objs ...client.Object) *harness {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	revs := []*networkv1alpha1.FabricRouterRevision{
		fixtureRevision(t, nil), fixtureRevision(t, interval("20")), fixtureRevision(t, interval("10")),
	}
	for _, r := range revs {
		objs = append(objs, r)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&networkv1alpha1.FabricRouterDeployment{}).
		WithIndex(&networkv1alpha1.FabricRouterDeployment{}, "spec.target.nodeName", func(o client.Object) []string {
			return []string{o.(*networkv1alpha1.FabricRouterDeployment).Spec.Target.NodeName}
		}).Build()

	dir := filepath.Join(t.TempDir(), "state")
	if _, err := activation.BindIdentity(dir, activation.Identity{
		NodeUID: depNodeUID, MachineID: depMachine, ClusterID: depCluster,
	}); err != nil {
		t.Fatal(err)
	}
	frr := &fakeRouter{}
	act := &activation.Activator{Dir: dir, FRR: frr}
	if err := act.Open(); err != nil {
		t.Fatal(err)
	}
	configDir := t.TempDir()
	return &harness{t: t, client: c, frr: frr, dir: dir, revs: revs, agent: &DeploymentAgent{
		Client: c, Namespace: depNamespace, NodeName: depNode, NodeUID: depNodeUID, ClusterID: depCluster,
		Activator: act, BGP: frr, Gate: NewSourceGate(networkv1alpha1.FabricConfigSourceConfigMap),
		ConfigDir: configDir, Version: "test",
	}}
}

func deployment(source networkv1alpha1.FabricConfigSource) *networkv1alpha1.FabricRouterDeployment {
	return &networkv1alpha1.FabricRouterDeployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: depNamespace, Name: depNode, UID: depUID, Generation: 1},
		Spec: networkv1alpha1.FabricRouterDeploymentSpec{
			RouterRef: networkv1alpha1.FabricObjectIdentity{Name: depNode, UID: "router-uid"},
			Target:    networkv1alpha1.FabricNodeIdentity{NodeName: depNode, NodeUID: depNodeUID},
			Source:    source,
		},
	}
}

// promote sets d's active epoch to rev, authorized by a release for it.
func promote(d *networkv1alpha1.FabricRouterDeployment, epoch int64, rev *networkv1alpha1.FabricRouterRevision) {
	d.Spec.ActivationEpoch = epoch
	d.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: rev.Name}
	d.Spec.ActivationDependencyDigest = rev.Spec.ActivationDependencyDigest
	d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: "release", UID: authUID}
	d.Spec.Activation = &networkv1alpha1.FabricActivationSettings{ApplyTimeoutSeconds: 60, OfflineBootSeconds: 3600}
}

func release(revs ...*networkv1alpha1.FabricRouterRevision) *networkv1alpha1.FabricReleaseAuthorization {
	a := &networkv1alpha1.FabricReleaseAuthorization{
		ObjectMeta: metav1.ObjectMeta{Namespace: depNamespace, Name: "release", UID: authUID},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type: networkv1alpha1.FabricReleaseTypeRelease, RoutingDomain: "fabric", FleetReleaseID: "r1", FleetSequence: 1,
		},
		Status: networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted},
	}
	for _, r := range revs {
		a.Spec.Deployments = append(a.Spec.Deployments, networkv1alpha1.FabricReleaseTarget{
			Deployment: depNode, DeploymentUID: depUID,
			Revision: r.Name, ActivationDependencyDigest: r.Spec.ActivationDependencyDigest,
		})
	}
	return a
}

func (h *harness) sync() *networkv1alpha1.FabricRouterDeployment {
	h.t.Helper()
	if err := h.agent.Sync(context.Background()); err != nil {
		h.t.Fatalf("sync: %v", err)
	}
	return h.get()
}

func (h *harness) get() *networkv1alpha1.FabricRouterDeployment {
	h.t.Helper()
	var d networkv1alpha1.FabricRouterDeployment
	if err := h.client.Get(context.Background(), types.NamespacedName{Namespace: depNamespace, Name: depNode},
		&d); err != nil {
		h.t.Fatal(err)
	}
	return &d
}

func (h *harness) update(edit func(*networkv1alpha1.FabricRouterDeployment)) {
	h.t.Helper()
	d := h.get()
	edit(d)
	if err := h.client.Update(context.Background(), d); err != nil {
		h.t.Fatal(err)
	}
}

func condition(d *networkv1alpha1.FabricRouterDeployment, t string) *metav1.Condition {
	return meta.FindStatusCondition(d.Status.Conditions, t)
}

func rendered(t *testing.T, rev *networkv1alpha1.FabricRouterRevision) string {
	t.Helper()
	res, err := revision.Verify(rev)
	if err != nil {
		t.Fatal(err)
	}
	return res.Config
}

func TestDeploymentAgentWithoutDeployment(t *testing.T) {
	h := newHarness(t)
	if err := h.agent.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceConfigMap {
		t.Errorf("source %s without a deployment", src)
	}
}

func TestDeploymentAgentShadowStages(t *testing.T) {
	d := deployment(networkv1alpha1.FabricConfigSourceShadow)
	h := newHarness(t, d)
	h.frr.running = rendered(t, h.revs[0])
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		d.Spec.CandidateRevisionRef = &networkv1alpha1.LocalObjectRef{Name: h.revs[1].Name}
	})
	got := h.sync()
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceShadow {
		t.Errorf("gate %s, want Shadow", src)
	}
	if got.Status.Staged == nil || got.Status.Staged.Revision != h.revs[1].Name ||
		got.Status.Staged.Class != networkv1alpha1.FabricChangeNonDisruptive || got.Status.Staged.LinesAdded != 1 {
		t.Fatalf("staged = %+v", got.Status.Staged)
	}
	if c := condition(got, networkv1alpha1.FabricConditionStaged); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Staged condition = %+v", c)
	}
	if h.frr.reloads != 0 {
		t.Error("shadow mode reloaded FRR")
	}
	if got.Status.EffectiveSource != networkv1alpha1.FabricConfigSourceShadow || got.Status.HeartbeatTime == nil ||
		got.Status.ClusterID != depCluster || got.Status.BoundDeploymentUID != depUID {
		t.Errorf("status = %+v", got.Status)
	}
}

func TestDeploymentAgentActivates(t *testing.T) {
	d := deployment(networkv1alpha1.FabricConfigSourceCRD)
	h := newHarness(t, d)
	if err := h.client.Create(context.Background(), release(h.revs[0], h.revs[1])); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	got := h.sync()
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceCRD {
		t.Errorf("gate %s, want CRD", src)
	}
	if got.Status.AppliedEpoch != 1 || got.Status.AppliedRevision != h.revs[0].Name ||
		got.Status.AppliedDigest != h.revs[0].Spec.ActivationDependencyDigest {
		t.Fatalf("applied = %d %s", got.Status.AppliedEpoch, got.Status.AppliedRevision)
	}
	if c := condition(got, networkv1alpha1.FabricConditionReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %+v", c)
	}
	if len(got.Status.Epochs) != 1 || got.Status.Epochs[0].Stage != networkv1alpha1.FabricStageCommitted {
		t.Errorf("epochs = %+v", got.Status.Epochs)
	}
	persisted, err := os.ReadFile(filepath.Join(h.agent.ConfigDir, KeyFRRConf))
	if err != nil || string(persisted) != rendered(t, h.revs[0]) {
		t.Errorf("frr.conf not persisted: %v", err)
	}

	// A second sync of a committed epoch does nothing.
	reloads := h.frr.reloads
	h.sync()
	if h.frr.reloads != reloads {
		t.Error("a committed epoch was reloaded again")
	}

	// The next epoch recovers to the first when a required peer is down.
	h.frr.peerState = "Active"
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		promote(d, 2, h.revs[1])
		d.Spec.Activation.RequiredPeers = []string{"203.0.113.1"}
		d.Spec.Recovery = &networkv1alpha1.FabricRecovery{
			TargetRevisionRef:      &networkv1alpha1.LocalObjectRef{Name: h.revs[0].Name},
			TargetDependencyDigest: h.revs[0].Spec.ActivationDependencyDigest,
		}
	})
	got = h.sync()
	if h.frr.get() != rendered(t, h.revs[0]) {
		t.Error("FRR does not run the recovery target")
	}
	if c := condition(got, networkv1alpha1.FabricConditionDegraded); c == nil || c.Status != metav1.ConditionTrue ||
		!strings.Contains(c.Message, "not Established") {
		t.Errorf("Degraded = %+v", c)
	}
	if got.Status.Epochs[0].Epoch != 2 || got.Status.Epochs[0].Stage != networkv1alpha1.FabricStageRecovered ||
		got.Status.Epochs[0].RecoveryTarget != h.revs[0].Name {
		t.Errorf("epoch 2 = %+v", got.Status.Epochs[0])
	}
}

func TestDeploymentAgentRefusesUnauthorized(t *testing.T) {
	for name, auth := range map[string]func(h *harness) *networkv1alpha1.FabricReleaseAuthorization{
		"missing":          func(*harness) *networkv1alpha1.FabricReleaseAuthorization { return nil },
		"another revision": func(h *harness) *networkv1alpha1.FabricReleaseAuthorization { return release(h.revs[1]) },
		"completed": func(h *harness) *networkv1alpha1.FabricReleaseAuthorization {
			a := release(h.revs[0])
			a.Status.Phase = networkv1alpha1.FabricReleasePhaseCompleted
			return a
		},
		"another UID": func(h *harness) *networkv1alpha1.FabricReleaseAuthorization {
			a := release(h.revs[0])
			a.UID = "other"
			return a
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
			if a := auth(h); a != nil {
				if err := h.client.Create(context.Background(), a); err != nil {
					t.Fatal(err)
				}
			}
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
			got := h.sync()
			if c := condition(got,
				networkv1alpha1.FabricConditionAccepted); c == nil || c.Reason != reasonNotAuthorized {
				t.Fatalf("Accepted = %+v", c)
			}
			if h.frr.reloads != 0 || len(h.agent.Activator.Journal().Records()) > 1 {
				t.Error("an unauthorized promotion reached FRR or was accepted")
			}
		})
	}
}

func TestDeploymentAgentHandoff(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: depNamespace, Name: ConfigMapName(depNode),
		UID: cmUID},
		Data: map[string]string{KeyFRRConf: "frr defaults traditional\n"}}
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD), cm)
	h.sync()
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceCRD {
		t.Fatalf("gate %s, want CRD", src)
	}

	var current corev1.ConfigMap
	if err := h.client.Get(context.Background(), client.ObjectKeyFromObject(cm), &current); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		handoff *networkv1alpha1.FabricSourceHandoff
	}{
		{"no handoff", nil},
		{"stale version", &networkv1alpha1.FabricSourceHandoff{
			ConfigMap: networkv1alpha1.FabricObjectIdentity{Name: cm.Name, UID: cmUID}, ResourceVersion: "1"}},
		{"recreated ConfigMap", &networkv1alpha1.FabricSourceHandoff{
			ConfigMap: networkv1alpha1.FabricObjectIdentity{Name: cm.Name,
				UID: "old"}, ResourceVersion: current.ResourceVersion}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
				d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
				d.Spec.SourceHandoff = tc.handoff
			})
			got := h.sync()
			if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceCRD {
				t.Errorf("left CRD on an invalid handoff: %s", src)
			}
			if c := condition(got,
				networkv1alpha1.FabricConditionAccepted); c == nil || c.Reason != reasonHandoffPending {
				t.Errorf("Accepted = %+v", c)
			}
		})
	}

	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		d.Spec.SourceHandoff = &networkv1alpha1.FabricSourceHandoff{
			ConfigMap:       networkv1alpha1.FabricObjectIdentity{Name: cm.Name, UID: cmUID},
			ResourceVersion: current.ResourceVersion,
		}
	})
	got := h.sync()
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceConfigMap {
		t.Errorf("gate %s after a valid handoff", src)
	}
	if got.Status.EffectiveSource != networkv1alpha1.FabricConfigSourceConfigMap {
		t.Errorf("effective source %s", got.Status.EffectiveSource)
	}
}

func TestDeploymentAgentRebind(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceShadow))
	if _, err := h.agent.Activator.Journal().Append(activation.Record{
		Type: activation.RecordAccepted, Activation: activation.Activation{DeploymentUID: "old-uid", Epoch: 3},
	}); err != nil {
		t.Fatal(err)
	}
	err := h.agent.Sync(context.Background())
	if !errors.Is(err, activation.ErrRecoveryConflict) {
		t.Fatalf("sync over another deployment's journal = %v", err)
	}
	if c := condition(h.get(),
		networkv1alpha1.FabricConditionRecoveryConflict); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("RecoveryConflict = %+v", c)
	}
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceConfigMap {
		t.Errorf("a conflicting deployment set the source to %s", src)
	}

	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		d.Spec.Rebind = &networkv1alpha1.FabricRebind{FromDeploymentUID: "old-uid", ApprovedBy: "oncall",
			ApprovedAt: metav1.Now()}
	})
	got := h.sync()
	if got.Status.BoundDeploymentUID != depUID || h.agent.Activator.Journal().BoundDeployment() != depUID {
		t.Errorf("not rebound: status %s, journal %s", got.Status.BoundDeploymentUID,
			h.agent.Activator.Journal().BoundDeployment())
	}
}

func TestDeploymentAgentIgnoresAnotherNodeUID(t *testing.T) {
	d := deployment(networkv1alpha1.FabricConfigSourceCRD)
	d.Spec.Target.NodeUID = "previous-node"
	h := newHarness(t, d)
	if err := h.agent.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceConfigMap {
		t.Errorf("a deployment for another Node UID set the source to %s", src)
	}
}

func TestBootConfig(t *testing.T) {
	d := deployment(networkv1alpha1.FabricConfigSourceCRD)
	h := newHarness(t, d)
	if err := h.client.Create(context.Background(), release(h.revs[0])); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })

	// Enrolled on CRD with nothing accepted: the ConfigMap.
	if _, _, err := h.agent.BootConfig(context.Background(), depMachine); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("BootConfig before any acceptance = %v, want ErrNotActivated", err)
	}

	// Accepted but not committed: the active revision from the API.
	act := activation.Activation{ClusterID: depCluster, NodeUID: depNodeUID, DeploymentUID: depUID, Epoch: 1,
		Revision: h.revs[0].Name, DependencyHash: h.revs[0].Spec.ActivationDependencyDigest}
	rec := activation.Record{Type: activation.RecordAccepted, Activation: act}
	if _, err := h.agent.Activator.Journal().Append(rec); err != nil {
		t.Fatal(err)
	}
	conf, reason, err := h.agent.BootConfig(context.Background(), depMachine)
	if err != nil || conf != rendered(t, h.revs[0]) || !strings.Contains(reason, "active revision") {
		t.Fatalf("BootConfig before a commit = %q, %v", reason, err)
	}

	h.sync()
	// After a commit, offline: the checkpoint.
	offline := *h.agent
	offline.Client = fake.NewClientBuilder().Build()
	conf, reason, err = offline.BootConfig(context.Background(), depMachine)
	if err != nil || conf != rendered(t, h.revs[0]) || !strings.Contains(reason, "restoring committed") {
		t.Fatalf("BootConfig offline = %q, %v", reason, err)
	}

	// On another machine, and offline: nothing.
	if _, _, err := offline.BootConfig(context.Background(), "other-machine"); err == nil {
		t.Error("another machine's checkpoint was restored")
	}
}

// TestBootConfigHonoursJournal: starting from the API's active revision is
// refused when the journal says the router is retired, the epoch failed,
// the journal belongs to another deployment, or the state is another
// node's.
func TestBootConfigHonoursJournal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(h *harness)
		want    string
	}{
		{"retired", func(h *harness) {
			journalAccept(h, depUID, 0, &activation.Recovery{Retired: true})
		}, "retired"},
		{"revoked origination", func(h *harness) {
			journalAccept(h, depUID, 0, &activation.Recovery{RevokedPrefixes: []string{"192.0.2.0/24"}})
		}, "originates revoked"},
		{"failed epoch", func(h *harness) {
			journalAccept(h, depUID, 1, nil)
			if _, err := h.agent.Activator.Journal().Append(activation.Record{Type: activation.RecordApplyFailed,
				Activation: activation.Activation{DeploymentUID: depUID, Epoch: 1}}); err != nil {
				h.t.Fatal(err)
			}
		}, "already failed"},
		{"another deployment", func(h *harness) { journalAccept(h, "old-uid", 4, nil) }, "bound to deployment"},
		{"another node", func(h *harness) {
			journalAccept(h, depUID, 0, nil)
			h.agent.IdentityErr = activation.ErrIdentityMismatch
		}, "another node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
			if err := h.client.Create(context.Background(), release(h.revs[0])); err != nil {
				t.Fatal(err)
			}
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
			tc.prepare(h)
			_, _, err := h.agent.BootConfig(context.Background(), depMachine)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BootConfig = %v, want %q", err, tc.want)
			}
		})
	}
}

// journalAccept journals an accepted activation of deployment uid at epoch,
// as an earlier run would have.
func journalAccept(h *harness, uid string, epoch int64, rec *activation.Recovery) {
	h.t.Helper()
	if _, err := h.agent.Activator.Journal().Append(activation.Record{
		Type:       activation.RecordAccepted,
		Activation: activation.Activation{ClusterID: depCluster, NodeUID: depNodeUID, DeploymentUID: uid, Epoch: epoch},
		Recovery:   rec,
	}); err != nil {
		h.t.Fatal(err)
	}
}

// TestDeploymentAgentFailsClosedOnIdentity: with state bound elsewhere the
// agent activates nothing, keeps the journal's source and reports it.
func TestDeploymentAgentFailsClosedOnIdentity(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
	if err := h.client.Create(context.Background(), release(h.revs[0])); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	h.agent.IdentityErr = activation.ErrIdentityMismatch
	if err := h.agent.Sync(context.Background()); !errors.Is(err, activation.ErrIdentityMismatch) {
		t.Fatalf("sync = %v", err)
	}
	if h.frr.reloads != 0 || len(h.agent.Activator.Journal().Records()) != 0 {
		t.Error("state bound elsewhere was acted on")
	}
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceConfigMap {
		t.Errorf("gate %s, want the journal's source", src)
	}
	c := condition(h.get(), networkv1alpha1.FabricConditionRecoveryConflict)
	if c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("RecoveryConflict = %+v", c)
	}
}

// TestDeploymentAgentStatusWrites: an unchanged status is not rewritten
// every sync, and a status another writer changed meanwhile is written
// over without a conflict.
func TestDeploymentAgentStatusWrites(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceShadow))
	first := h.sync()
	second := h.sync()
	if second.ResourceVersion != first.ResourceVersion {
		t.Error("an unchanged status was rewritten within the heartbeat interval")
	}
	other := h.get()
	other.Status.AgentVersion = "someone-else"
	if err := h.client.Status().Update(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	h.agent.written = nil
	if got := h.sync(); got.Status.AgentVersion != "test" {
		t.Errorf("agent version %q after a concurrent write", got.Status.AgentVersion)
	}
}

// TestBootConfigRefusesAnotherRevisionInEpoch: a spec changed to another
// revision under an epoch the journal accepted is not started.
func TestBootConfigRefusesAnotherRevisionInEpoch(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
	if err := h.client.Create(context.Background(), release(h.revs[0], h.revs[1])); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	h.sync()
	if err := os.Remove(filepath.Join(h.dir, "checkpoint.json")); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[1]) })
	if _, _, err := h.agent.BootConfig(context.Background(), depMachine); !errors.Is(err, activation.ErrStale) {
		t.Fatalf("BootConfig = %v, want ErrStale", err)
	}
}

// TestDeploymentAgentReassertsAfterReturn: a node that leaves CRD for its
// ConfigMap and returns at the same epoch runs the committed revision
// again, and is Ready only then.
func TestDeploymentAgentReassertsAfterReturn(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: depNamespace, Name: ConfigMapName(depNode), UID: cmUID},
		Data:       map[string]string{KeyFRRConf: "frr defaults traditional\n"},
	}
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD), cm)
	if err := h.client.Create(context.Background(), release(h.revs[0])); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	h.sync()

	// Handed back, and the ConfigMap path reapplies its ConfigMap.
	var current corev1.ConfigMap
	if err := h.client.Get(context.Background(), client.ObjectKeyFromObject(cm), &current); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
		d.Spec.SourceHandoff = &networkv1alpha1.FabricSourceHandoff{
			ConfigMap: networkv1alpha1.FabricObjectIdentity{Name: cm.Name, UID: cmUID}, ResourceVersion: current.ResourceVersion,
		}
	})
	h.sync()
	if h.agent.Gate.Handoff() != cmUID || h.agent.Activator.Journal().Handoff() != cmUID {
		t.Errorf("handoff UID %q in the gate, %q in the journal",
			h.agent.Gate.Handoff(), h.agent.Activator.Journal().Handoff())
	}
	// A restarted sidecar pins the same ConfigMap.
	reopened := &activation.Activator{Dir: h.dir}
	if err := reopened.Open(); err != nil {
		t.Fatal(err)
	}
	if reopened.Journal().Handoff() != cmUID {
		t.Errorf("handoff UID %q after a restart", reopened.Journal().Handoff())
	}
	h.frr.mu.Lock()
	h.frr.running = cm.Data[KeyFRRConf]
	h.frr.mu.Unlock()
	if err := os.WriteFile(filepath.Join(h.agent.ConfigDir, KeyFRRConf), []byte(cm.Data[KeyFRRConf]), 0o600); err != nil {
		t.Fatal(err)
	}

	// Back to CRD at the same epoch.
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		d.Spec.Source = networkv1alpha1.FabricConfigSourceCRD
		d.Spec.SourceHandoff = nil
	})
	got := h.sync()
	if h.frr.get() != rendered(t, h.revs[0]) {
		t.Error("the committed revision was not reasserted")
	}
	persisted, err := os.ReadFile(filepath.Join(h.agent.ConfigDir, KeyFRRConf))
	if err != nil || string(persisted) != rendered(t, h.revs[0]) {
		t.Errorf("frr.conf not repaired: %v", err)
	}
	if c := condition(got, networkv1alpha1.FabricConditionReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %+v", c)
	}
}

func TestDeploymentAgentRefusesUnstartedRelease(t *testing.T) {
	for _, phase := range []networkv1alpha1.FabricReleasePhase{
		networkv1alpha1.FabricReleasePhasePending,
		networkv1alpha1.FabricReleasePhaseFailed,
		networkv1alpha1.FabricReleasePhaseUnknown,
	} {
		t.Run(string(phase), func(t *testing.T) {
			h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
			a := release(h.revs[0])
			a.Status.Phase = phase
			if err := h.client.Create(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
			got := h.sync()
			if c := condition(got, networkv1alpha1.FabricConditionAccepted); c == nil || c.Reason != reasonNotAuthorized {
				t.Fatalf("Accepted = %+v", c)
			}
			if h.frr.reloads != 0 {
				t.Error("a release that is not Started activated")
			}
		})
	}
}

// TestBootConfigOnlineAfterExpiry: with the API reachable and the
// deployment bound, an expired boot authorization does not stop the
// checkpoint from starting, as after a failed epoch.
func TestBootConfigOnlineAfterExpiry(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
	if err := h.client.Create(context.Background(), release(h.revs[0])); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		promote(d, 1, h.revs[0])
		d.Spec.Activation.OfflineBootSeconds = 0
	})
	h.sync()
	conf, reason, err := h.agent.BootConfig(context.Background(), depMachine)
	if err != nil || conf != rendered(t, h.revs[0]) || !strings.Contains(reason, "with the API") {
		t.Fatalf("BootConfig = %q, %v", reason, err)
	}
}

// TestDeploymentAgentNotReadyWhenDrifted: FRR drifting from the committed
// revision, and failing to come back, is Degraded and not Ready.
func TestDeploymentAgentNotReadyWhenDrifted(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
	if err := h.client.Create(context.Background(), release(h.revs[0])); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	h.sync()
	h.frr.mu.Lock()
	h.frr.running = rendered(t, h.revs[1])
	h.frr.reloadErr = errors.New("bgpd refused the change")
	h.frr.mu.Unlock()
	got := h.sync()
	if c := condition(got, networkv1alpha1.FabricConditionReady); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("Ready = %+v, want False", c)
	}
	if c := condition(got, networkv1alpha1.FabricConditionDegraded); c == nil || c.Reason != reasonReassertFailed {
		t.Errorf("Degraded = %+v", c)
	}

	// Once FRR can be brought back, both conditions clear.
	h.frr.mu.Lock()
	h.frr.reloadErr = nil
	h.frr.mu.Unlock()
	got = h.sync()
	if c := condition(got, networkv1alpha1.FabricConditionDegraded); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("Degraded after recovery = %+v", c)
	}
	if c := condition(got, networkv1alpha1.FabricConditionReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Ready after recovery = %+v", c)
	}
}

// TestDeploymentAgentResolvesIdentityLater: started without the API, the
// agent keeps the journal's source and resolves its identity on a later
// sync.
func TestDeploymentAgentResolvesIdentityLater(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceShadow))
	h.agent.NodeUID, h.agent.ClusterID = "", ""
	down := true
	h.agent.Resolve = func(context.Context) error {
		if down {
			return errors.New("connection refused")
		}
		h.agent.NodeUID, h.agent.ClusterID = depNodeUID, depCluster
		return nil
	}
	if err := h.agent.Sync(context.Background()); err == nil {
		t.Fatal("synced without an identity")
	}
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceConfigMap {
		t.Errorf("gate %s without an identity", src)
	}
	down = false
	h.sync()
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceShadow {
		t.Errorf("gate %s after resolving", src)
	}
}
