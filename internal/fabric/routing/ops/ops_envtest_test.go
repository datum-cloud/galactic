// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package ops

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/controller"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/revision"
)

const (
	ns    = "galactic-system"
	nodeA = "edge-a"
	nodeB = "edge-b"
	// domain is the routing domain of every test release.
	domain = "fabric"
)

// startAPI runs an API server with the fabric CRDs, so every write the
// workflows make passes their admission rules.
func startAPI(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the operator workflow envtest")
	}
	names := []string{"fabricrouterdeployments", "fabricrouterrevisions", "fabricreleaseauthorizations"}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(names))
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "config", "crd",
			"galactic.datumapis.com_"+n+".yaml"))
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
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	return c
}

// buildRevision compiles the synthetic edge fixture as the router of
// Node node, named after it, with edit applied.
func buildRevision(t *testing.T, node *corev1.Node, edit func(string) string) *networkv1alpha1.FabricRouterRevision {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "edge-a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(edit(string(data)), "hostname edge-a-fabric", "hostname "+node.Name+"-fabric", 1)
	o, err := frrimport.Import(strings.NewReader(text), frrimport.Options{
		Namespace: ns, NodeName: node.Name, RouterClassName: "fabric-frr",
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Router.UID = types.UID("router-" + node.Name)
	in, err := bundle.FromImport(o, "fabric-frr").Input(node.Name)
	if err != nil {
		t.Fatal(err)
	}
	rev, _, err := revision.Build(in, string(node.UID))
	if err != nil {
		t.Fatal(err)
	}
	rev.Namespace = ns
	// As the revision controller labels every revision it builds.
	rev.Labels = map[string]string{controller.RouterLabel: node.Name}
	return rev
}

// fleet creates, per name, a Node, two revisions of its router and a
// deployment named after it on the given source, with the first revision
// as candidate. It returns the first Node.
func fleet(t *testing.T, c client.Client, source networkv1alpha1.FabricConfigSource, names ...string) *corev1.Node {
	t.Helper()
	ctx := context.Background()
	var firstNode *corev1.Node
	for _, name := range names {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := c.Create(ctx, node); err != nil {
			t.Fatal(err)
		}
		if firstNode == nil {
			firstNode = node
		}
		var first string
		for i, interval := range []string{"30", "20"} {
			rev := buildRevision(t, node, func(s string) string {
				return strings.Replace(s, "advertisement-interval 30", "advertisement-interval "+interval, 1)
			})
			if err := c.Create(ctx, rev); err != nil {
				t.Fatalf("revision: %v", err)
			}
			if i == 0 {
				first = rev.Name
				revisions[name] = rev
			}
		}
		d := &networkv1alpha1.FabricRouterDeployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: networkv1alpha1.FabricRouterDeploymentSpec{
				RouterRef:            networkv1alpha1.FabricObjectIdentity{Name: name, UID: "router-" + name},
				Target:               networkv1alpha1.FabricNodeIdentity{NodeName: name, NodeUID: string(node.UID)},
				Source:               source,
				CandidateRevisionRef: &networkv1alpha1.LocalObjectRef{Name: first},
			},
		}
		if err := c.Create(ctx, d); err != nil {
			t.Fatalf("deployment: %v", err)
		}
	}
	return firstNode
}

// revisions holds each router's candidate revision as fleet created it.
var revisions = map[string]*networkv1alpha1.FabricRouterRevision{}

// edgeA reads edge-a's deployment.
func edgeA(t *testing.T, c client.Client) *networkv1alpha1.FabricRouterDeployment {
	t.Helper()
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: nodeA}, d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestReleaseWorkflows(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	fleet(t, c, networkv1alpha1.FabricConfigSourceCRD, nodeA, nodeB)
	if err := SetSource(ctx, c, ns, nodeB, networkv1alpha1.FabricConfigSourceCRD); err != nil {
		t.Fatal(err)
	}
	if err := SetSuspended(ctx, c, ns, nodeB, true); err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// Every changed, promotable deployment: edge-b is suspended, so edge-a only.
	auth, err := BuildRelease(ctx, c, ReleaseSpec{Namespace: ns, Name: "rel-1", RoutingDomain: domain,
		FleetSequence: 1, StartWithin: time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth.Spec.Deployments) != 1 || auth.Spec.Deployments[0].Deployment != nodeA ||
		auth.Spec.Deployments[0].DeploymentUID != string(edgeA(t, c).UID) ||
		auth.Spec.Deployments[0].ActivationDependencyDigest != revisions[nodeA].Spec.ActivationDependencyDigest {
		t.Fatalf("release targets %+v", auth.Spec.Deployments)
	}
	if err := c.Create(ctx, auth); err != nil {
		t.Fatalf("the release does not pass admission: %v", err)
	}

	// Naming a suspended deployment is an error, not a silent skip.
	if _, err := BuildRelease(ctx, c, ReleaseSpec{Namespace: ns, Name: "rel-2", RoutingDomain: domain,
		FleetSequence: 2, Deployments: []string{nodeB}}, now); err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Errorf("a suspended deployment: %v", err)
	}
	if err := SetSuspended(ctx, c, ns, nodeB, false); err != nil {
		t.Fatal(err)
	}

	// An emergency withdrawal that retires.
	ew, err := BuildRelease(ctx, c, ReleaseSpec{Namespace: ns, Name: "ew-1", RoutingDomain: domain, FleetSequence: 3,
		Deployments: []string{nodeB}, Withdraw: []string{"192.0.2.0/24"}, Retire: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if ew.Spec.Type != networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal || !ew.Spec.Deployments[0].Retire {
		t.Errorf("withdrawal %+v", ew.Spec)
	}
	if err := c.Create(ctx, ew); err != nil {
		t.Fatalf("the withdrawal does not pass admission: %v", err)
	}

	// Nothing changed and nothing named: nothing to release.
	d := edgeA(t, c)
	d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
	d.Spec.SourceHandoff = &networkv1alpha1.FabricSourceHandoff{
		ConfigMap: networkv1alpha1.FabricObjectIdentity{Name: "x", UID: "y"}, ResourceVersion: "1",
	}
	if err := c.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := SetSuspended(ctx, c, ns, nodeB, true); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRelease(ctx, c, ReleaseSpec{Namespace: ns, Name: "rel-3", RoutingDomain: domain,
		FleetSequence: 4}, now); !errors.Is(err, ErrNothingToRelease) {
		t.Errorf("an empty release: %v", err)
	}

	// Recovery is confirmed only on a failed release.
	if err := ConfirmRecovery(ctx, c, ns, "rel-1", "oncall"); err == nil {
		t.Error("confirmed recovery of a release that has not failed")
	}
	started := metav1.NewTime(now)
	auth.Status = networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted,
		StartedAt: &started}
	if err := c.Status().Update(ctx, auth); err != nil {
		t.Fatal(err)
	}
	auth.Status.Phase = networkv1alpha1.FabricReleasePhaseFailed
	if err := c.Status().Update(ctx, auth); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(ctx, c, ns, "rel-1", "oncall"); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(ctx, c, ns, "rel-1", "someone-else"); err == nil {
		t.Error("a second confirmation replaced who confirmed first")
	}
	got := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(auth),
		got); err != nil || got.Annotations[RecoveryVerifiedAnnotation] != "oncall" {
		t.Errorf("annotation %v, %v", got.Annotations, err)
	}

	var out bytes.Buffer
	if err := ReleaseStatus(ctx, c, ns, "rel-1", &out); err != nil || !strings.Contains(out.String(), nodeA) ||
		!strings.Contains(out.String(), "Failed") {
		t.Errorf("release status %q, %v", out.String(), err)
	}
}

// TestReleaseRefusesWhatRolloutWould: a target the rollout manager would
// fail the release on is an error when named and left out otherwise, and
// retirement never applies to the whole fleet.
func TestReleaseRefusesWhatRolloutWould(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	fleet(t, c, networkv1alpha1.FabricConfigSourceCRD, nodeA, nodeB)
	now := time.Now()

	if _, err := BuildRelease(ctx, c, ReleaseSpec{Namespace: ns, Name: "retire-all", RoutingDomain: domain,
		FleetSequence: 1, Retire: true}, now); err == nil {
		t.Error("retired every changed router without naming one")
	}

	// edge-b's candidate was compiled for edge-a.
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: nodeB}, d); err != nil {
		t.Fatal(err)
	}
	d.Spec.CandidateRevisionRef = &networkv1alpha1.LocalObjectRef{Name: revisions[nodeA].Name}
	if err := c.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	auth, err := BuildRelease(ctx, c, ReleaseSpec{Namespace: ns, Name: "rel-1", RoutingDomain: domain,
		FleetSequence: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth.Spec.Deployments) != 1 || auth.Spec.Deployments[0].Deployment != nodeA {
		t.Errorf("release targets %+v, want edge-a only", auth.Spec.Deployments)
	}
	if _, err := BuildRelease(ctx, c, ReleaseSpec{Namespace: ns, Name: "rel-2", RoutingDomain: domain,
		FleetSequence: 1, Deployments: []string{nodeB}}, now); err == nil ||
		!strings.Contains(err.Error(), "compiled for router") {
		t.Errorf("naming a deployment the rollout manager would refuse: %v", err)
	}
}

func TestSourceWorkflows(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	fleet(t, c, networkv1alpha1.FabricConfigSourceConfigMap, nodeA)

	for _, s := range []networkv1alpha1.FabricConfigSource{networkv1alpha1.FabricConfigSourceShadow,
		networkv1alpha1.FabricConfigSourceCRD} {
		if err := SetSource(ctx, c, ns, nodeA, s); err != nil {
			t.Fatalf("to %s: %v", s, err)
		}
	}
	if err := SetSource(ctx, c, ns, nodeA, networkv1alpha1.FabricConfigSourceShadow); err == nil {
		t.Error("left CRD for Shadow")
	}
	if err := SetSource(ctx, c, ns, nodeA, networkv1alpha1.FabricConfigSourceConfigMap); err == nil ||
		!strings.Contains(err.Error(), "configmap-retired") {
		t.Errorf("handed back without the node's ConfigMap: %v, want an error pointing at the retirement", err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "fabric-router." + nodeA}}
	if err := c.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if err := SetSource(ctx, c, ns, nodeA, networkv1alpha1.FabricConfigSourceConfigMap); err != nil {
		t.Fatalf("handoff: %v", err)
	}
	d := edgeA(t, c)
	h := d.Spec.SourceHandoff
	if h == nil || h.ConfigMap.UID != string(cm.UID) || h.ResourceVersion != cm.ResourceVersion {
		t.Errorf("handoff %+v", d.Spec.SourceHandoff)
	}

	// The ConfigMap changes before the agent hands the node back: running
	// the move again names it as it is now.
	d.Status.EffectiveSource = networkv1alpha1.FabricConfigSourceCRD
	if err := c.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	cm.Data = map[string]string{"frr.conf": "frr defaults traditional\n"}
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if err := SetSource(ctx, c, ns, nodeA, networkv1alpha1.FabricConfigSourceConfigMap); err != nil {
		t.Fatalf("refreshing the handoff: %v", err)
	}
	if h := edgeA(t, c).Spec.SourceHandoff; h == nil || h.ResourceVersion != cm.ResourceVersion {
		t.Errorf("handoff %+v, want the ConfigMap at version %s", h, cm.ResourceVersion)
	}
}

func TestRebindAndMove(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	old := fleet(t, c, networkv1alpha1.FabricConfigSourceConfigMap, nodeA)
	now := time.Now()

	if err := Rebind(ctx, c, ns, nodeA, "", "oncall", now); err == nil {
		t.Error("rebound without naming the old deployment")
	}
	if err := Rebind(ctx, c, ns, nodeA, "old-uid", "oncall", now); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if r := edgeA(t, c).Spec.Rebind; r == nil || r.FromDeploymentUID != "old-uid" {
		t.Errorf("rebind %+v", r)
	}

	if err := Move(ctx, c, ns, nodeA, "edge-c", "port shutdown", "oncall", now); err == nil {
		t.Error("moved to a Node that does not exist")
	}
	next := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "edge-c"}}
	if err := c.Create(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := Move(ctx, c, ns, nodeA, "edge-c", "", "oncall", now); err == nil {
		t.Error("moved without saying how the old node was fenced")
	}
	if err := Move(ctx, c, ns, nodeA, "edge-c", "port shutdown", "oncall", now); err != nil {
		t.Fatalf("move: %v", err)
	}
	d := edgeA(t, c)
	if d.Spec.Target.NodeUID != string(next.UID) || d.Spec.Fence == nil || d.Spec.Fence.NodeUID != string(old.UID) {
		t.Errorf("after the move: target %+v fence %+v", d.Spec.Target, d.Spec.Fence)
	}

	var out bytes.Buffer
	if err := FleetStatus(ctx, c, ns, now, &out); err != nil || !strings.Contains(out.String(), "edge-c") {
		t.Errorf("fleet status %q, %v", out.String(), err)
	}
}

// TestAttention: only conditions an operator acts on are flagged; a router
// with nothing promoted to it is as it should be.
func TestAttention(t *testing.T) {
	d := &networkv1alpha1.FabricRouterDeployment{}
	d.Status.Conditions = []metav1.Condition{{Type: networkv1alpha1.FabricConditionAccepted, Status: "False",
		Reason: networkv1alpha1.FabricReasonWaitingForPromotion}}
	if got := attention(d); got != "-" {
		t.Errorf("attention = %q for a router waiting for a promotion", got)
	}
	d.Status.Conditions[0].Reason = networkv1alpha1.FabricReasonPromotionRefused
	d.Status.Conditions = append(d.Status.Conditions, metav1.Condition{Type: networkv1alpha1.FabricConditionDegraded,
		Status: "True", Reason: networkv1alpha1.FabricReasonNoEligibleRecovery})
	if got := attention(d); got != "Degraded:NoEligibleRecovery,NotAccepted:PromotionRefused" {
		t.Errorf("attention = %q", got)
	}
}

// promoteTo moves edge-a to epoch on rev, with recovery, and reports it
// committed when committed is set, as the rollout manager and the node
// agent would.
func promoteTo(t *testing.T, c client.Client, epoch int64, rev *networkv1alpha1.FabricRouterRevision,
	recovery *networkv1alpha1.FabricRecovery, committed bool) {
	t.Helper()
	ctx := context.Background()
	d := edgeA(t, c)
	d.Spec.ActivationEpoch = epoch
	d.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: rev.Name}
	d.Spec.ActivationDependencyDigest = rev.Spec.ActivationDependencyDigest
	d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: "earlier", UID: "earlier-uid"}
	d.Spec.Activation = &networkv1alpha1.FabricActivationSettings{ApplyTimeoutSeconds: 60}
	d.Spec.Recovery = recovery
	if err := c.Update(ctx, d); err != nil {
		t.Fatalf("promote edge-a to epoch %d: %v", epoch, err)
	}
	if !committed {
		return
	}
	now := metav1.Now()
	d.Status = networkv1alpha1.FabricRouterDeploymentStatus{HeartbeatTime: &now, AppliedEpoch: epoch,
		AppliedRevision: rev.Name, AppliedDigest: rev.Spec.ActivationDependencyDigest,
		Epochs: []networkv1alpha1.FabricEpochStatus{{Epoch: epoch, Revision: rev.Name,
			Stage: networkv1alpha1.FabricStageCommitted}}}
	if err := c.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
}

// credentialName is the Secret a test revision's peer authenticates with.
const credentialName = "bgp-auth"

// TestReleaseRefusesRevokedCredential: a revision using a credential the
// deployment revoked, by Secret UID, or one that cannot be resolved, is an
// error when named and left out otherwise; a Secret recreated under the
// same name is a new credential.
func TestReleaseRefusesRevokedCredential(t *testing.T) {
	c := startAPI(t)
	ctx := context.Background()
	node := fleet(t, c, networkv1alpha1.FabricConfigSourceCRD, nodeA)
	now := time.Now()
	rev := buildRevision(t, node, func(s string) string {
		return strings.Replace(s, "advertisement-interval 30", "advertisement-interval 10", 1)
	})
	rev.Spec.Configuration.Peers[0].Spec.AuthSecretRef = &networkv1alpha1.LocalSecretRef{Name: credentialName}
	if err := c.Create(ctx, rev); err != nil {
		t.Fatal(err)
	}
	d := edgeA(t, c)
	d.Spec.CandidateRevisionRef = &networkv1alpha1.LocalObjectRef{Name: rev.Name}
	if err := c.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	named := ReleaseSpec{Namespace: ns, Name: "rel", RoutingDomain: domain, FleetSequence: 1,
		Deployments: []string{nodeA}}
	fleetWide := ReleaseSpec{Namespace: ns, Name: "rel", RoutingDomain: domain, FleetSequence: 1}

	if _, err := BuildRelease(ctx, c, named, now); err == nil || !strings.Contains(err.Error(),
		"uses credential "+credentialName+", which cannot be resolved") {
		t.Errorf("an unresolvable credential: %v", err)
	}
	if _, err := BuildRelease(ctx, c, fleetWide, now); !errors.Is(err, ErrNothingToRelease) {
		t.Errorf("an unresolvable credential, fleet-wide: %v, want it left out", err)
	}

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: credentialName}}
	if err := c.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRelease(ctx, c, named, now); err != nil {
		t.Fatalf("a resolvable credential: %v", err)
	}
	promoteTo(t, c, 1, revisions[nodeA], &networkv1alpha1.FabricRecovery{
		RevokedCredentials: []networkv1alpha1.FabricObjectIdentity{{Name: secret.Name, UID: string(secret.UID)}},
	}, true)
	if _, err := BuildRelease(ctx, c, named, now); err == nil || !strings.Contains(err.Error(),
		"uses credential "+credentialName+" (Secret UID "+string(secret.UID)+"), which is revoked") {
		t.Errorf("a revoked credential: %v", err)
	}
	if _, err := BuildRelease(ctx, c, fleetWide, now); !errors.Is(err, ErrNothingToRelease) {
		t.Errorf("a revoked credential, fleet-wide: %v, want it left out", err)
	}

	if err := c.Delete(ctx, secret); err != nil {
		t.Fatal(err)
	}
	recreated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: credentialName}}
	if err := c.Create(ctx, recreated); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRelease(ctx, c, named, now); err != nil {
		t.Errorf("a recreated Secret: %v", err)
	}
}
