// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package activation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/bundle"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/frrtext"
	"go.datum.net/galactic/internal/fabric/routing/revision"
)

const (
	testCluster    = "cluster-uid"
	testNode       = "node-uid"
	testDeployment = "deployment-uid"
	testMachine    = "machine-id"
	testPrefix     = "192.0.2.0/24"
	testRev1       = "r-1"
	otherID        = "other"

	anotherNode       = "another node"
	originatesRevoked = "originates revoked"
)

// buildRevision imports the edge fixture, with edit applied to its text,
// and builds the revision it compiles to.
func buildRevision(t *testing.T, edit func(string) string) *networkv1alpha1.FabricRouterRevision {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "fabric", "routing", "testdata", "edge-a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if edit != nil {
		text = edit(text)
	}
	o, err := frrimport.Import(strings.NewReader(text), frrimport.Options{
		Namespace: "galactic-system", NodeName: "edge-a", RouterClassName: "fabric-frr",
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Router.UID = types.UID("router-uid")
	in, err := bundle.FromImport(o, "fabric-frr").Input("edge-a")
	if err != nil {
		t.Fatal(err)
	}
	rev, _, err := revision.Build(in, testNode)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// revisions returns three distinct revisions of one router: the committed
// one, a newer one and a third.
func revisions(t *testing.T) (r1, r2, r3 *networkv1alpha1.FabricRouterRevision) {
	t.Helper()
	interval := func(n string) func(string) string {
		return func(s string) string {
			return strings.Replace(s, "advertisement-interval 30", "advertisement-interval "+n, 1)
		}
	}
	return buildRevision(t, nil), buildRevision(t, interval("20")), buildRevision(t, interval("10"))
}

func activationOf(rev *networkv1alpha1.FabricRouterRevision, epoch int64) Activation {
	return Activation{
		ClusterID: testCluster, NodeUID: testNode, DeploymentUID: testDeployment, Epoch: epoch,
		Revision: rev.Name, DependencyHash: rev.Spec.ActivationDependencyDigest,
	}
}

func recoveryTo(rev *networkv1alpha1.FabricRouterRevision) Recovery {
	return Recovery{TargetRevision: rev.Name, TargetDigest: rev.Spec.ActivationDependencyDigest}
}

// fakeFRR is FRR whose running configuration is whatever was last
// reloaded. Failures are injected per call kind.
type fakeFRR struct {
	mu        sync.Mutex
	running   string
	reloads   int
	checkErr  error
	reloadErr func(path string) error
	// reloadWrites, when set, replaces what a reload leaves running.
	reloadWrites func(content string) string
}

func (f *fakeFRR) Check(_ context.Context, path string) error {
	if _, err := os.ReadFile(path); err != nil {
		return err
	}
	return f.checkErr
}

func (f *fakeFRR) Changes(_ context.Context, path string) (added, removed []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	running := f.running
	f.mu.Unlock()
	for _, line := range frrtext.Diff(frrtext.Normalize(running), frrtext.Normalize(string(data))) {
		switch {
		case strings.HasPrefix(line, "+ "):
			added = append(added, strings.TrimPrefix(line, "+ "))
		case strings.HasPrefix(line, "- "):
			removed = append(removed, strings.TrimPrefix(line, "- "))
		}
	}
	return added, removed, nil
}

func (f *fakeFRR) Reload(ctx context.Context, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	if f.reloadErr != nil {
		if err := f.reloadErr(path); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.running = string(data)
	if f.reloadWrites != nil {
		f.running = f.reloadWrites(f.running)
	}
	return nil
}

// Running wraps the configuration as vtysh displays it: a banner, the
// version and vtysh's own setting before it, and after it an empty block
// for a VRF device on the host and an end line.
func (f *fakeFRR) Running(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return "Building configuration...\n\nCurrent configuration:\n!\nfrr version 10.7.1\n" +
		"service integrated-vtysh-config\n" + f.running + "!\nvrf G000000010V\nexit-vrf\n!\nend\n", nil
}

func (f *fakeFRR) set(running string) {
	f.mu.Lock()
	f.running = running
	f.mu.Unlock()
}

func (f *fakeFRR) get() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

var errCrash = errors.New("crash")

func withActivation(act Activation, edit func(*Activation)) Activation {
	edit(&act)
	return act
}

func testIdentity() Identity {
	return Identity{NodeUID: testNode, MachineID: testMachine, ClusterID: testCluster}
}

// newActivator binds dir to the test identity and opens an activator over dir.
func newActivator(t *testing.T, dir string, frr *fakeFRR, now func() time.Time) *Activator {
	t.Helper()
	if _, err := BindIdentity(dir, testIdentity()); err != nil {
		t.Fatal(err)
	}
	a := &Activator{Dir: dir, FRR: frr, Now: now}
	if err := a.Open(); err != nil {
		t.Fatal(err)
	}
	return a
}

// rendered is a revision's configuration.
func rendered(t *testing.T, rev *networkv1alpha1.FabricRouterRevision) string {
	t.Helper()
	res, err := revision.Verify(rev)
	if err != nil {
		t.Fatal(err)
	}
	return res.Config
}

func recordTypes(j *Journal) []RecordType {
	out := make([]RecordType, 0, len(j.Records()))
	for _, rec := range j.Records() {
		out = append(out, rec.Type)
	}
	return out
}

func removeCheckpoint(dir string) error { return os.Remove(filepath.Join(dir, "checkpoint.json")) }
