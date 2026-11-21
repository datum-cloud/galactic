// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/worker"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
	"go.datum.net/galactic/internal/worker/sources"
	"go.datum.net/galactic/internal/worker/store"
	"go.datum.net/galactic/pkg/workerclient"
)

// The connector fixture (D14, D37) runs the agent against a real Worker,
// whose reconciliation, admission, ownership and status are the production
// code's. Its Local module is the fake one, which records what Worker asks
// it to program, so the fixture proves the agent and Worker protocol, the
// ownership transfer and the authority checks, not the kernel rows: the
// Local module's root tests and the lab do that.

const (
	edgeSA = "galactic-system/galactic-edge"
	uid1   = "uid-1"
)

// edgeCaller authenticates every call as galactic-edge's ServiceAccount.
type edgeCaller struct{}

func (edgeCaller) Authenticate(context.Context) (auth.Caller, error) {
	return auth.Caller{ServiceAccount: edgeSA, PodUID: "galactic-edge-pod",
		Capabilities: []string{workerv1alpha1.CapabilityLocalRoutedLink}}, nil
}

// fixtureLinkGates is LinkGates on the fixture's in-memory gates.
type fixtureLinkGates struct{ g *gates }

func (f fixtureLinkGates) SetLink(i uint32, a netip.Addr) error { f.g.setLink(i, a); return nil }
func (f fixtureLinkGates) DeleteGates(i uint32) error           { f.g.deleteGates(i); return nil }
func (f fixtureLinkGates) DeleteLink(i uint32) error            { return f.g.DeleteLink(i) }

// workerFixture is a running Worker over the fixture's ownership directory.
type workerFixture struct {
	t      *testing.T
	f      *fixture
	src    *sources.Static
	local  *fake.Module
	host   *fake.Host
	w      *worker.Worker
	socket string
	stop   func()
}

func (f *fixture) startWorker() *workerFixture {
	f.t.Helper()
	wf := &workerFixture{t: f.t, f: f, src: sources.NewStatic(), host: fake.NewHost()}
	wf.src.SetLocator(node, netip.MustParsePrefix("2001:db8:0:1::/64"))
	dir, err := os.MkdirTemp("", "gw")
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = os.RemoveAll(dir) })
	wf.socket = filepath.Join(dir, "w.sock")
	wf.start(dir)
	return wf
}

func (wf *workerFixture) start(dir string) {
	t := wf.t
	st, err := store.Open(filepath.Join(dir, "claims"))
	if err != nil {
		t.Fatal(err)
	}
	fence, err := ownership.New(wf.f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	wf.local = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, wf.host)
	reg, err := module.NewRegistry(wf.local, fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, wf.host))
	if err != nil {
		t.Fatal(err)
	}
	w, err := worker.New(worker.Config{Node: node, RetryMin: 5 * time.Millisecond, RetryMax: 50 * time.Millisecond,
		ResyncInterval: time.Hour, Lease: time.Hour, RenewInterval: time.Minute},
		worker.Deps{Store: st, Fence: fence, Sources: wf.src, Modules: reg, Auth: edgeCaller{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = os.Remove(wf.socket)
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", wf.socket)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	w.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	wf.w = w
	wf.stop = func() {
		cancel()
		srv.Stop()
		w.Wait()
	}
	t.Cleanup(func() {
		if wf.stop != nil {
			wf.stop()
		}
	})
}

// admit records att in Worker's trusted sources as core leaves it.
func (wf *workerFixture) admit(att *galacticv1alpha1.EdgeAttachment, admitted bool) {
	wf.src.SetAttachment(sources.Attachment{UID: string(att.UID), Kind: sources.KindEdgeAttachment,
		VPC: att.Status.VPC, Node: node, Admitted: admitted,
		Addresses: []netip.Addr{netip.MustParseAddr(att.Status.Address)}})
	wf.w.Changed(att.Status.VPC)
}

// rows returns the attachment UIDs Worker's Local module holds rows for in
// vpcA.
func (wf *workerFixture) rows() []string {
	var out []string
	for _, r := range wf.host.Rows(vpcA) {
		if r.ID == "attachment/"+r.Key.AttachmentUID {
			out = append(out, r.Key.AttachmentUID)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// edgeLink returns the edge link Worker's Local module was last asked to
// program for uid in vpc.
func (wf *workerFixture) edgeLink(vpc, uid string) *module.EdgeLink {
	for _, c := range wf.local.Desired(vpc) {
		if c.Key.AttachmentUID == uid {
			return c.EdgeLink
		}
	}
	return nil
}

// connectorAgent returns a new agent process whose datapath is Worker.
func (f *fixture) connectorAgent(wf *workerFixture) *Agent {
	f.t.Helper()
	c := &WorkerConn{Dial: func(ctx context.Context) (*workerclient.Client, error) {
		return workerclient.Dial(ctx, workerclient.Options{SocketPath: wf.socket,
			Token:    func() (string, error) { return "token", nil },
			RetryMin: time.Millisecond, RetryMax: 10 * time.Millisecond, Attempts: 2})
	}}
	f.t.Cleanup(func() { _ = c.Close() })
	dp := &WorkerDatapath{Client: c, Node: node, Gates: fixtureLinkGates{f.gates}, Wait: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = dp.Run(ctx); close(done) }()
	f.t.Cleanup(func() { cancel(); <-done })
	a := f.agent()
	a.Datapath = dp
	return a
}

func (f *fixture) wantCondition(name, typ string, st metav1.ConditionStatus, reason string) {
	f.t.Helper()
	c := f.condition(name, typ)
	if c == nil || c.Status != st || (reason != "" && c.Reason != reason) {
		f.t.Fatalf("%s %s = %+v, want %s/%s", name, typ, c, st, reason)
	}
}

func (wf *workerFixture) eventually(what string, cond func() bool) {
	wf.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			wf.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestConnectorAttachDeliverWithdraw attaches an authorized attachment
// through Worker, delivers a held route's prefix through its claim, and
// withdraws everything when the attachment is deleted.
func TestConnectorAttachDeliverWithdraw(t *testing.T) {
	f := newFixture(t)
	wf := f.startWorker()
	a := f.connectorAgent(wf)
	f.pod("pod-1")
	att := f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false)
	wf.admit(att, true)

	f.reconcile(a)
	f.programmed("a1")
	if got := wf.rows(); !slices.Equal(got, []string{uid1}) {
		t.Fatalf("Worker rows = %v", got)
	}
	if el := wf.edgeLink(vpcA, uid1); el == nil || el.Name != f.links()[0].HostLink {
		t.Fatalf("edge link = %+v, want host link %s", el, f.links()[0].HostLink)
	}
	if idx := f.hostLink("a1").Attrs().Index; !f.gatedAs(uint32(idx), "2001:db8:100::10") {
		t.Fatal("the link's gate row does not name its address")
	}

	// Delivery: a route this attachment holds is carried on the link.
	f.acceptRoute(t, "r1", "2001:db8:200::/48", uid1)
	f.reconcile(a)
	wf.eventually("the held prefix in the claim", func() bool {
		el := wf.edgeLink(vpcA, uid1)
		return el != nil && slices.Contains(el.Prefixes, netip.MustParsePrefix("2001:db8:200::/48"))
	})

	// Withdrawal.
	if err := f.client.Delete(context.Background(), f.get("a1")); err != nil {
		t.Fatal(err)
	}
	f.reconcile(a)
	f.wantCondition("a1", galacticv1alpha1.EdgeAttachmentReleased, metav1.ConditionTrue, ReasonReleased)
	if got := wf.rows(); len(got) != 0 {
		t.Fatalf("Worker rows after withdrawal = %v", got)
	}
	if len(f.links()) != 0 {
		t.Fatalf("links after withdrawal = %v", f.links())
	}
}

// TestConnectorReplacement replaces an attachment with a new one for the
// same pod: the old claim is released, the new one attached on its own link.
func TestConnectorReplacement(t *testing.T) {
	f := newFixture(t)
	wf := f.startWorker()
	a := f.connectorAgent(wf)
	f.pod("pod-1")
	wf.admit(f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false), true)
	f.reconcile(a)
	f.programmed("a1")

	if err := f.client.Delete(context.Background(), f.get("a1")); err != nil {
		t.Fatal(err)
	}
	wf.src.DeleteAttachment(uid1)
	wf.admit(f.attach("a2", "uid-2", "pod-1", vpcA, "2001:db8:100::11", false), true)
	f.reconcile(a)
	f.reconcile(a)
	f.programmed("a2")
	if got := wf.rows(); !slices.Equal(got, []string{"uid-2"}) {
		t.Fatalf("Worker rows after replacement = %v", got)
	}
	// A replay of the replaced attachment's claim is refused.
	dp := a.Datapath.(*WorkerDatapath)
	err := dp.Prepare(Link{VPC: vpcA, AttachmentUID: uid1, Name: "Ereplayed"})
	var we *WorkerError
	if !errors.As(err, &we) || we.WorkerReason != workerv1alpha1.ReasonVPCNotAuthorized {
		t.Fatalf("replayed claim = %v, want refused with VPCNotAuthorized", err)
	}
}

// TestConnectorDenied creates no link for an attachment Worker does not
// authorize, and reports why.
func TestConnectorDenied(t *testing.T) {
	f := newFixture(t)
	wf := f.startWorker()
	a := f.connectorAgent(wf)
	f.pod("pod-1")
	wf.admit(f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false), false)
	if err := a.Reconcile(context.Background()); err != nil {
		t.Logf("reconcile: %v", err)
	}
	f.wantCondition("a1", galacticv1alpha1.EdgeAttachmentProgrammed, metav1.ConditionFalse, ReasonWorkerRefused)
	if len(f.links()) != 0 {
		t.Fatalf("links of a denied attachment = %v", f.links())
	}
	if got := wf.rows(); len(got) != 0 {
		t.Fatalf("Worker rows of a denied attachment = %v", got)
	}
}

// TestConnectorRevoked withdraws a programmed link's rows when core revokes
// the attachment, and the agent reports the refusal of its next claim.
func TestConnectorRevoked(t *testing.T) {
	f := newFixture(t)
	wf := f.startWorker()
	a := f.connectorAgent(wf)
	f.pod("pod-1")
	att := f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false)
	wf.admit(att, true)
	f.reconcile(a)
	f.programmed("a1")

	wf.admit(att, false)
	wf.eventually("Worker to withdraw the revoked claim", func() bool { return len(wf.rows()) == 0 })
	_ = a.Reconcile(context.Background())
	f.wantCondition("a1", galacticv1alpha1.EdgeAttachmentProgrammed, metav1.ConditionFalse, ReasonWorkerRefused)
	if got := wf.rows(); len(got) != 0 {
		t.Fatalf("Worker rows after revocation = %v", got)
	}
}

// TestConnectorHandover hands a scope a PinnedDatapath process owns to
// Worker: the new process claims the live link, gives the scope up, and
// Worker takes it with the link's claim, while the link's pinned rows are
// never unregistered.
func TestConnectorHandover(t *testing.T) {
	f := newFixture(t)
	pinned := f.agent()
	f.pod("pod-1")
	att := f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false)
	f.reconcile(pinned)
	f.programmed("a1")
	unregistered := len(f.dp.unregistered)

	wf := f.startWorker()
	wf.admit(att, true)
	a := f.connectorAgent(wf)
	f.reconcile(a)
	f.programmed("a1")
	rec, err := a.Ownership.Read(ownership.VPCScope(vpcA))
	if err != nil {
		t.Fatal(err)
	}
	if !ownership.WorkerOwned(rec.Owner) {
		t.Fatalf("VPC scope owner after handover = %q, want a Worker incarnation", rec.Owner)
	}
	if got := wf.rows(); !slices.Equal(got, []string{uid1}) {
		t.Fatalf("Worker rows after handover = %v", got)
	}
	if len(f.dp.unregistered) != unregistered {
		t.Fatalf("the handover unregistered links %v", f.dp.unregistered[unregistered:])
	}
	// The PinnedDatapath process lost the scope and never writes it again.
	if err := pinned.Reconcile(context.Background()); err == nil {
		t.Fatal("the PinnedDatapath process reconciled a scope Worker owns")
	}
	if pinned.Healthy(nil) == nil {
		t.Fatal("the PinnedDatapath process is healthy after losing its scope")
	}
}

// TestConnectorRollback hands Worker's scope back after Worker stops, as
// galactic-worker handback does, and a PinnedDatapath process takes it over
// and registers the link again.
func TestConnectorRollback(t *testing.T) {
	f := newFixture(t)
	wf := f.startWorker()
	a := f.connectorAgent(wf)
	f.pod("pod-1")
	wf.admit(f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false), true)
	f.reconcile(a)
	f.programmed("a1")
	wf.stop()
	wf.stop = nil

	fence, err := ownership.New(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fence.Relinquish(ownership.VPCScope(vpcA), func(r ownership.Record) bool {
		return ownership.WorkerOwned(r.Owner)
	}, ownership.HandbackOwnerPrefix+"1"); err != nil {
		t.Fatal(err)
	}
	pinned := f.agent()
	f.reconcile(pinned)
	f.programmed("a1")
	rec, err := fence.Read(ownership.VPCScope(vpcA))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Owner != pinned.Owner {
		t.Fatalf("VPC scope owner after rollback = %q, want the PinnedDatapath process", rec.Owner)
	}
	if _, ok := f.dp.table(f.hostLink("a1").Attrs().Index); !ok {
		t.Fatal("the PinnedDatapath process did not register the link again")
	}
}

// TestConnectorGateScopeFencesOlderProcess refuses a gate an older process
// commits once a newer one has taken the edge gate scope.
func TestConnectorGateScopeFencesOlderProcess(t *testing.T) {
	f := newFixture(t)
	wf := f.startWorker()
	older := f.connectorAgent(wf)
	newer := f.connectorAgent(wf)
	noop := func() error { return nil }
	if err := older.gateCommit(vpcA, true, noop); err != nil {
		t.Fatal(err)
	}
	if err := newer.gateCommit(vpcA, true, noop); err != nil {
		t.Fatal(err)
	}
	if err := older.gateCommit(vpcA, true, func() error {
		t.Error("the older process's gate write ran")
		return nil
	}); !errors.Is(err, ownership.ErrNotOwner) {
		t.Fatalf("older process's gate commit = %v, want ErrNotOwner", err)
	}
	if older.Healthy(nil) == nil {
		t.Fatal("the fenced process is healthy")
	}
}

// TestConnectorWorkerDown keeps an attachment whose link Worker registered
// Programmed while Worker is down, in the running process and in one that
// starts during the outage, and programs no new attachment until Worker is
// back.
func TestConnectorWorkerDown(t *testing.T) {
	f := newFixture(t)
	wf := f.startWorker()
	a := f.connectorAgent(wf)
	f.pod("pod-1")
	f.pod("pod-2")
	wf.admit(f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false), true)
	f.reconcile(a)
	f.programmed("a1")
	links := len(f.links())

	wf.stop()
	wf.stop = nil
	_ = a.Reconcile(context.Background())
	f.wantCondition("a1", galacticv1alpha1.EdgeAttachmentProgrammed, metav1.ConditionTrue, ReasonProgrammed)

	restarted := f.connectorAgent(wf)
	f.attach("a2", "uid-2", "pod-2", vpcA, "2001:db8:100::11", false)
	_ = restarted.Reconcile(context.Background())
	f.wantCondition("a1", galacticv1alpha1.EdgeAttachmentProgrammed, metav1.ConditionTrue, ReasonProgrammed)
	f.wantCondition("a2", galacticv1alpha1.EdgeAttachmentProgrammed, metav1.ConditionFalse, ReasonWorkerUnavailable)
	if got := len(f.links()); got != links {
		t.Fatalf("links during the outage = %d, want %d: none removed, none added", got, links)
	}
	if idx := f.hostLink("a1").Attrs().Index; !f.gatedAs(uint32(idx), "2001:db8:100::10") {
		t.Fatal("the registered link lost its gate row during the outage")
	}
}

// TestConnectorNewerPassFencesOlderProcess fences an older process on the
// edge gate scope with the newer process's first scope pass, before the newer
// one commits any gate, in both modes.
func TestConnectorNewerPassFencesOlderProcess(t *testing.T) {
	for _, withWorker := range []bool{false, true} {
		t.Run(map[bool]string{false: "pinned", true: "worker"}[withWorker], func(t *testing.T) {
			f := newFixture(t)
			var wf *workerFixture
			agent := f.agent
			if withWorker {
				wf = f.startWorker()
				agent = func() *Agent { return f.connectorAgent(wf) }
			}
			f.pod("pod-1")
			att := f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false)
			if withWorker {
				wf.admit(att, true)
			}
			older := agent()
			f.reconcile(older)
			f.programmed("a1")
			newer := agent()
			f.reconcile(newer)
			f.programmed("a1")
			if err := older.gateCommit(vpcA, true, func() error {
				t.Error("the older process's gate write ran")
				return nil
			}); !errors.Is(err, ownership.ErrNotOwner) {
				t.Fatalf("older process's gate commit = %v, want ErrNotOwner", err)
			}
			if err := older.Reconcile(context.Background()); err == nil {
				t.Fatal("the fenced process reconciled the VPC")
			}
			f.programmed("a1")
			if older.Healthy(nil) == nil {
				t.Fatal("the fenced process is healthy")
			}
		})
	}
}

// TestConnectorTransferSkipsRefusedClaim hands a scope to Worker although
// Worker refuses one live link's claim: the authorized link keeps its claim
// and its status, and Worker does not program the refused one.
func TestConnectorTransferSkipsRefusedClaim(t *testing.T) {
	f := newFixture(t)
	pinned := f.agent()
	f.pod("pod-1")
	f.pod("pod-2")
	a1 := f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false)
	a2 := f.attach("a2", "uid-2", "pod-2", vpcA, "2001:db8:100::11", false)
	f.reconcile(pinned)
	f.programmed("a1")
	f.programmed("a2")

	wf := f.startWorker()
	wf.admit(a1, true)
	wf.admit(a2, false)
	a := f.connectorAgent(wf)
	_ = a.Reconcile(context.Background())
	rec, err := a.Ownership.Read(ownership.VPCScope(vpcA))
	if err != nil {
		t.Fatal(err)
	}
	if !ownership.WorkerOwned(rec.Owner) {
		t.Fatalf("VPC scope owner = %q, want Worker: a refused claim stopped the transfer", rec.Owner)
	}
	f.programmed("a1")
	if got := wf.rows(); !slices.Equal(got, []string{uid1}) {
		t.Fatalf("Worker rows = %v, want only the authorized link's", got)
	}
	f.wantCondition("a2", galacticv1alpha1.EdgeAttachmentProgrammed, metav1.ConditionFalse, ReasonWorkerRefused)
}

// TestConnectorTransferWorkerDown leaves a scope galactic-edge holds, and the
// status of its Programmed attachments, as they are while Worker cannot be
// reached at the transfer; a new attachment waits as WorkerUnavailable.
func TestConnectorTransferWorkerDown(t *testing.T) {
	f := newFixture(t)
	pinned := f.agent()
	f.pod("pod-1")
	f.pod("pod-2")
	f.attach("a1", uid1, "pod-1", vpcA, "2001:db8:100::10", false)
	f.reconcile(pinned)
	f.programmed("a1")
	before, err := pinned.Ownership.Read(ownership.VPCScope(vpcA))
	if err != nil {
		t.Fatal(err)
	}

	wf := f.startWorker()
	wf.stop()
	wf.stop = nil
	a := f.connectorAgent(wf)
	f.attach("a2", "uid-2", "pod-2", vpcA, "2001:db8:100::11", false)
	if err := a.Reconcile(context.Background()); err == nil {
		t.Fatal("the pass reported no error with Worker down at the transfer")
	}
	after, err := a.Ownership.Read(ownership.VPCScope(vpcA))
	if err != nil {
		t.Fatal(err)
	}
	if after.Owner != before.Owner || after.Generation != before.Generation {
		t.Fatalf("VPC scope moved from %+v to %+v with Worker down", before, after)
	}
	f.programmed("a1")
	f.wantCondition("a2", galacticv1alpha1.EdgeAttachmentProgrammed, metav1.ConditionFalse, ReasonWorkerUnavailable)
	if a.Healthy(nil) != nil {
		t.Fatal("Worker's outage made galactic-edge unhealthy")
	}
}

// gatedAs reports whether ifindex's gate link row names addr.
func (f *fixture) gatedAs(ifindex uint32, addr string) bool {
	got, ok, _ := f.gates.Link(ifindex)
	return ok && got == netip.MustParseAddr(addr)
}

// acceptRoute creates a route core accepted on node for the attachment.
func (f *fixture) acceptRoute(t *testing.T, name, prefix, uid string) {
	t.Helper()
	rt := &galacticv1alpha1.EdgeRoute{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: edgeNS},
		Spec: galacticv1alpha1.EdgeRouteSpec{Prefix: prefix}}
	if err := f.client.Create(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
	rt.Status.Accepted = &galacticv1alpha1.EdgeRouteHolder{Epoch: 1, AttachmentUID: uid, Node: node}
	if err := f.client.Status().Update(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
}
