// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
	"go.datum.net/galactic/internal/worker/refusal"
	"go.datum.net/galactic/internal/worker/sources"
	"go.datum.net/galactic/internal/worker/store"
)

// Test identities and topology. Addresses are documentation prefixes.
const (
	node      = "node-a"
	otherNode = "node-b"
	vpcA      = "vpcA"
	vpcB      = "vpcB"

	natSA   = "galactic-system/nat"
	gwSA    = "galactic-system/gateway"
	otherSA = "galactic-system/other"

	callerMD = "x-test-caller"
)

var (
	locA = netip.MustParsePrefix("2001:db8:0:1::/64")
	locB = netip.MustParsePrefix("2001:db8:0:2::/64")

	testCaps = map[string][]string{
		natSA:   {workerv1alpha1.CapabilityLocalVethPair, workerv1alpha1.CapabilityFabricSRv6},
		gwSA:    {workerv1alpha1.CapabilityLocalTap},
		otherSA: {workerv1alpha1.CapabilityLocalVethPair, workerv1alpha1.CapabilityFabricSRv6},
	}
)

// metaAuth authenticates a test caller named in metadata.
type metaAuth struct{}

func (metaAuth) Authenticate(ctx context.Context) (auth.Caller, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get(callerMD)
	if len(v) != 1 {
		return auth.Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity, "no caller", nil)
	}
	caps, ok := testCaps[v[0]]
	if !ok {
		return auth.Caller{}, refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed,
			"not listed", nil)
	}
	return auth.Caller{ServiceAccount: v[0], Capabilities: caps}, nil
}

// faultyStore fails chosen operations once, standing in for a crash at
// that point.
type faultyStore struct {
	store.Store
	failDelete atomic.Int32
	failPut    atomic.Int32
}

var errInjectedStore = errors.New("injected store failure")

func (f *faultyStore) Put(r store.Record) error {
	if f.failPut.Load() > 0 {
		f.failPut.Add(-1)
		return errInjectedStore
	}
	return f.Store.Put(r)
}

func (f *faultyStore) Delete(n, v, a string) error {
	if f.failDelete.Load() > 0 {
		f.failDelete.Add(-1)
		return errInjectedStore
	}
	return f.Store.Delete(n, v, a)
}

// env is one Worker over persistent test state that survives restarts.
type env struct {
	t        *testing.T
	stateDir string
	fenceDir string
	host     *fake.Host
	src      *sources.Static
	store    *faultyStore
	fence    *ownership.Authority
	cfg      Config
	clock    *clock
	modules  func(*fake.Host) []module.Module
	// pauseOnStart pauses the Local module's Plan before Start, so the
	// first reconcile of a restart holds until the test resumes it.
	pauseOnStart bool
	startPaused  <-chan struct{}

	// Per incarnation.
	w      *Worker
	local  *fake.Module
	fabric *fake.Module
	cancel context.CancelFunc
	srv    *grpc.Server
	cc     *grpc.ClientConn
	api    workerv1alpha1.WorkerClient

	mu       sync.Mutex
	sessions map[string]string
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "claims"))
	if err != nil {
		t.Fatal(err)
	}
	fence, err := ownership.New(filepath.Join(dir, "ownership"))
	if err != nil {
		t.Fatal(err)
	}
	src := sources.NewStatic()
	src.SetLocator(node, locA)
	src.SetLocator(otherNode, locB)
	// The service's handoff attachment and guests in two VPCs that use the
	// same guest addresses; only VPC identity tells them apart.
	for _, a := range []sources.Attachment{
		{UID: "svc-a", VPC: vpcA, Node: node},
		{UID: "svc-a2", VPC: vpcA, Node: node},
		{UID: "svc-b", VPC: vpcB, Node: node},
		{UID: "guest-a1", VPC: vpcA, Node: node},
		{UID: "guest-a2", VPC: vpcA, Node: otherNode},
		{UID: "guest-a3", VPC: vpcA, Node: node},
		{UID: "guest-b1", VPC: vpcB, Node: node},
	} {
		a.Kind, a.Admitted = sources.KindVPCAttachment, true
		src.SetAttachment(a)
	}
	e := &env{
		t: t, stateDir: filepath.Join(dir, "claims"), fenceDir: filepath.Join(dir, "ownership"),
		host: fake.NewHost(), src: src, store: &faultyStore{Store: st}, fence: fence,
		clock: &clock{now: time.Unix(1_700_000_000, 0)},
		cfg: Config{Node: node, RetryMin: 5 * time.Millisecond, RetryMax: 50 * time.Millisecond,
			ResyncInterval: time.Hour, RenewInterval: time.Hour, Lease: 2 * time.Hour},
	}
	t.Cleanup(e.crash)
	return e
}

// start starts a new Worker incarnation with fresh module objects over the
// persistent host.
func (e *env) start() {
	e.t.Helper()
	e.local = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, e.host)
	e.fabric = fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, e.host)
	if e.pauseOnStart {
		e.startPaused = e.local.PausePlan()
	}
	mods := []module.Module{e.local, e.fabric}
	if e.modules != nil {
		mods = e.modules(e.host)
	}
	reg, err := module.NewRegistry(mods...)
	if err != nil {
		e.t.Fatal(err)
	}
	w, err := New(e.cfg, Deps{Store: e.store, Fence: e.fence, Sources: e.src, Modules: reg, Auth: metaAuth{},
		Now: e.clock.Now})
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		cancel()
		e.t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	w.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///worker",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		e.t.Fatal(err)
	}
	e.w, e.cancel, e.srv, e.cc, e.api = w, cancel, srv, cc, workerv1alpha1.NewWorkerClient(cc)
	e.mu.Lock()
	e.sessions = map[string]string{}
	e.mu.Unlock()
}

// crash stops the incarnation without any cleanup, as a killed process
// would. Host, store and fence state stay.
func (e *env) crash() {
	if e.cancel == nil {
		return
	}
	e.cancel()
	e.srv.Stop()
	_ = e.cc.Close()
	e.cancel = nil
	if e.local != nil {
		e.local.Resume()
		e.local.ResumePlan()
	}
}

// ctx returns a call context for caller with a live session.
func (e *env) ctx(caller string) context.Context {
	e.t.Helper()
	e.mu.Lock()
	id := e.sessions[caller]
	e.mu.Unlock()
	if id == "" {
		resp, err := e.api.GetCapabilities(metadata.AppendToOutgoingContext(context.Background(), callerMD, caller),
			&workerv1alpha1.GetCapabilitiesRequest{Versions: []string{workerv1alpha1.Version}})
		if err != nil {
			e.t.Fatalf("GetCapabilities(%s): %v", caller, err)
		}
		id = resp.GetSessionId()
		e.mu.Lock()
		e.sessions[caller] = id
		e.mu.Unlock()
	}
	return metadata.AppendToOutgoingContext(context.Background(), callerMD, caller,
		workerv1alpha1.SessionMetadataKey, id)
}

func key(vpc, att string) *workerv1alpha1.ClaimKey {
	return &workerv1alpha1.ClaimKey{Node: node, Vpc: vpc, AttachmentUid: att}
}

func mkey(vpc, att string) module.ClaimKey {
	return module.ClaimKey{Node: node, VPC: vpc, AttachmentUID: att}
}

func spec(h workerv1alpha1.Handoff, uids ...string) *workerv1alpha1.ClaimSpec {
	s := &workerv1alpha1.ClaimSpec{Handoff: h}
	for _, u := range uids {
		s.Destinations = append(s.Destinations, &workerv1alpha1.Destination{
			Target: &workerv1alpha1.Destination_Attachment{Attachment: &workerv1alpha1.AttachmentRef{Uid: u}}})
	}
	return s
}

func veth(uids ...string) *workerv1alpha1.ClaimSpec {
	return spec(workerv1alpha1.Handoff_HANDOFF_VETH_PAIR, uids...)
}

func (e *env) request(caller string, k *workerv1alpha1.ClaimKey, gen uint64, s *workerv1alpha1.ClaimSpec) error {
	_, err := e.api.Request(e.ctx(caller), &workerv1alpha1.RequestRequest{Key: k, Generation: gen, Spec: s})
	return err
}

func (e *env) update(caller string, k *workerv1alpha1.ClaimKey, gen uint64, s *workerv1alpha1.ClaimSpec) error {
	_, err := e.api.Update(e.ctx(caller), &workerv1alpha1.UpdateRequest{Key: k, Generation: gen, Spec: s})
	return err
}

func (e *env) release(caller string, k *workerv1alpha1.ClaimKey, gen uint64) error {
	_, err := e.api.Release(e.ctx(caller), &workerv1alpha1.ReleaseRequest{Key: k, Generation: gen})
	return err
}

func (e *env) mustOK(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatalf("unexpected error: %v", err)
	}
}

func wantRefusal(t *testing.T, err error, code codes.Code, reason string) {
	t.Helper()
	if status.Code(err) != code || refusal.Reason(err) != reason {
		t.Fatalf("got %v (reason %q), want %s/%s", err, refusal.Reason(err), code, reason)
	}
}

// status returns a copy of the claim's status, or nil.
func (e *env) status(k module.ClaimKey) *workerv1alpha1.ClaimStatus {
	e.w.mu.Lock()
	defer e.w.mu.Unlock()
	c := e.w.claims[k]
	if c == nil {
		return nil
	}
	return proto.Clone(c.status).(*workerv1alpha1.ClaimStatus)
}

func condOf(st *workerv1alpha1.ClaimStatus, t string) *workerv1alpha1.Condition {
	for _, c := range st.GetConditions() {
		if c.GetType() == t {
			return c
		}
	}
	return nil
}

func isTrue(st *workerv1alpha1.ClaimStatus, t string) bool {
	return condOf(st, t).GetStatus() == condTrue
}

// eventually polls cond until it holds or the deadline passes.
func (e *env) eventually(what string, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitReady waits for a claim to be Ready at gen.
func (e *env) waitReady(k module.ClaimKey, gen uint64) *workerv1alpha1.ClaimStatus {
	e.t.Helper()
	var st *workerv1alpha1.ClaimStatus
	e.eventually("claim "+k.String()+" ready", func() bool {
		st = e.status(k)
		return st.GetObservedGeneration() == gen && isTrue(st, workerv1alpha1.ConditionReady)
	})
	return st
}

// waitObserved waits for a claim to report on its first generation.
func (e *env) waitObserved(k module.ClaimKey) *workerv1alpha1.ClaimStatus {
	const gen = 1
	e.t.Helper()
	var st *workerv1alpha1.ClaimStatus
	e.eventually("claim "+k.String()+" observed", func() bool {
		st = e.status(k)
		return st.GetObservedGeneration() == gen && condOf(st, workerv1alpha1.ConditionProgrammed).GetStatus() != condUnknown
	})
	return st
}

// waitGone waits for a released claim to be deleted.
func (e *env) waitGone(k module.ClaimKey) {
	e.t.Helper()
	e.eventually("claim "+k.String()+" released", func() bool { return e.status(k) == nil })
}

// idle waits until the queue holds no work.
func (e *env) idle() {
	e.t.Helper()
	e.eventually("queue idle", func() bool { return e.w.queue.Len() == 0 })
	time.Sleep(20 * time.Millisecond)
	e.eventually("queue idle", func() bool { return e.w.queue.Len() == 0 })
}

// persisted is a byte snapshot of the store and fence directories.
func (e *env) persisted() map[string]string {
	e.t.Helper()
	out := map[string]string{}
	for _, dir := range []string{e.stateDir, e.fenceDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			e.t.Fatal(err)
		}
		for _, ent := range entries {
			b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
			if err != nil {
				e.t.Fatal(err)
			}
			out[filepath.Join(filepath.Base(dir), ent.Name())] = string(b)
		}
	}
	return out
}

func rowIDs(rows []fake.Row) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Key.AttachmentUID+"→"+r.ID)
	}
	sort.Strings(out)
	return out
}
