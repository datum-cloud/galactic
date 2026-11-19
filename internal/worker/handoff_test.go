// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
)

// podOne is the pod a test's owner first calls from.
const podOne = "pod-1"

// handoffModule is a Local module that records the pod each claim's owner
// calls from and reports one handoff interface per claim, as the Local
// module reports a veth pair's NAT end.
type handoffModule struct {
	*fake.Module
	mu   sync.Mutex
	pods map[module.ClaimKey]string
}

func (m *handoffModule) Plan(ctx context.Context, scope module.Scope, desired []module.Claim) (module.Change, error) {
	m.mu.Lock()
	for _, c := range desired {
		m.pods[c.Key] = c.OwnerPod
	}
	m.mu.Unlock()
	return m.Module.Plan(ctx, scope, desired)
}

func (m *handoffModule) HandoffInterfaces(scope module.Scope) map[module.ClaimKey][]module.HandoffInterface {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[module.ClaimKey][]module.HandoffInterface{}
	for k := range m.pods {
		if k.VPC == scope.VPC {
			out[k] = []module.HandoffInterface{{Role: workerv1alpha1.HandoffRoleNAT, Name: "Gnat", Ifindex: 7}}
		}
	}
	return out
}

func (m *handoffModule) pod(k module.ClaimKey) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pods[k]
}

// TestHandoffInterfacesAndOwnerPod checks that a module's handoff
// interfaces reach the claim's status, and that a claim whose handoff serves
// no pod records only the pod it was requested from.
func TestHandoffInterfacesAndOwnerPod(t *testing.T) {
	e := newEnv(t)
	hm := &handoffModule{pods: map[module.ClaimKey]string{}}
	e.modules = func(h *fake.Host) []module.Module {
		hm.Module = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, h)
		return []module.Module{hm, fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, h)}
	}
	e.start()
	k := key(vpcA, "svc-a")
	fromPod := func(pod string) error {
		ctx := metadata.AppendToOutgoingContext(e.ctx(natSA), podMD, pod)
		_, err := e.api.Request(ctx, &workerv1alpha1.RequestRequest{Key: k, Generation: 1, Spec: veth("guest-a1")})
		return err
	}
	e.mustOK(fromPod(podOne))
	st := e.waitReady(mkey(vpcA, "svc-a"), 1)
	if got := st.GetHandoffInterfaces(); len(got) != 1 || got[0].GetRole() != workerv1alpha1.HandoffRoleNAT ||
		got[0].GetName() != "Gnat" || got[0].GetIfindex() != 7 {
		t.Fatalf("handoff interfaces = %v, want the NAT end", got)
	}
	if got := hm.pod(mkey(vpcA, "svc-a")); got != podOne {
		t.Fatalf("the module planned the claim for pod %q, want pod-1", got)
	}

	// A veth pair serves no pod: a call from another pod of the owner
	// changes nothing.
	e.idle()
	before := e.persisted()
	e.mustOK(fromPod("pod-2"))
	e.idle()
	for name, b := range e.persisted() {
		if before[name] != b {
			t.Fatalf("a duplicate Request from another pod rewrote %s", name)
		}
	}
	if got := hm.pod(mkey(vpcA, "svc-a")); got != podOne {
		t.Fatalf("the module planned the claim for pod %q, want pod-1", got)
	}
}

// TestRoutedLinkServesOnePod checks that a routed link's claim serves one
// pod: while that pod runs, a call from another pod of the owner is refused
// and changes nothing; once it is gone, the call moves the claim. A claim
// whose handoff serves no pod never records a move.
func TestRoutedLinkServesOnePod(t *testing.T) {
	e := newEnv(t)
	hm := &handoffModule{pods: map[module.ClaimKey]string{}}
	e.modules = func(h *fake.Host) []module.Module {
		hm.Module = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, h)
		return []module.Module{hm, fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, h)}
	}
	var mu sync.Mutex
	alive := map[string]bool{podOne: true}
	e.podAlive = func(uid string) bool {
		mu.Lock()
		defer mu.Unlock()
		return alive[uid]
	}
	e.start()
	k := key(vpcA, "svc-a")
	routed := spec(workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK, "guest-a1")
	fromPod := func(pod string, gen uint64) error {
		ctx := metadata.AppendToOutgoingContext(e.ctx(routedSA), podMD, pod)
		_, err := e.api.Request(ctx, &workerv1alpha1.RequestRequest{Key: k, Generation: gen, Spec: routed})
		return err
	}
	e.mustOK(fromPod(podOne, 1))
	e.waitReady(mkey(vpcA, "svc-a"), 1)
	e.idle()
	before := e.persisted()

	// A second pod, while the first runs: refused, with nothing changed.
	wantRefusal(t, fromPod("pod-2", 1), codes.FailedPrecondition, workerv1alpha1.ReasonClaimHeldByAnotherPod)
	ctx := metadata.AppendToOutgoingContext(e.ctx(routedSA), podMD, "pod-2")
	_, err := e.api.Update(ctx, &workerv1alpha1.UpdateRequest{Key: k, Generation: 2, Spec: routed})
	wantRefusal(t, err, codes.FailedPrecondition, workerv1alpha1.ReasonClaimHeldByAnotherPod)
	e.idle()
	for name, b := range e.persisted() {
		if before[name] != b {
			t.Fatalf("a refused call from another pod rewrote %s", name)
		}
	}
	if got := hm.pod(mkey(vpcA, "svc-a")); got != podOne {
		t.Fatalf("the claim serves %q after a refused call, want pod-1", got)
	}

	// The first pod is gone: the next call moves the claim.
	mu.Lock()
	delete(alive, podOne)
	mu.Unlock()
	e.mustOK(fromPod("pod-2", 1))
	e.eventually("the claim follows the owner's new pod", func() bool { return hm.pod(mkey(vpcA, "svc-a")) == "pod-2" })
	recorded := false
	for name, b := range e.persisted() {
		if strings.HasPrefix(name, "claims/") && strings.Contains(b, `"podUID":"pod-2"`) {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("the claim's new pod was not recorded durably")
	}
}
