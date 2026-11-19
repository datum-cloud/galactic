// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/metadata"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
)

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
// interfaces reach the claim's status, and that a duplicate Request from the
// owner's new pod records that pod, durably, and changes nothing else.
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
	e.mustOK(fromPod("pod-1"))
	st := e.waitReady(mkey(vpcA, "svc-a"), 1)
	if got := st.GetHandoffInterfaces(); len(got) != 1 || got[0].GetRole() != workerv1alpha1.HandoffRoleNAT ||
		got[0].GetName() != "Gnat" || got[0].GetIfindex() != 7 {
		t.Fatalf("handoff interfaces = %v, want the NAT end", got)
	}
	if got := hm.pod(mkey(vpcA, "svc-a")); got != "pod-1" {
		t.Fatalf("the module planned the claim for pod %q, want pod-1", got)
	}

	before := e.persisted()
	e.mustOK(fromPod("pod-2"))
	e.eventually("the claim follows the owner's new pod", func() bool { return hm.pod(mkey(vpcA, "svc-a")) == "pod-2" })
	after := e.persisted()
	recorded := false
	for name, b := range after {
		if strings.HasPrefix(name, "claims/") && strings.Contains(b, `"podUID":"pod-2"`) {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("the new pod was not recorded durably: before %v after %v", before, after)
	}
	e.idle()
	unchanged := e.persisted()
	e.mustOK(fromPod("pod-2"))
	e.idle()
	for name, b := range e.persisted() {
		if unchanged[name] != b {
			t.Fatalf("a duplicate Request from the same pod rewrote %s", name)
		}
	}
}
