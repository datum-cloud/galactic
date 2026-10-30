// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
)

type convergenceDatapath struct {
	gateway.NoopDatapath
	owned     map[netip.Addr]bool
	blocks    map[netip.Addr]int
	renewals  map[netip.Addr]int
	rows      map[string]gateway.DesiredRule
	failKey   string
	failRenew netip.Addr
	orphanErr error
	failOwned bool
	failBlock bool
}

func newConvergenceDatapath() *convergenceDatapath {
	return &convergenceDatapath{
		owned:    map[netip.Addr]bool{},
		blocks:   map[netip.Addr]int{},
		renewals: map[netip.Addr]int{},
		rows:     map[string]gateway.DesiredRule{},
	}
}
func (d *convergenceDatapath) SetOwnedVIPs(_ context.Context, addrs []netip.Addr) error {
	next := map[netip.Addr]bool{}
	for _, addr := range addrs {
		blocked, exists := d.owned[addr]
		next[addr] = !exists || blocked
	}
	d.owned = next
	if d.failOwned {
		return errors.New("partial guard write failed")
	}
	return nil
}
func (d *convergenceDatapath) SetBlockedVIPs(_ context.Context, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return errors.New("global unblock is forbidden")
	}
	for _, addr := range addrs {
		if _, ok := d.owned[addr]; ok {
			d.owned[addr] = true
			d.blocks[addr]++
		}
	}
	if d.failBlock {
		return errors.New("partial block write failed")
	}
	return nil
}
func (d *convergenceDatapath) RenewVIPs(_ context.Context, addrs []netip.Addr) error {
	for _, addr := range addrs {
		if addr == d.failRenew {
			return errors.New("renewal failed")
		}
		d.owned[addr] = false
		d.renewals[addr]++
	}
	return nil
}
func (d *convergenceDatapath) ApplyRule(_ context.Context, rule gateway.DesiredRule) error {
	d.rows[rule.Key] = rule
	if rule.Key == d.failKey {
		return errors.New("partial write failed")
	}
	return nil
}
func (d *convergenceDatapath) RemoveRule(_ context.Context, key string) error {
	if key == d.failKey {
		return errors.New("removal failed")
	}
	delete(d.rows, key)
	return nil
}

type convergenceFixture struct {
	r         *NetworkGatewayReconciler
	d         *convergenceDatapath
	addresses []*api.NetworkServiceAddress
	rules     []api.NetworkService
	desired   gateway.EngineState
}

func newConvergenceFixture(t *testing.T) convergenceFixture {
	t.Helper()
	a, ar := sharedAddressFixture()
	b, br := sharedAddressFixture()
	b.Name, b.UID, b.Spec.VIPAddress, b.Spec.Group.UID = "address-b", "anchor-b", "2001:db8::2", "allocation-b"
	br.Name, br.UID, br.Spec.VIPAddresses, br.Spec.AddressGroup = b.Name, "rule-b", []string{
		b.Spec.VIPAddress,
	}, b.Spec.Group.DeepCopy()
	br.Spec.AddressGroup.ListenerName = testSharedControl
	c := fake.NewClientBuilder().WithScheme(newRuleTestScheme(t)).WithStatusSubresource(a, ar, b, br).
		WithObjects(a, ar, b, br).Build()
	d := newConvergenceDatapath()
	engine := gateway.NewEngine(d, gateway.NoopQuotaEnforcer{}, gateway.NoopTelemetryEmitter{})
	r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
	desired := gateway.EngineState{Rules: map[string]gateway.DesiredRule{}}
	for _, rule := range []*api.NetworkService{ar, br} {
		key := rule.Namespace + "/" + rule.Name
		desired.Rules[key] = gateway.DesiredRule{
			Key:          key,
			VIPAddresses: []netip.Addr{netip.MustParseAddr(rule.Spec.VIPAddresses[0])},
			Protocol:     "tcp",
			Port:         443,
			Backends:     []gateway.DesiredBackend{{Address: netip.MustParseAddr("fd00::1")}},
		}
	}
	return convergenceFixture{
		r:         r,
		d:         d,
		addresses: []*api.NetworkServiceAddress{a, b},
		rules:     []api.NetworkService{*ar, *br},
		desired:   desired,
	}
}
func (f convergenceFixture) pass(t *testing.T) gateway.EngineStatus {
	t.Helper()
	ctx := context.Background()
	snapshot, err := f.r.prepareAddressInventory(ctx, testNamespace, f.rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.r.blockChangedAddressRules(ctx, f.desired); err != nil {
		t.Fatal(err)
	}
	status, err := f.r.Engine.Reconcile(ctx, f.desired)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.r.finishAddressConvergence(ctx, newTestGateway(testNodeGWA), f.desired, &status, 0, snapshot); err != nil {
		t.Fatal(err)
	}
	return status
}
func TestSteadySharedVIPRenewalNeverBlocks(t *testing.T) {
	f := newConvergenceFixture(t)
	f.pass(t)
	addr := netip.MustParseAddr(f.addresses[0].Spec.VIPAddress)
	before := f.d.blocks[addr]
	f.pass(t)
	f.pass(t)
	if f.d.blocks[addr] != before || f.d.owned[addr] || f.d.renewals[addr] != 3 {
		t.Fatalf("renewal interrupted VIP: %+v %+v", f.d.blocks, f.d.renewals)
	}
}
func TestFailedOtherVIPDoesNotBlockHealthySharedVIP(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "OtherTenant", true: "Legacy"}[legacy], func(t *testing.T) {
			f := newConvergenceFixture(t)
			f.pass(t)
			healthy := netip.MustParseAddr(f.addresses[0].Spec.VIPAddress)
			before := f.d.blocks[healthy]
			key := f.rules[1].Namespace + "/" + f.rules[1].Name
			changed := f.desired.Rules[key]
			changed.Port = 8443
			if legacy {
				key = "legacy/broken"
				changed.Key = key
				changed.VIPAddresses = []netip.Addr{netip.MustParseAddr("2001:db8::99")}
			}
			f.desired.Rules[key] = changed
			f.d.failKey = key
			status := f.pass(t)
			if status.Healthy || !status.VIPConverged(healthy) || f.d.owned[healthy] || f.d.blocks[healthy] != before ||
				f.d.renewals[healthy] != 2 {
				t.Fatalf("unrelated failure interrupted healthy VIP: %+v %+v", status, f.d)
			}
			outcomes := make([]ruleOutcome, 0, len(f.rules))
			for i := range f.rules {
				rule := &f.rules[i]
				outcomes = append(
					outcomes,
					ruleOutcome{rule: rule, desired: f.desired.Rules[rule.Namespace+"/"+rule.Name]},
				)
			}
			if _, err := f.r.publishAddressOutcomes(context.Background(), testNamespace, f.r.confirmedAddresses,
				outcomes, status, testRouterName); err != nil {
				t.Fatal(err)
			}
			observed := &api.NetworkServiceAddress{}
			if err := f.r.Get(context.Background(), client.ObjectKeyFromObject(f.addresses[0]), observed); err != nil {
				t.Fatal(err)
			}
			if !meta.IsStatusConditionTrue(observed.Status.Conditions, programmedConditionType(testNodeGWA)) {
				t.Fatal("unrelated failure withdrew healthy address readiness")
			}
			f.pass(t)
			if f.d.blocks[healthy] != before || f.d.renewals[healthy] != 3 {
				t.Fatal("persistent failure interrupted healthy renewal")
			}
		})
	}
}
func TestChangedAuthorityBlocksOnlyItsVIPAndRejectsStaleRenewal(t *testing.T) {
	ctx := context.Background()
	f := newConvergenceFixture(t)
	f.pass(t)
	a, b := netip.MustParseAddr(f.addresses[0].Spec.VIPAddress), netip.MustParseAddr(f.addresses[1].Spec.VIPAddress)
	beforeB := f.d.blocks[b]
	current := &api.NetworkServiceAddress{}
	if err := f.r.Get(ctx, client.ObjectKeyFromObject(f.addresses[0]), current); err != nil {
		t.Fatal(err)
	}
	current.Generation++
	current.Spec.Group.Revision = "changed"
	if err := f.r.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.r.prepareAddressInventory(ctx, testNamespace, f.rules)
	if err != nil {
		t.Fatal(err)
	}
	if !f.d.owned[a] || f.d.owned[b] || f.d.blocks[b] != beforeB {
		t.Fatal("authority fence affected wrong VIP")
	}
	current.Generation++
	current.Spec.Retired = true
	if err := f.r.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	status := gateway.EngineStatus{Healthy: true}
	if err := f.r.finishAddressConvergence(ctx, newTestGateway(testNodeGWA), f.desired, &status, 0, snapshot); err != nil {
		t.Fatal(err)
	}
	if status.VIPConverged(a) || !status.VIPConverged(b) || !f.d.owned[a] || f.d.owned[b] || f.d.renewals[a] != 1 ||
		f.d.renewals[b] != 2 {
		t.Fatalf("stale revision renewed or unrelated VIP withheld: %+v %+v", status, f.d)
	}
}
func TestRestartFencesPreviouslyServingOwnedVIPs(t *testing.T) {
	f := newConvergenceFixture(t)
	f.pass(t)
	engine := gateway.NewEngine(f.d, gateway.NoopQuotaEnforcer{}, gateway.NoopTelemetryEmitter{})
	f.r = newGatewayReconciler(f.r.Client, f.r.Scheme, engine, testNodeGWA)
	if _, err := f.r.prepareAddressInventory(context.Background(), testNamespace, f.rules); err != nil {
		t.Fatal(err)
	}
	for _, blocked := range f.d.owned {
		if !blocked {
			t.Fatal("restart trusted prior process receipts")
		}
	}
	f.pass(t)
	for _, blocked := range f.d.owned {
		if blocked {
			t.Fatal("restart did not converge")
		}
	}
}
func TestProjectOffPreemptiveRetirementThroughGatewayReconcile(t *testing.T) {
	ctx := context.Background()
	address, _ := sharedAddressFixture()
	address.Namespace = testTenantNamespace
	address.Spec.Retired = true
	address.Spec.VPCRef = ""
	address.Spec.Group.Listeners = nil
	gw := newTestGateway(testNodeGWA)
	c := newIndexedClientBuilder(
		newRuleTestScheme(t),
	).WithStatusSubresource(address, gw).
		WithObjects(address, gw).
		Build()
	r := newGatewayReconciler(
		c,
		c.Scheme(),
		gateway.NewEngine(newConvergenceDatapath(), gateway.NoopQuotaEnforcer{}, gateway.NoopTelemetryEmitter{}),
		testNodeGWA,
	)
	r.Scope = ServiceScope{GatewayNamespace: testNamespace}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired)
	if condition == nil || condition.Status != metav1.ConditionTrue ||
		condition.ObservedGeneration != address.Generation {
		t.Fatalf("retirement stalled with project services off: %+v", address.Status)
	}
}

func (d *convergenceDatapath) OwnedVIPs() ([]netip.Addr, error) {
	result := make([]netip.Addr, 0, len(d.owned))
	for addr := range d.owned {
		result = append(result, addr)
	}
	return result, nil
}

func TestRestartRetainsAbsentPinnedGuardUntilCleanup(t *testing.T) {
	ctx := context.Background()
	f := newConvergenceFixture(t)
	old := netip.MustParseAddr("2001:db8::99")
	f.d.owned[old] = false
	snapshot, err := f.r.prepareAddressInventory(ctx, testNamespace, f.rules)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, exists := f.d.owned[old]; !exists || !blocked {
		t.Fatal("restart removed or trusted absent pinned guard before sweep")
	}
	f.d.orphanErr = errors.New("orphan sweep failed")
	uncertain := gateway.EngineStatus{Healthy: true}
	err = f.r.finishAddressConvergence(ctx, newTestGateway(testNodeGWA), f.desired, &uncertain, 0, snapshot)
	if err == nil {
		t.Fatal("orphan sweep failure was ignored")
	}
	if blocked, exists := f.d.owned[old]; !exists || !blocked || f.d.renewals[old] != 0 {
		t.Fatal("failed restart sweep released or renewed pinned guard")
	}
	f.d.orphanErr = nil
	status := gateway.EngineStatus{
		Healthy: false,
		Rules:   []gateway.RuleStatus{{Key: "persisted", VIPAddresses: []netip.Addr{old}, Error: "cleanup failed"}},
	}
	if err := f.r.finishAddressConvergence(ctx, newTestGateway(testNodeGWA), f.desired, &status, 0, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, exists := f.d.owned[old]; !exists {
		t.Fatal("failed cleanup released persisted ownership")
	}
	status = gateway.EngineStatus{Healthy: true}
	if err := f.r.finishAddressConvergence(ctx, newTestGateway(testNodeGWA), f.desired, &status, 0, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, exists := f.d.owned[old]; exists {
		t.Fatal("successful cleanup retained absent owned guard")
	}
}

func TestSelectiveRenewalFailureDoesNotWithholdHealthyVIP(t *testing.T) {
	f := newConvergenceFixture(t)
	f.pass(t)
	healthy, bad := netip.MustParseAddr(
		f.addresses[0].Spec.VIPAddress,
	), netip.MustParseAddr(
		f.addresses[1].Spec.VIPAddress,
	)
	f.d.failRenew = bad
	status := f.pass(t)
	if !status.VIPConverged(healthy) || status.VIPConverged(bad) || f.d.renewals[healthy] != 2 {
		t.Fatalf("renewal failure not isolated: %+v", status)
	}
	f.pass(t)
	if f.d.owned[healthy] || !f.d.owned[bad] || f.d.renewals[healthy] != 3 {
		t.Fatal("retry affected healthy VIP or reopened failed VIP")
	}
}

func (d *convergenceDatapath) ReconcileOrphans(context.Context, []gateway.DesiredRule, uint64) error {
	return d.orphanErr
}

func TestGuardWriteFailureCannotAuthorizeForwarding(t *testing.T) {
	for _, block := range []bool{false, true} {
		t.Run(map[bool]string{false: "Ownership", true: "Block"}[block], func(t *testing.T) {
			f := newConvergenceFixture(t)
			f.d.failOwned = !block
			f.d.failBlock = block
			if _, err := f.r.prepareAddressInventory(context.Background(), testNamespace, f.rules); err == nil {
				t.Fatal("partial guard failure was ignored")
			}
			if len(f.d.rows) != 0 || len(f.d.renewals) != 0 || len(f.r.confirmedAddresses) != 0 {
				t.Fatal("failed guard write authorized programming")
			}
			f.d.failOwned = false
			f.d.failBlock = false
			f.pass(t)
			for _, blocked := range f.d.owned {
				if blocked {
					t.Fatal("guard retry failed to converge")
				}
			}
		})
	}
}
