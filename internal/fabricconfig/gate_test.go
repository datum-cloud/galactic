// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestConvergeObeysGate: on the CRD source the ConfigMap agent writes
// nothing, and once the node is handed back it applies its ConfigMap again
// even though the ConfigMap did not change.
func TestConvergeObeysGate(t *testing.T) {
	ctx := context.Background()
	cm := configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "v1"})
	a, frr, _ := newTestAgent(t, cm)
	if err := a.loadApplied(); err != nil {
		t.Fatal(err)
	}
	gate := NewSourceGate(networkv1alpha1.FabricConfigSourceConfigMap)
	a.Gate = gate

	if err := a.converge(ctx, cm, nil); err != nil || len(frr.reloads) != 1 {
		t.Fatalf("ConfigMap source: %v, %d reloads", err, len(frr.reloads))
	}

	gate.Set(networkv1alpha1.FabricConfigSourceCRD)
	before, err := os.ReadFile(filepath.Join(a.ConfigDir, KeyFRRConf))
	if err != nil {
		t.Fatal(err)
	}
	changed := configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "v2", KeyDaemons: "bgpd=yes\n"})
	if err := a.converge(ctx, changed, nil); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(a.ConfigDir, KeyFRRConf))
	if err != nil {
		t.Fatal(err)
	}
	if len(frr.reloads) != 1 || string(after) != string(before) {
		t.Error("the ConfigMap agent wrote FRR on the CRD source")
	}

	// Another writer ran FRR meanwhile; the handoff reapplies v1, read
	// from the API even though the informer copy passed in is stale.
	gate.Set(networkv1alpha1.FabricConfigSourceConfigMap)
	stale := configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "v0"})
	if err := a.converge(ctx, stale, nil); err != nil {
		t.Fatal(err)
	}
	if len(frr.reloads) != 2 || frr.reloads[1] != "v1" {
		t.Errorf("after the handoff: reloads %q, want v1 reapplied", frr.reloads)
	}
}

func TestSourceGate(t *testing.T) {
	var nilGate *SourceGate
	if src, _ := nilGate.Get(); src != networkv1alpha1.FabricConfigSourceConfigMap || nilGate.Changed() != nil {
		t.Error("a nil gate is not ConfigMap")
	}
	g := NewSourceGate(networkv1alpha1.FabricConfigSourceConfigMap)
	_, v0 := g.Get()
	g.Set(networkv1alpha1.FabricConfigSourceConfigMap)
	if _, v := g.Get(); v != v0 {
		t.Error("setting the same source changed the version")
	}
	g.Set(networkv1alpha1.FabricConfigSourceCRD)
	select {
	case <-g.Changed():
	default:
		t.Error("a change did not notify")
	}
	if src, v := g.Get(); src != networkv1alpha1.FabricConfigSourceCRD || v == v0 {
		t.Errorf("Get = %s, %d", src, v)
	}
}

func TestFileLock(t *testing.T) {
	l := FileLock{Path: filepath.Join(t.TempDir(), "lock"), Poll: time.Millisecond}
	unlock, err := l.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock while held = %v, want a timeout", err)
	}
	var held atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		u, err := l.Lock(context.Background())
		if err != nil {
			t.Error(err)
			return
		}
		held.Store(true)
		u()
	}()
	time.Sleep(10 * time.Millisecond)
	if held.Load() {
		t.Fatal("the lock was taken twice")
	}
	unlock()
	<-done
	if !held.Load() {
		t.Error("the lock was not handed over")
	}
}

// TestParseReloadTest reads output captured from FRR 10.7.1's
// frr-reload.py --test between the edge fixture and an edit of it.
func TestParseReloadTest(t *testing.T) {
	out := `2026-10-17 18:08:16,997  INFO: Loading Config object from file /rt/b.conf

Lines To Delete
===============
router bgp 64500
 no neighbor UPSTREAM advertisement-interval 30
exit
router bgp 64500
 address-family ipv4 unicast
  no network 192.0.2.0/24  route-map ORIGINATE
 exit
exit
no ip prefix-list OLD seq 5 permit 198.51.100.0/24

Lines To Add
============
router bgp 64500
 neighbor UPSTREAM advertisement-interval 20
exit
router bgp 64500
 address-family ipv4 unicast
  network 192.0.2.0/25  route-map ORIGINATE
 exit
exit
`
	added, removed := parseReloadTest(out)
	wantAdded := []string{
		"router bgp 64500 :: neighbor UPSTREAM advertisement-interval 20",
		"router bgp 64500 :: address-family ipv4 unicast :: network 192.0.2.0/25  route-map ORIGINATE",
	}
	wantRemoved := []string{
		"router bgp 64500 :: no neighbor UPSTREAM advertisement-interval 30",
		"router bgp 64500 :: address-family ipv4 unicast :: no network 192.0.2.0/24  route-map ORIGINATE",
		"no ip prefix-list OLD seq 5 permit 198.51.100.0/24",
	}
	if !slices.Equal(added, wantAdded) || !slices.Equal(removed, wantRemoved) {
		t.Errorf("added %q\nremoved %q", added, removed)
	}
	if a, r := parseReloadTest("\nLines To Delete\n===============\n\nLines To Add\n============\n"); len(a)+len(r) != 0 {
		t.Errorf("no changes parsed as %q %q", a, r)
	}
}

// TestConvergeRechecksGateUnderLock: a switch to CRD while converge waits
// for the writer lock stops it from writing FRR.
func TestConvergeRechecksGateUnderLock(t *testing.T) {
	cm := configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "v1"})
	a, frr, _ := newTestAgent(t, cm)
	if err := a.loadApplied(); err != nil {
		t.Fatal(err)
	}
	lock := FileLock{Path: filepath.Join(t.TempDir(), "lock"), Poll: time.Millisecond}
	a.Lock = lock
	a.Gate = NewSourceGate(networkv1alpha1.FabricConfigSourceConfigMap)

	unlock, err := lock.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.converge(context.Background(), cm, nil) }()
	time.Sleep(20 * time.Millisecond)
	a.Gate.Set(networkv1alpha1.FabricConfigSourceCRD)
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(frr.reloads) != 0 {
		t.Error("converge reloaded FRR after the source moved to CRD")
	}
}
