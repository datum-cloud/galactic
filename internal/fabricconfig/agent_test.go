// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/events"
)

const (
	testConf       = "conf"
	customDaemons  = "custom"
	defaultDaemons = "zebra=yes\n"
	defaultVtysh   = "service integrated-vtysh-config\n"
	invalidMarker  = "bogus"
)

// fakeFRR rejects any file containing invalidMarker and records reloads.
type fakeFRR struct {
	reloadErr error
	reloads   []string
}

func (f *fakeFRR) Check(_ context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.Contains(string(b), invalidMarker) {
		return errors.New("unknown command")
	}
	return nil
}

func (f *fakeFRR) Reload(_ context.Context, path string) error {
	if f.reloadErr != nil {
		return f.reloadErr
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.reloads = append(f.reloads, string(b))
	return nil
}

func newTestAgent(t *testing.T, objs ...*corev1.ConfigMap) (*Agent, *fakeFRR, *events.FakeRecorder) {
	t.Helper()
	defaults := t.TempDir()
	for name, contents := range map[string]string{KeyDaemons: defaultDaemons, KeyVtyshConf: defaultVtysh} {
		if err := os.WriteFile(filepath.Join(defaults, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	client := fake.NewClientset()
	for _, cm := range objs {
		_, err := client.CoreV1().ConfigMaps(cm.Namespace).Create(context.Background(), cm, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	frr := &fakeFRR{}
	rec := events.NewFakeRecorder(100)
	return &Agent{
		Client:    client,
		Recorder:  rec,
		FRR:       frr,
		Namespace: testNamespace,
		NodeName:  testNode,
		Pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "fabric-router-abcde", Namespace: testNamespace,
		}},
		LegacyConfigMap: DefaultLegacyConfigMap,
		ConfigDir:       t.TempDir(),
		DefaultsDir:     defaults,
		RetryInterval:   10 * time.Millisecond,
	}, frr, rec
}

func readConfig(t *testing.T, a *Agent, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(a.ConfigDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// drainReasons returns the reason of every event recorded so far.
func drainReasons(rec *events.FakeRecorder) []string {
	var reasons []string
	for {
		select {
		case e := <-rec.Events:
			reasons = append(reasons, strings.Fields(e)[1])
		default:
			return reasons
		}
	}
}

func TestInit(t *testing.T) {
	tests := []struct {
		name        string
		objs        []*corev1.ConfigMap
		wantFRRConf string
		wantDaemons string
		wantVtysh   string
		wantReasons []string
	}{
		{
			name:        "PerNodeWithDefaults",
			objs:        []*corev1.ConfigMap{configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: testConf})},
			wantFRRConf: testConf,
			wantDaemons: defaultDaemons,
			wantVtysh:   defaultVtysh,
		},
		{
			name: "PerNodeOverridesDaemons",
			objs: []*corev1.ConfigMap{configMap(ConfigMapName(testNode), map[string]string{
				KeyFRRConf: testConf, KeyDaemons: customDaemons,
			})},
			wantFRRConf: testConf,
			wantDaemons: customDaemons,
			wantVtysh:   defaultVtysh,
		},
		{
			name: "Legacy",
			objs: []*corev1.ConfigMap{
				configMap(DefaultLegacyConfigMap, map[string]string{legacyKey: legacyConf}),
			},
			wantFRRConf: legacyConf,
			wantDaemons: defaultDaemons,
			wantVtysh:   defaultVtysh,
			wantReasons: []string{ReasonDeprecatedSource},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, rec := newTestAgent(t, tt.objs...)
			if err := a.Init(context.Background()); err != nil {
				t.Fatalf("Init() error = %v", err)
			}
			if got := readConfig(t, a, KeyFRRConf); got != tt.wantFRRConf {
				t.Errorf("frr.conf = %q, want %q", got, tt.wantFRRConf)
			}
			if got := readConfig(t, a, KeyDaemons); got != tt.wantDaemons {
				t.Errorf("daemons = %q, want %q", got, tt.wantDaemons)
			}
			if got := readConfig(t, a, KeyVtyshConf); got != tt.wantVtysh {
				t.Errorf("vtysh.conf = %q, want %q", got, tt.wantVtysh)
			}
			if _, err := os.Stat(filepath.Join(a.ConfigDir, candidateName)); !os.IsNotExist(err) {
				t.Errorf("candidate file left behind: %v", err)
			}
			if got := drainReasons(rec); strings.Join(got, ",") != strings.Join(tt.wantReasons, ",") {
				t.Errorf("event reasons = %v, want %v", got, tt.wantReasons)
			}
		})
	}
}

// TestInitWaitsForValidConfig checks that Init keeps retrying, without
// installing anything, while configuration is missing and then invalid, and
// installs it once a valid version appears.
func TestInitWaitsForValidConfig(t *testing.T) {
	a, _, rec := newTestAgent(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.Init(ctx) }()

	waitForReason(t, rec, ReasonConfigMissing)
	cms := a.Client.CoreV1().ConfigMaps(a.Namespace)
	invalid := configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: invalidMarker})
	cm, err := cms.Create(ctx, invalid, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitForReason(t, rec, ReasonRejected)
	if _, err := os.Stat(filepath.Join(a.ConfigDir, KeyFRRConf)); !os.IsNotExist(err) {
		t.Fatalf("frr.conf installed from an invalid configuration")
	}

	cm.Data[KeyFRRConf] = "good"
	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if got := readConfig(t, a, KeyFRRConf); got != "good" {
		t.Errorf("frr.conf = %q, want %q", got, "good")
	}
}

func waitForReason(t *testing.T, rec *events.FakeRecorder, reason string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e := <-rec.Events:
			if strings.Fields(e)[1] == reason {
				return
			}
		case <-timeout:
			t.Fatalf("no %s event", reason)
		}
	}
}

func TestConverge(t *testing.T) {
	ctx := context.Background()
	perNode := func(data map[string]string) *corev1.ConfigMap {
		return configMap(ConfigMapName(testNode), data)
	}

	a, frr, rec := newTestAgent(t)
	if err := os.WriteFile(filepath.Join(a.ConfigDir, KeyFRRConf), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{KeyDaemons: defaultDaemons, KeyVtyshConf: defaultVtysh} {
		if err := os.WriteFile(filepath.Join(a.ConfigDir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.loadApplied(); err != nil {
		t.Fatal(err)
	}

	steps := []struct {
		name        string
		cm          *corev1.ConfigMap
		reloadErr   error
		wantErr     bool
		wantFRRConf string
		wantReloads int
		wantReasons []string
	}{
		{
			name:        "UnchangedReportsRunning",
			cm:          perNode(map[string]string{KeyFRRConf: "v1"}),
			wantFRRConf: "v1",
			wantReasons: []string{ReasonApplied},
		},
		{
			name:        "UnchangedReportsOnce",
			cm:          perNode(map[string]string{KeyFRRConf: "v1"}),
			wantFRRConf: "v1",
		},
		{
			name:        "Changed",
			cm:          perNode(map[string]string{KeyFRRConf: "v2"}),
			wantFRRConf: "v2",
			wantReloads: 1,
			wantReasons: []string{ReasonApplied},
		},
		{
			name:        "InvalidKeepsRunningConfig",
			cm:          perNode(map[string]string{KeyFRRConf: invalidMarker}),
			wantFRRConf: "v2",
			wantReloads: 1,
			wantReasons: []string{ReasonRejected},
		},
		{
			name:        "SameInvalidIsNotRetried",
			cm:          perNode(map[string]string{KeyFRRConf: invalidMarker}),
			wantFRRConf: "v2",
			wantReloads: 1,
		},
		{
			name:        "ReloadFailureIsRetried",
			cm:          perNode(map[string]string{KeyFRRConf: "v3"}),
			reloadErr:   errors.New("vtysh: connection refused"),
			wantErr:     true,
			wantFRRConf: "v2",
			wantReloads: 1,
			wantReasons: []string{ReasonReloadFailed},
		},
		{
			name:        "RetrySucceeds",
			cm:          perNode(map[string]string{KeyFRRConf: "v3"}),
			wantFRRConf: "v3",
			wantReloads: 2,
			wantReasons: []string{ReasonApplied},
		},
		{
			name:        "DaemonsChangeRequiresRestart",
			cm:          perNode(map[string]string{KeyFRRConf: "v3", KeyDaemons: customDaemons}),
			wantFRRConf: "v3",
			wantReloads: 2,
			wantReasons: []string{ReasonRestartRequired},
		},
		{
			name:        "MissingKeepsRunningConfig",
			cm:          nil,
			wantFRRConf: "v3",
			wantReloads: 2,
			wantReasons: []string{ReasonConfigMissing},
		},
	}
	for _, s := range steps {
		frr.reloadErr = s.reloadErr
		err := a.converge(ctx, s.cm, nil)
		if (err != nil) != s.wantErr {
			t.Fatalf("%s: converge() error = %v, wantErr %v", s.name, err, s.wantErr)
		}
		if got := readConfig(t, a, KeyFRRConf); got != s.wantFRRConf {
			t.Errorf("%s: frr.conf = %q, want %q", s.name, got, s.wantFRRConf)
		}
		if len(frr.reloads) != s.wantReloads {
			t.Errorf("%s: reloads = %d, want %d", s.name, len(frr.reloads), s.wantReloads)
		}
		if got := drainReasons(rec); strings.Join(got, ",") != strings.Join(s.wantReasons, ",") {
			t.Errorf("%s: event reasons = %v, want %v", s.name, got, s.wantReasons)
		}
	}
	if got := readConfig(t, a, KeyDaemons); got != customDaemons {
		t.Errorf("daemons = %q, want %q", got, customDaemons)
	}
}

// TestWatch checks that a ConfigMap update reaches the running configuration
// through the informer.
func TestWatch(t *testing.T) {
	cm := configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "v1"})
	a, frr, rec := newTestAgent(t, cm)
	if err := a.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	drainReasons(rec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Watch(ctx) }()
	waitForReason(t, rec, ReasonApplied) // reports the running v1 at startup

	cm.Data[KeyFRRConf] = "v2"
	if _, err := a.Client.CoreV1().ConfigMaps(a.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForReason(t, rec, ReasonApplied)
	if got := readConfig(t, a, KeyFRRConf); got != "v2" {
		t.Errorf("frr.conf = %q, want %q", got, "v2")
	}
	if len(frr.reloads) != 1 {
		t.Errorf("reloads = %d, want 1", len(frr.reloads))
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Watch() error = %v", err)
	}
}
