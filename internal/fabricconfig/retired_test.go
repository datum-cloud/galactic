// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// isConfigMap reports whether obj is a ConfigMap or a list of them, typed,
// as metadata or unstructured.
func isConfigMap(obj runtime.Object) bool {
	switch o := obj.(type) {
	case *corev1.ConfigMap, *corev1.ConfigMapList:
		return true
	case *metav1.PartialObjectMetadata:
		return o.Kind == "ConfigMap"
	case *metav1.PartialObjectMetadataList:
		return o.Kind == "ConfigMapList"
	case *unstructured.Unstructured:
		return o.GetKind() == "ConfigMap"
	case *unstructured.UnstructuredList:
		return o.GetKind() == "ConfigMapList"
	}
	return false
}

// noConfigMaps wraps c so that any ConfigMap call fails the test and the
// call.
func noConfigMaps(t *testing.T, c client.WithWatch) client.Client {
	t.Helper()
	refuse := func(verb string, obj runtime.Object) error {
		if !isConfigMap(obj) {
			return nil
		}
		t.Errorf("%s of a ConfigMap with the ConfigMap path retired", verb)
		return fmt.Errorf("%s ConfigMap: refused by the test", verb)
	}
	return interceptor.NewClient(c, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption) error {
			if err := refuse("get", obj); err != nil {
				return err
			}
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := refuse("list", list); err != nil {
				return err
			}
			return c.List(ctx, list, opts...)
		},
		Watch: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
			opts ...client.ListOption) (watch.Interface, error) {
			if err := refuse("watch", list); err != nil {
				return nil, err
			}
			return c.Watch(ctx, list, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := refuse("create", obj); err != nil {
				return err
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if err := refuse("update", obj); err != nil {
				return err
			}
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch,
			opts ...client.PatchOption) error {
			if err := refuse("patch", obj); err != nil {
				return err
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	})
}

// retiredHarness is a harness whose agent has its ConfigMap path retired
// and whose client fails the test on any ConfigMap call. The node's
// ConfigMap exists, so only the agent's restraint keeps it unread.
func retiredHarness(t *testing.T, objs ...client.Object) *harness {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: depNamespace, Name: ConfigMapName(depNode),
		UID: cmUID}, Data: map[string]string{KeyFRRConf: minimalConf}}
	h := newHarness(t, append(objs, cm)...)
	h.agent.Client = noConfigMaps(t, h.client.(client.WithWatch))
	h.agent.ConfigMapsRetired = true
	return h
}

// committed promotes and commits the harness's first revision at epoch 1.
func (h *harness) committed() {
	h.t.Helper()
	if err := h.client.Create(context.Background(), release(h.revs[0], h.revs[1])); err != nil {
		h.t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	if got := h.sync(); got.Status.AppliedEpoch != 1 {
		h.t.Fatalf("applied epoch %d, want 1", got.Status.AppliedEpoch)
	}
}

// TestRetiredAgentStaysOnCRD: with the ConfigMap path retired, a deployment
// asking for another source, even with a valid handoff, is reported and the
// node stays on CRD; no ConfigMap is read.
func TestRetiredAgentStaysOnCRD(t *testing.T) {
	for _, source := range []networkv1alpha1.FabricConfigSource{
		networkv1alpha1.FabricConfigSourceConfigMap, networkv1alpha1.FabricConfigSourceShadow,
	} {
		t.Run(string(source), func(t *testing.T) {
			h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
			h.committed()
			reloads := h.frr.reloads
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
				d.Spec.Source = source
				if source == networkv1alpha1.FabricConfigSourceConfigMap {
					d.Spec.SourceHandoff = &networkv1alpha1.FabricSourceHandoff{
						ConfigMap:       networkv1alpha1.FabricObjectIdentity{Name: ConfigMapName(depNode), UID: cmUID},
						ResourceVersion: "999",
					}
				}
			})
			got := h.sync()
			if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceCRD {
				t.Errorf("gate %s, want CRD", src)
			}
			if j := h.agent.Activator.Journal(); JournalSource(j) != networkv1alpha1.FabricConfigSourceCRD ||
				j.Handoff() != "" {
				t.Errorf("journal source %s handoff %q, want CRD and none", JournalSource(j), j.Handoff())
			}
			if got.Status.EffectiveSource != networkv1alpha1.FabricConfigSourceCRD {
				t.Errorf("effective source %s", got.Status.EffectiveSource)
			}
			c := condition(got, networkv1alpha1.FabricConditionAccepted)
			if c == nil || c.Status != metav1.ConditionFalse || c.Reason != networkv1alpha1.FabricReasonConfigMapRetired {
				t.Errorf("Accepted = %+v, want False %s", c, networkv1alpha1.FabricReasonConfigMapRetired)
			}
			if h.frr.reloads != reloads || h.frr.get() != rendered(t, h.revs[0]) {
				t.Error("FRR left the committed revision")
			}
			// Back on CRD, the condition clears with the next promotion.
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
				d.Spec.Source, d.Spec.SourceHandoff = networkv1alpha1.FabricConfigSourceCRD, nil
				promote(d, 2, h.revs[1])
			})
			got = h.sync()
			if c := condition(got, networkv1alpha1.FabricConditionAccepted); c == nil ||
				c.Reason != networkv1alpha1.FabricReasonCommitted || got.Status.AppliedEpoch != 2 {
				t.Errorf("after returning to CRD: Accepted = %+v, applied epoch %d", c, got.Status.AppliedEpoch)
			}
		})
	}
}

// TestRetiredAgentNewNodeActivates: a node with no journal settles on CRD
// at its first sync and activates its deployment's active revision.
func TestRetiredAgentNewNodeActivates(t *testing.T) {
	h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
	if src := h.agent.Activator.Journal().Source(); src != "" {
		t.Fatalf("journal source %q, want none", src)
	}
	h.committed()
	if src, _ := h.agent.Gate.Get(); src != networkv1alpha1.FabricConfigSourceCRD {
		t.Errorf("gate %s, want CRD", src)
	}
}

// TestRetiredBootConfig covers where a node whose ConfigMap path is retired
// starts FRR from, and that nothing reads a ConfigMap on the way.
func TestRetiredBootConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("CommittedOffline", func(t *testing.T) {
		h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
		h.committed()
		offline := *h.agent
		offline.Client = noConfigMaps(t, interceptor.NewClient(h.client.(client.WithWatch), interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return errors.New("the API is unreachable")
			},
		}))
		conf, reason, err := offline.BootConfig(ctx, depMachine)
		if err != nil || conf != rendered(t, h.revs[0]) || offline.Booted != BootCheckpointOffline {
			t.Fatalf("BootConfig offline = %q, %v, booted %s", reason, err, offline.Booted)
		}
	})

	t.Run("CommittedOnlineAfterExpiry", func(t *testing.T) {
		h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
		h.committed()
		h.agent.Activator.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
		conf, reason, err := h.agent.BootConfig(ctx, depMachine)
		if err != nil || conf != rendered(t, h.revs[0]) || h.agent.Booted != BootCheckpointOnline {
			t.Fatalf("BootConfig = %q, %v, booted %s", reason, err, h.agent.Booted)
		}
	})

	for _, tc := range []struct {
		name string
		// journal is the source the journal records, empty for none.
		journal string
		phase   networkv1alpha1.FabricReleasePhase
	}{
		{"NewNode", "", networkv1alpha1.FabricReleasePhaseStarted},
		{"NewNodeReleaseUnknown", "", networkv1alpha1.FabricReleasePhaseUnknown},
		{"EnrolledNothingActivated", string(networkv1alpha1.FabricConfigSourceCRD),
			networkv1alpha1.FabricReleasePhaseStarted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
			if tc.journal != "" {
				if err := h.agent.Activator.Journal().SetSource(tc.journal); err != nil {
					t.Fatal(err)
				}
			}
			auth := release(h.revs[0])
			auth.Status.Phase = tc.phase
			if err := h.client.Create(ctx, auth); err != nil {
				t.Fatal(err)
			}
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
			conf, reason, err := h.agent.BootConfig(ctx, depMachine)
			if err != nil || conf != rendered(t, h.revs[0]) || h.agent.Booted != BootActiveRevision {
				t.Fatalf("BootConfig = %q, %v, booted %s", reason, err, h.agent.Booted)
			}
		})
	}

	// A node with nothing activated is held until a started release
	// authorizes its deployment's active revision on CRD; each refusal
	// names why and stays retryable.
	for _, tc := range []struct {
		name    string
		prepare func(h *harness)
		want    string
	}{
		{"NoDeployment", func(h *harness) {
			if err := h.client.Delete(ctx, deployment(networkv1alpha1.FabricConfigSourceCRD)); err != nil {
				h.t.Fatal(err)
			}
		}, "has no deployment"},
		{"DeploymentOnConfigMap", func(h *harness) {
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
				d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
			})
		}, "on the ConfigMap source, not CRD"},
		{"NothingPromoted", func(h *harness) {
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) { d.Spec.ActivationEpoch = 0 })
		}, "has no active revision"},
		{"ReleaseFinished", func(h *harness) {
			auth := &networkv1alpha1.FabricReleaseAuthorization{}
			if err := h.client.Get(ctx, client.ObjectKey{Namespace: depNamespace, Name: releaseName}, auth); err != nil {
				h.t.Fatal(err)
			}
			auth.Status.Phase = networkv1alpha1.FabricReleasePhaseCompleted
			if err := h.client.Update(ctx, auth); err != nil {
				h.t.Fatal(err)
			}
		}, "is Completed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
			if err := h.client.Create(ctx, release(h.revs[0])); err != nil {
				t.Fatal(err)
			}
			h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
			tc.prepare(h)
			_, _, err := h.agent.BootConfig(ctx, depMachine)
			if !errors.Is(err, ErrNotActivated) || !strings.Contains(err.Error(), tc.want) || !retryable(err) {
				t.Fatalf("BootConfig = %v, want a retryable ErrNotActivated naming %q", err, tc.want)
			}
		})
	}

	// A journal recording another source fails closed for good.
	for _, source := range []networkv1alpha1.FabricConfigSource{
		networkv1alpha1.FabricConfigSourceConfigMap, networkv1alpha1.FabricConfigSourceShadow,
	} {
		t.Run("JournalOn"+string(source), func(t *testing.T) {
			h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
			h.committed()
			if err := h.agent.Activator.Journal().SetSource(string(source)); err != nil {
				t.Fatal(err)
			}
			_, _, err := h.agent.BootConfig(ctx, depMachine)
			if !errors.Is(err, ErrConfigMapsRetired) || retryable(err) {
				t.Fatalf("BootConfig = %v, want a fatal ErrConfigMapsRetired", err)
			}
		})
	}
}

// TestBootConfigReleaseUnknown: at boot a release whose outcome is Unknown
// still authorizes the active revision, but an activation waits for it to
// start again.
func TestBootConfigReleaseUnknown(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
	auth := release(h.revs[0])
	auth.Status.Phase = networkv1alpha1.FabricReleasePhaseUnknown
	if err := h.client.Create(ctx, auth); err != nil {
		t.Fatal(err)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	// Activated before, for another epoch: no checkpoint to restore.
	journalAccept(h, depUID, 0, nil)
	if conf, reason, err := h.agent.BootConfig(ctx, depMachine); err != nil || conf != rendered(t, h.revs[0]) {
		t.Fatalf("BootConfig = %q, %v", reason, err)
	}
	got := h.sync()
	if c := condition(got, networkv1alpha1.FabricConditionAccepted); c == nil || c.Reason != reasonNotAuthorized ||
		got.Status.AppliedEpoch != 0 {
		t.Errorf("Accepted = %+v, applied epoch %d; want an Unknown release to authorize no activation", c,
			got.Status.AppliedEpoch)
	}
}

// configMapAccess fails the test on any ConfigMap call through clientset c.
func configMapAccess(t *testing.T, c *fake.Clientset) {
	t.Helper()
	c.PrependReactor("*", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		t.Errorf("%s of a ConfigMap with the ConfigMap path retired", a.GetVerb())
		return true, nil, errors.New("refused by the test")
	})
	c.PrependWatchReactor("configmaps", func(k8stesting.Action) (bool, watch.Interface, error) {
		t.Error("watch of a ConfigMap with the ConfigMap path retired")
		return true, nil, errors.New("refused by the test")
	})
}

// TestRetiredAgentReadsNoConfigMap: every ConfigMap entry point of a
// retired Agent fails without calling the API.
func TestRetiredAgentReadsNoConfigMap(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: ConfigMapName(testNode)},
		Data: map[string]string{KeyFRRConf: testConf}}
	a, _, _ := newTestAgent(t, cm)
	configMapAccess(t, a.Client.(*fake.Clientset))
	a.ConfigMapsRetired = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Init(ctx); !errors.Is(err, ErrConfigMapsRetired) {
		t.Errorf("Init = %v, want ErrConfigMapsRetired", err)
	}
	if _, _, err := a.ConfigMapConfig(ctx); !errors.Is(err, ErrConfigMapsRetired) {
		t.Errorf("ConfigMapConfig = %v, want ErrConfigMapsRetired", err)
	}
	if err := a.Watch(ctx); !errors.Is(err, ErrConfigMapsRetired) {
		t.Errorf("Watch = %v, want ErrConfigMapsRetired", err)
	}
	if _, err := os.Stat(filepath.Join(a.ConfigDir, KeyFRRConf)); !os.IsNotExist(err) {
		t.Errorf("frr.conf written: %v", err)
	}
}

// TestInitActivated covers frr-init on the activation path: what it starts
// from, with the ConfigMap path and with it retired.
func TestInitActivated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: depNamespace, Name: ConfigMapName(depNode)},
		Data: map[string]string{KeyFRRConf: testConf}}

	// newAgent is a ConfigMap agent for the harness's node.
	newAgent := func(t *testing.T, retired bool) *Agent {
		t.Helper()
		a, _, _ := newTestAgent(t, cm)
		a.Namespace, a.NodeName = depNamespace, depNode
		if retired {
			configMapAccess(t, a.Client.(*fake.Clientset))
			a.ConfigMapsRetired = true
		}
		return a
	}

	t.Run("EnrolledNothingActivated", func(t *testing.T) {
		h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
		if err := h.agent.Activator.Journal().SetSource(string(networkv1alpha1.FabricConfigSourceCRD)); err != nil {
			t.Fatal(err)
		}
		a := newAgent(t, false)
		var rec BootRecord
		if err := a.InitActivated(ctx, h.agent, &rec); err != nil {
			t.Fatal(err)
		}
		if got := readConfig(t, a, KeyFRRConf); got != testConf || rec.Source != BootConfigMap {
			t.Errorf("frr.conf %q from %s, want the ConfigMap's", got, rec.Source)
		}
	})

	t.Run("RetiredNewNode", func(t *testing.T) {
		h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
		if err := h.client.Create(ctx, release(h.revs[0])); err != nil {
			t.Fatal(err)
		}
		h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
		a := newAgent(t, true)
		var rec BootRecord
		if err := a.InitActivated(ctx, h.agent, &rec); err != nil {
			t.Fatal(err)
		}
		if got := readConfig(t, a, KeyFRRConf); got != rendered(t, h.revs[0]) || rec.Source != BootActiveRevision {
			t.Errorf("frr.conf from %s, want the active revision", rec.Source)
		}
	})

	t.Run("RetiredJournalOnConfigMap", func(t *testing.T) {
		h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
		if err := h.agent.Activator.Journal().SetSource(string(networkv1alpha1.FabricConfigSourceConfigMap)); err != nil {
			t.Fatal(err)
		}
		a := newAgent(t, true)
		var rec BootRecord
		if err := a.InitActivated(ctx, h.agent, &rec); !errors.Is(err, ErrConfigMapsRetired) {
			t.Fatalf("InitActivated = %v, want ErrConfigMapsRetired at once", err)
		}
		if _, err := os.Stat(filepath.Join(a.ConfigDir, KeyFRRConf)); !os.IsNotExist(err) {
			t.Errorf("frr.conf written: %v", err)
		}
	})

	t.Run("RetiredNothingPromoted", func(t *testing.T) {
		h := retiredHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
		a := newAgent(t, true)
		short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		var rec BootRecord
		if err := a.InitActivated(short, h.agent, &rec); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("InitActivated = %v, want it held on ErrNotActivated until its context ends", err)
		}
		if _, err := os.Stat(filepath.Join(a.ConfigDir, KeyFRRConf)); !os.IsNotExist(err) {
			t.Errorf("frr.conf written: %v", err)
		}
	})
}
