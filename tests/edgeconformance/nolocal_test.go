// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// TestNoLocalWorkload runs a provider on an edge node where its VPC has no
// workload (#1288): galactic-edge creates whatever of the VPC's host VRF,
// BGPVRFInstance and vrf_table row the node lacks, and galactic-router GC
// removes the BGPVRFInstance once nothing on the node uses the VPC.
//
// GC keeps a node's host VRF while the VPC has a tenant EndpointSlice anywhere
// in the cluster, and tenant A always has workloads on other nodes, so the VRF
// stays on the node throughout, with nothing enslaved to it once the node has
// no user. That is the state most edge nodes are in when a provider attaches.
//
// It uses tenant A on edgeNode2, scaling that node's edge-client to zero for
// the rows that need no workload there, and restores it at the end. It runs
// on its own: TestConformance also places tenant A's providers on edgeNode2.
func TestNoLocalWorkload(t *testing.T) {
	l := getLab(t)
	t.Cleanup(func() { l.writeSummary(t) })

	a := &side{tn: tenantA, deploy: "nl1", node: edgeNode2}
	t.Cleanup(func() { l.scaleClient(t, a.tn, a.node, 1) })
	if os.Getenv("EDGE_CONFORMANCE_KEEP") == "" {
		t.Cleanup(func() { teardown(t, l, a) })
	}

	// Precondition: nothing on the node uses the VPC, so GC has removed its
	// BGPVRFInstance there.
	if !t.Run("setup", func(t *testing.T) {
		l.scaleClient(t, a.tn, a.node, 0)
		l.waitNodeVPCReleased(t, a.tn, a.node, l.gcInterval(t)+time.Minute)
	}) {
		t.FailNow()
	}

	t.Run("26-attach-without-local-workload", func(t *testing.T) {
		// setup waits for the attachment, its route's acceptance and replies
		// from the provider to probes from the compute node, which cross the
		// edge node's new VRF in both directions.
		setup(t, l, a)
		l.requireNodeVPCState(t, a.tn, a.node)
		l.reachable(t, a, computeNode)
	})

	t.Run("26a-workload-arrives-and-leaves", func(t *testing.T) {
		a.refresh(t, l)
		before := a.att.Generation
		l.scaleClient(t, a.tn, a.node, 1)
		l.reachable(t, a, computeNode)
		l.reachable(t, a, a.node)
		l.scaleClient(t, a.tn, a.node, 0)
		l.reachable(t, a, computeNode)
		l.requireProgrammed(t, a, before)
		l.requireNodeVPCState(t, a.tn, a.node)
	})

	t.Run("26b-galactic-edge-restart", func(t *testing.T) {
		a.refresh(t, l)
		before := a.att.Generation
		agent := l.agentPod(t, a.node)
		if err := l.c.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: systemNS, Name: agent}}); err != nil {
			t.Fatal(err)
		}
		eventually(t, 3*time.Minute, 2*time.Second, "galactic-edge replaced on "+a.node, func() (bool, error) {
			var pods corev1.PodList
			if err := l.c.List(context.Background(), &pods, client.InNamespace(systemNS),
				client.MatchingLabels{"app.kubernetes.io/name": "galactic-edge"}); err != nil {
				return false, err
			}
			for _, p := range pods.Items {
				if p.Spec.NodeName == a.node && p.Name != agent && podReady(&p) {
					return true, nil
				}
			}
			return false, nil
		})
		// Two resyncs of the new agent, then one GC pass.
		time.Sleep(2 * time.Minute)
		l.requireProgrammed(t, a, before)
		l.requireNodeVPCState(t, a.tn, a.node)
		l.reachable(t, a, computeNode)
	})

	t.Run("26c-removal-with-a-workload", func(t *testing.T) {
		l.scaleClient(t, a.tn, a.node, 1)
		l.stopProvider(t, a.tn.namespace, a.deploy)
		l.waitNoAttachment(t, a)
		time.Sleep(l.gcInterval(t) + 30*time.Second)
		l.requireNodeVPCState(t, a.tn, a.node)
	})

	t.Run("26d-removal-with-no-user", func(t *testing.T) {
		l.scaleClient(t, a.tn, a.node, 0)
		l.waitNodeVPCReleased(t, a.tn, a.node, l.gcInterval(t)+time.Minute)
	})
}

// scaleClient sets the replicas of tenant tn's edge-client on node and waits
// for the pods to match: ready ones when it scales up, none when it scales to
// zero. A pod that becomes ready has passed CNI ADD on the node.
func (l *lab) scaleClient(t *testing.T, tn tenant, node string, replicas int32) {
	t.Helper()
	ctx := context.Background()
	i := map[string]string{computeNode: "1", edgeNode1: "2", edgeNode2: "3"}[node]
	key := client.ObjectKey{Namespace: tn.vpcNamespace, Name: "edge-client-" + i}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		d := &appsv1.Deployment{}
		if err := l.c.Get(ctx, key, d); err != nil {
			return err
		}
		d.Spec.Replicas = ptr.To(replicas)
		return l.c.Update(ctx, d)
	})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Minute, 2*time.Second, fmt.Sprintf("%s at %d replicas", key.Name, replicas),
		func() (bool, error) {
			var pods corev1.PodList
			if err := l.c.List(ctx, &pods, client.InNamespace(tn.vpcNamespace),
				client.MatchingLabels{appLabel: key.Name}); err != nil {
				return false, err
			}
			var ready int32
			for _, p := range pods.Items {
				if replicas == 0 {
					return false, nil
				}
				if p.DeletionTimestamp == nil && podReady(&p) {
					ready++
				}
			}
			return ready == replicas, nil
		})
}

// nodeVPCState reports whether tenant tn's VPC has its host VRF on node and
// its BGPVRFInstance for node, each separately.
func (l *lab) nodeVPCState(t *testing.T, tn tenant, node string) (vrf, instance bool) {
	t.Helper()
	_, err := nodeExec(node, "ip", "link", "show", intf.GenerateInterfaceNameVRF(tn.vpc))
	vrf = err == nil
	var inst networkv1alpha1.BGPVRFInstance
	key := client.ObjectKey{Namespace: systemNS, Name: crdnames.BGPVRFInstanceName(tn.vpc, node)}
	switch err := l.c.Get(context.Background(), key, &inst); {
	case err == nil:
		instance = true
	case !apierrors.IsNotFound(err):
		t.Fatal(err)
	}
	return vrf, instance
}

// requireNodeVPCState fails unless the VPC's VRF and BGPVRFInstance on node
// are both present.
func (l *lab) requireNodeVPCState(t *testing.T, tn tenant, node string) {
	t.Helper()
	if vrf, inst := l.nodeVPCState(t, tn, node); !vrf || !inst {
		t.Errorf("VPC %s on %s: host VRF present %t, BGPVRFInstance present %t; want both",
			tn.vpc, node, vrf, inst)
	}
}

// waitNodeVPCReleased waits up to timeout for the VPC's BGPVRFInstance for
// node to be gone and for no link on node to be enslaved to the VPC's host
// VRF. It records whether GC kept the VRF itself, which it does while the VPC
// has workloads elsewhere in the cluster.
func (l *lab) waitNodeVPCReleased(t *testing.T, tn tenant, node string, timeout time.Duration) {
	t.Helper()
	start := time.Now()
	vrfName := intf.GenerateInterfaceNameVRF(tn.vpc)
	var vrf bool
	eventually(t, timeout, 5*time.Second, fmt.Sprintf("VPC %s released on %s", tn.vpc, node),
		func() (bool, error) {
			var inst bool
			vrf, inst = l.nodeVPCState(t, tn, node)
			if inst {
				return false, nil
			}
			if !vrf {
				return true, nil
			}
			slaves, err := nodeExec(node, "ip", "-br", "link", "show", "master", vrfName)
			return err == nil && strings.TrimSpace(slaves) == "", nil
		})
	l.record(t, "VPC BGPVRFInstance removed and VRF unused after", time.Since(start).Round(time.Second))
	l.record(t, "host VRF kept by GC for the VPC's workloads elsewhere", vrf)
}

// requireProgrammed fails unless s's attachment is still the one of the
// given generation and reports Programmed True.
func (l *lab) requireProgrammed(t *testing.T, s *side, generation int64) {
	t.Helper()
	var att galacticv1alpha1.EdgeAttachment
	if err := l.c.Get(context.Background(), client.ObjectKeyFromObject(s.att), &att); err != nil {
		t.Fatal(err)
	}
	if att.UID != s.att.UID || att.Generation != generation {
		t.Errorf("attachment %s was replaced or changed: generation %d, want %d", att.Name, att.Generation, generation)
	}
	if !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed) {
		t.Errorf("attachment %s is not Programmed: %+v", att.Name,
			meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed))
	}
}

// waitNoAttachment waits for s's attachment to be gone once its provider
// stopped.
func (l *lab) waitNoAttachment(t *testing.T, s *side) {
	t.Helper()
	eventually(t, 2*time.Minute, 2*time.Second, "attachment "+s.att.Name+" removed", func() (bool, error) {
		err := l.c.Get(context.Background(), client.ObjectKeyFromObject(s.att), &galacticv1alpha1.EdgeAttachment{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, client.IgnoreNotFound(err)
	})
}
