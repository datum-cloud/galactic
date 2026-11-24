// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"net/netip"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

func TestSidecarReturnUsesWorkerOwnedAdvertisements(t *testing.T) {
	const vpc, attachment, node = "vpcone", "proxy-attachment", "node-a"
	const gateway = "2001:db8::1/128"
	cni := bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdnames.BGPAdvertisementName(vpc, "proxy", node),
			Labels: map[string]string{
				crdnames.LabelWorkerVPC: vpc, crdnames.LabelWorkerNode: node, crdnames.LabelWorkerAttachment: attachment,
			},
			Annotations: map[string]string{
				crdnames.AnnotationWorkerPod:     "proxy-pod",
				crdnames.NetNSKey("container-a"): "/run/netns/fixture",
			},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{Prefixes: []bgpv1alpha1.Prefix{gateway}},
	}

	_, routes := sidecarReturnEndpoints([]bgpv1alpha1.BGPAdvertisement{cni}, nil, node)
	if len(routes) != 0 {
		t.Fatalf("CNI advertisement with inherited Worker metadata qualified for takeover: %v", routes)
	}

	worker := cni.DeepCopy()
	worker.Name = crdnames.WorkerAdvertisementName(vpc, attachment, node)
	delete(worker.Annotations, crdnames.NetNSKey("container-a"))
	_, routes = sidecarReturnEndpoints([]bgpv1alpha1.BGPAdvertisement{cni, *worker}, nil, node)
	aliases := routes[workerSidecarRoute{vpc, netip.MustParsePrefix(gateway)}]
	want := []string{attach.InternalAliasPrefix + vpc + "/" + attachment}
	if !slices.Equal(aliases, want) {
		t.Fatalf("takeover aliases = %v, want %v", aliases, want)
	}
}
