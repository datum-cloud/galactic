// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostscope

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// Advertisement is one routed_link or socket claim's addresses, which Worker
// advertises over EVPN so that remote nodes return traffic for them to this
// node's host VRF, where the routed link's /128 routes deliver it.
type Advertisement struct {
	AttachmentUID string
	// PodUID is the pod the claim's routed link serves.
	PodUID    string
	Addresses []netip.Addr
}

// Advertiser publishes the advertisements of a VPC's claims. A Host that
// implements it is the only writer of the advertisements it labels as
// Worker's (crdnames.LabelWorkerVPC).
type Advertiser interface {
	// Advertise makes the node's Worker advertisements for vpc exactly want,
	// deleting any other. Worker calls it inside the scope's commit.
	Advertise(ctx context.Context, vpc string, want []Advertisement) error
	// Current reports whether the node's Worker advertisements for vpc are
	// exactly want, so Worker knows whether a commit must publish.
	Current(ctx context.Context, vpc string, want []Advertisement) (bool, error)
}

var _ Advertiser = (*Kernel)(nil)

// Advertise implements Advertiser. Each advertisement uses the VPC's
// BGPVRFInstance on the node, which Ensure created: its router, VRFID and
// export route target, with End.DT46 into the host VRF.
func (k *Kernel) Advertise(ctx context.Context, vpc string, want []Advertisement) error {
	have, err := k.listAdvertisements(ctx, vpc)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	if len(want) > 0 {
		inst := &bgpv1alpha1.BGPVRFInstance{}
		key := client.ObjectKey{Namespace: k.Namespace, Name: crdnames.BGPVRFInstanceName(vpc, k.Node)}
		if err := k.K8s.Get(ctx, key, inst); err != nil {
			return fmt.Errorf("read BGPVRFInstance %s: %w", key.Name, err)
		}
		if inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name == "" || len(inst.Spec.ExportRouteTargets) == 0 {
			return fmt.Errorf("BGPVRFInstance %s names no router or export route target", key.Name)
		}
		for _, a := range want {
			name := crdnames.WorkerAdvertisementName(vpc, a.AttachmentUID, k.Node)
			keep[name] = true
			if err := k.applyAdvertisement(ctx, vpc, name, a, inst); err != nil {
				return err
			}
		}
	}
	for _, adv := range have {
		if keep[adv.Name] {
			continue
		}
		if err := k.K8s.Delete(ctx, &adv); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete BGPAdvertisement %s: %w", adv.Name, err)
		}
	}
	return nil
}

// Current implements Advertiser. Besides the names, pods and prefixes it
// compares each advertisement's router, VRF ID, route target and function
// with the VPC's BGPVRFInstance, so a drift in either is published again.
func (k *Kernel) Current(ctx context.Context, vpc string, want []Advertisement) (bool, error) {
	have, err := k.listAdvertisements(ctx, vpc)
	if err != nil || len(have) != len(want) {
		return false, err
	}
	if len(want) == 0 {
		return true, nil
	}
	inst := &bgpv1alpha1.BGPVRFInstance{}
	key := client.ObjectKey{Namespace: k.Namespace, Name: crdnames.BGPVRFInstanceName(vpc, k.Node)}
	if err := k.K8s.Get(ctx, key, inst); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("read BGPVRFInstance %s: %w", key.Name, err)
	}
	byName := map[string]bgpv1alpha1.BGPAdvertisement{}
	for _, adv := range have {
		byName[adv.Name] = adv
	}
	for _, a := range want {
		adv, ok := byName[crdnames.WorkerAdvertisementName(vpc, a.AttachmentUID, k.Node)]
		if !ok || adv.Annotations[crdnames.AnnotationWorkerPod] != a.PodUID ||
			!slices.Equal(adv.Spec.Prefixes, advertisedPrefixes(a.Addresses)) || !matchesInstance(adv, inst) {
			return false, nil
		}
	}
	return true, nil
}

// listAdvertisements returns the node's Worker advertisements for vpc.
func (k *Kernel) listAdvertisements(ctx context.Context, vpc string) ([]bgpv1alpha1.BGPAdvertisement, error) {
	var list bgpv1alpha1.BGPAdvertisementList
	if err := k.K8s.List(ctx, &list, client.InNamespace(k.Namespace),
		client.MatchingLabels{crdnames.LabelWorkerVPC: vpc, crdnames.LabelWorkerNode: k.Node}); err != nil {
		return nil, fmt.Errorf("list Worker BGPAdvertisements of VPC %s: %w", vpc, err)
	}
	return list.Items, nil
}

// applyAdvertisement creates or updates the advertisement name for a.
func (k *Kernel) applyAdvertisement(ctx context.Context, vpc, name string, a Advertisement,
	inst *bgpv1alpha1.BGPVRFInstance) error {
	prefixes := advertisedPrefixes(a.Addresses)
	vrfID := inst.Spec.VRFID
	function := bgpv1alpha1.SRv6FunctionEndDT46
	adv := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: k.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, k.K8s, adv, func() error {
		if adv.Labels == nil {
			adv.Labels = map[string]string{}
		}
		adv.Labels[crdnames.LabelWorkerVPC] = vpc
		adv.Labels[crdnames.LabelWorkerNode] = k.Node
		adv.Labels[crdnames.LabelWorkerAttachment] = a.AttachmentUID
		if adv.Annotations == nil {
			adv.Annotations = map[string]string{}
		}
		adv.Annotations[crdnames.AnnotationWorkerPod] = a.PodUID
		adv.Spec = bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: inst.Spec.RouterRef.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      prefixes,
			Communities:   []bgpv1alpha1.Community{bgpv1alpha1.Community(inst.Spec.ExportRouteTargets[0].Value)},
			VRFID:         &vrfID,
			Function:      &function,
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apply BGPAdvertisement %s: %w", name, err)
	}
	return nil
}

// advertisedPrefixes returns the sorted, unique /128 prefixes of addrs' IPv6
// addresses. A routed link carries IPv6 only.
func advertisedPrefixes(addrs []netip.Addr) []bgpv1alpha1.Prefix {
	sorted := slices.Clone(addrs)
	slices.SortFunc(sorted, func(x, y netip.Addr) int { return x.Compare(y) })
	var out []bgpv1alpha1.Prefix
	for _, addr := range slices.Compact(sorted) {
		if addr.Is6() && !addr.Is4In6() {
			out = append(out, bgpv1alpha1.Prefix(netip.PrefixFrom(addr, 128).String()))
		}
	}
	return out
}

// matchesInstance reports whether adv carries inst's router, VRF ID and
// export route target, and End.DT46.
func matchesInstance(adv bgpv1alpha1.BGPAdvertisement, inst *bgpv1alpha1.BGPVRFInstance) bool {
	if inst.Spec.RouterRef == nil || len(inst.Spec.ExportRouteTargets) == 0 {
		return false
	}
	return adv.Spec.RouterRef.Name == inst.Spec.RouterRef.Name &&
		adv.Spec.VRFID != nil && *adv.Spec.VRFID == inst.Spec.VRFID &&
		adv.Spec.Function != nil && *adv.Spec.Function == bgpv1alpha1.SRv6FunctionEndDT46 &&
		slices.Equal(adv.Spec.Communities,
			[]bgpv1alpha1.Community{bgpv1alpha1.Community(inst.Spec.ExportRouteTargets[0].Value)})
}
