// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"fmt"
	"maps"
	"strconv"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	"go.datum.net/galactic/internal/crdnames"
)

// Reasons of a route's Published condition, beyond galactic-router's own
// reasons for its advertisement's Advertised condition, which Published
// carries while the advertisement exists.
const (
	ReasonPublished          = "Published"
	ReasonNotAccepted        = "NotAccepted"
	ReasonNotProgrammed      = "AttachmentNotProgrammed"
	ReasonVRFNotReady        = "VRFNotReady"
	ReasonAwaitingRouter     = "AwaitingRouter"
	ReasonNoRoutesPublished  = "NoRoutesPublished"
	ReasonRoutesPublished    = "RoutesPublished"
	advertisementWithdrawMsg = "the route has no accepted holder that may forward"
)

// publish keeps the route's BGPAdvertisement in step with its accepted
// holder and reports the result as the route's Published condition.
//
// The advertisement is published only for an accepted, unreleased holder
// whose attachment the node has programmed, on the holder's node and in the
// VPC's VRF there. It names the holder's host link and address, and
// galactic-router on that node advertises it only while the link's
// forwarding gate for the prefix is open: publication never widens what the
// gate allows. Every other advertisement of the route, by its name
// annotation, is withdrawn: one of an earlier object of the same name, and
// the route's own once it may no longer forward. Each write is conditional
// on what was just read, and only this route's advertisements are touched,
// so a stale pass cannot remove a replacement's or another route's.
func (r *Reconciler) publish(ctx context.Context, rt *galacticv1alpha1.EdgeRoute) error {
	want, reason, message, err := r.desiredAdvertisement(ctx, rt)
	if err != nil {
		return err
	}
	if err := r.withdraw(ctx, client.ObjectKeyFromObject(rt), want); err != nil {
		return err
	}
	cond := metav1.Condition{Type: galacticv1alpha1.EdgeRoutePublished, Status: metav1.ConditionFalse,
		Reason: reason, Message: message}
	if want != nil {
		adv, err := r.apply(ctx, want)
		if err != nil {
			return err
		}
		cond = publishedCondition(adv)
	}
	return r.setStatus(ctx, rt, func(s *galacticv1alpha1.EdgeRouteStatus) {
		setCondition(s, cond.Type, cond.Status, cond.Reason, cond.Message)
	})
}

// desiredAdvertisement returns the advertisement the route's accepted holder
// should have, or nil with the reason it should have none.
func (r *Reconciler) desiredAdvertisement(ctx context.Context, rt *galacticv1alpha1.EdgeRoute,
) (*bgpv1alpha1.BGPAdvertisement, string, string, error) {
	acc := rt.Status.Accepted
	if acc == nil || !meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
		return nil, ReasonNotAccepted, advertisementWithdrawMsg, nil
	}
	if c := rt.Spec.Claim; c != nil && c.Epoch == acc.Epoch && c.Released {
		return nil, ReasonNotAccepted, fmt.Sprintf("epoch %d was released", acc.Epoch), nil
	}
	var att galacticv1alpha1.EdgeAttachment
	switch err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: rt.Namespace, Name: acc.Attachment}, &att); {
	case apierrors.IsNotFound(err):
		return nil, ReasonNotProgrammed, fmt.Sprintf("EdgeAttachment %s does not exist", acc.Attachment), nil
	case err != nil:
		return nil, "", "", err
	case string(att.UID) != acc.AttachmentUID:
		return nil, ReasonNotProgrammed, fmt.Sprintf("EdgeAttachment %s was replaced", acc.Attachment), nil
	case !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed) ||
		att.Status.HostLink == "" || att.Status.Address == "" || att.Status.VPC == "":
		return nil, ReasonNotProgrammed, fmt.Sprintf("EdgeAttachment %s is not programmed on node %s",
			acc.Attachment, acc.Node), nil
	}
	vrfKey := client.ObjectKey{Namespace: r.BGPNamespace, Name: crdnames.BGPVRFInstanceName(att.Status.VPC, acc.Node)}
	var vrf bgpv1alpha1.BGPVRFInstance
	switch err := r.APIReader.Get(ctx, vrfKey, &vrf); {
	case apierrors.IsNotFound(err):
		return nil, ReasonVRFNotReady, fmt.Sprintf("BGPVRFInstance %s does not exist", vrfKey.Name), nil
	case err != nil:
		return nil, "", "", err
	case vrf.Spec.RouterRef == nil || vrf.Spec.RouterRef.Name == "" || len(vrf.Spec.ExportRouteTargets) == 0:
		return nil, ReasonVRFNotReady, fmt.Sprintf("BGPVRFInstance %s names no router or export route target",
			vrfKey.Name), nil
	}
	vrfID := vrf.Spec.VRFID
	function := bgpv1alpha1.SRv6FunctionEndDT46
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdnames.EdgeAdvertisementName(string(rt.UID)), Namespace: r.BGPNamespace,
			Labels: map[string]string{
				crdnames.LabelEdgeRoute: string(rt.UID),
				crdnames.LabelEdgeEpoch: strconv.FormatInt(acc.Epoch, 10),
			},
			Annotations: map[string]string{
				crdnames.AnnotationEdgeRoute:    rt.Namespace + "/" + rt.Name,
				crdnames.AnnotationEdgeHostLink: att.Status.HostLink,
				crdnames.AnnotationEdgeAddress:  att.Status.Address,
			},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: vrf.Spec.RouterRef.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(rt.Spec.Prefix)},
			Communities:   []bgpv1alpha1.Community{bgpv1alpha1.Community(vrf.Spec.ExportRouteTargets[0].Value)},
			VRFID:         &vrfID,
			Function:      &function,
		},
	}
	return adv, "", "", nil
}

// withdraw deletes every advertisement of the route named by key except
// keep, each on a precondition of the version read, so an advertisement
// rewritten since is decided again rather than deleted.
func (r *Reconciler) withdraw(ctx context.Context, key client.ObjectKey, keep *bgpv1alpha1.BGPAdvertisement) error {
	return r.withdrawIf(ctx, key, func(adv *bgpv1alpha1.BGPAdvertisement) bool {
		return keep == nil || adv.Name != keep.Name
	})
}

// withdrawGone withdraws the advertisements of the route named by key, which
// was found gone, except those of a route recreated under its name since:
// that route's own pass decides them.
func (r *Reconciler) withdrawGone(ctx context.Context, key client.ObjectKey) error {
	var rt galacticv1alpha1.EdgeRoute
	err := r.APIReader.Get(ctx, key, &rt)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return r.withdrawIf(ctx, key, func(adv *bgpv1alpha1.BGPAdvertisement) bool {
		return err != nil || adv.Labels[crdnames.LabelEdgeRoute] != string(rt.UID)
	})
}

// withdrawIf deletes the advertisements of the route named by key that
// remove selects.
func (r *Reconciler) withdrawIf(ctx context.Context, key client.ObjectKey,
	remove func(*bgpv1alpha1.BGPAdvertisement) bool) error {
	var list bgpv1alpha1.BGPAdvertisementList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(r.BGPNamespace),
		client.HasLabels{crdnames.LabelEdgeRoute}); err != nil {
		return fmt.Errorf("list edge route advertisements: %w", err)
	}
	for i := range list.Items {
		adv := &list.Items[i]
		if adv.Annotations[crdnames.AnnotationEdgeRoute] != key.String() || !remove(adv) {
			continue
		}
		uid, rv := adv.UID, adv.ResourceVersion
		err := r.Client.Delete(ctx, adv, client.Preconditions{UID: &uid, ResourceVersion: &rv})
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return fmt.Errorf("withdraw BGPAdvertisement %s: %w", adv.Name, err)
		}
	}
	return nil
}

// apply creates want or updates the advertisement of its name to it, and
// returns the advertisement as written.
func (r *Reconciler) apply(ctx context.Context, want *bgpv1alpha1.BGPAdvertisement,
) (*bgpv1alpha1.BGPAdvertisement, error) {
	var cur bgpv1alpha1.BGPAdvertisement
	switch err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(want), &cur); {
	case apierrors.IsNotFound(err):
		if err := r.Client.Create(ctx, want); err != nil {
			return nil, fmt.Errorf("publish BGPAdvertisement %s: %w", want.Name, err)
		}
		return want, nil
	case err != nil:
		return nil, err
	}
	if equality.Semantic.DeepEqual(cur.Spec, want.Spec) && subset(want.Labels, cur.Labels) &&
		subset(want.Annotations, cur.Annotations) {
		return &cur, nil
	}
	cur.Spec = want.Spec
	if cur.Labels == nil {
		cur.Labels = map[string]string{}
	}
	if cur.Annotations == nil {
		cur.Annotations = map[string]string{}
	}
	maps.Copy(cur.Labels, want.Labels)
	maps.Copy(cur.Annotations, want.Annotations)
	if err := r.Client.Update(ctx, &cur); err != nil {
		return nil, fmt.Errorf("publish BGPAdvertisement %s: %w", want.Name, err)
	}
	return &cur, nil
}

func subset(want, have map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// publishedCondition is the route's Published condition from its
// advertisement: galactic-router's Advertised condition, once it describes
// the advertisement's current generation.
func publishedCondition(adv *bgpv1alpha1.BGPAdvertisement) metav1.Condition {
	c := meta.FindStatusCondition(adv.Status.Conditions, galactic.ConditionAdvertised)
	switch {
	case c == nil || adv.Status.ObservedGeneration != adv.Generation:
		return metav1.Condition{Type: galacticv1alpha1.EdgeRoutePublished, Status: metav1.ConditionFalse,
			Reason: ReasonAwaitingRouter, Message: fmt.Sprintf("router %s has not reported BGPAdvertisement %s",
				adv.Spec.RouterRef.Name, adv.Name)}
	case c.Status == metav1.ConditionTrue:
		return metav1.Condition{Type: galacticv1alpha1.EdgeRoutePublished, Status: metav1.ConditionTrue,
			Reason: ReasonPublished, Message: fmt.Sprintf("router %s advertises the prefix", adv.Spec.RouterRef.Name)}
	}
	return metav1.Condition{Type: galacticv1alpha1.EdgeRoutePublished, Status: metav1.ConditionFalse,
		Reason: c.Reason, Message: c.Message}
}
