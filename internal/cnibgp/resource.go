// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/nldump"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

var cniScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(cniScheme))
}

// newK8sClient creates a new Kubernetes client using the in-cluster config,
// scoped to cniScheme (BGP CRDs).
func newK8sClient() (client.Client, error) {
	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("get kubeconfig: %w", err)
	}
	c, err := client.New(restCfg, client.Options{Scheme: cniScheme})
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}
	return c, nil
}

// resourceTracker tracks the resources cmdAdd created, for selective rollback.
// This plugin's ADD only ever creates BGP CRDs and an eBPF vrf_table entry;
// kernel-interface cleanup belongs to each master plugin's own tracker.
//
// publishResult is embedded rather than copied field by field, so a field added
// to one struct cannot silently stop being tracked in the other with no
// compiler error to catch it.
type resourceTracker struct {
	vpc, vpcAttachment, nodeName string
	namespace                    string
	k8s                          client.Client

	publishResult
}

// cleanup rolls back the tracked resources. Errors are logged and never
// returned, the caller already having a failure.
//
// Deliberately conditional. The BGPVRFInstance is deleted only when this ADD's
// own attempt created it, and the vrf_table entry is never unregistered at all.
// Unlike the advertisement, which is a reliable one-per-attachment key, both are
// shared by every attachment on this VPC on this node. Once a second
// attachment's ADD reuses a live sibling's, which is the ordinary case since
// both writes are idempotent, rolling either back would tear down that
// sibling's VRF.
//
// Reclaiming shared per-node state is garbage collection's job, once it has
// confirmed no advertisement for this VPC and node remains. The map entry has no
// cheap "did I just create this" signal the way an API object's write result
// does, so it stays unconditional there. The CRD does have one, which is what
// lets a rejected freshly created instance self-heal on retry rather than
// wedging permanently.
//
// Creating the instance is not enough on its own: a sibling ADD on the same
// VPC can reuse it between this ADD's write and its rollback, before that
// sibling writes anything of its own. Its host link is already enslaved to
// the VPC's VRF by then, so the instance is kept while any link other than
// this attachment's own is enslaved there.
func (rt *resourceTracker) cleanup(ctx context.Context) {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	if rt.advertisementCreated && rt.k8s != nil {
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPAdvertisementName(rt.vpc, rt.vpcAttachment, rt.nodeName),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, adv); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete BGPAdvertisement", "err", err,
				"resource_name", adv.Name, "resource_namespace", rt.namespace)
		} else {
			slog.Debug("Rollback: deleted BGPAdvertisement", "resource_name", adv.Name, "resource_namespace", rt.namespace)
		}
	}

	if rt.vrfInstanceCreated && rt.k8s != nil {
		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPVRFInstanceName(rt.vpc, rt.nodeName),
				Namespace: rt.namespace,
			},
		}
		// Under the VRF lock, so no sibling ADD can enslave its link between
		// the check and the delete: a sibling that enslaved in that gap could
		// reuse the instance before the delete lands. A sibling that enslaves
		// after it writes the instance again itself. The delete is bounded,
		// since every ADD on the node waits for this lock.
		var deleteErr error
		lockErr := vrfLockedFn(func() error {
			siblings, err := siblingHostLinks(rt.vpc, rt.vpcAttachment)
			if err != nil {
				return fmt.Errorf("list links enslaved to the VRF: %w", err)
			}
			if len(siblings) > 0 {
				slog.Info("Rollback: kept BGPVRFInstance that sibling attachments now use",
					"resource_name", vrfInst.Name, "resource_namespace", rt.namespace, "links", siblings)
				return nil
			}
			delCtx, cancel := context.WithTimeout(ctx, lockedDeleteTimeout)
			defer cancel()
			if err := rt.k8s.Delete(delCtx, vrfInst); client.IgnoreNotFound(err) != nil {
				deleteErr = err
				return nil
			}
			slog.Debug("Rollback: deleted freshly-created BGPVRFInstance",
				"resource_name", vrfInst.Name, "resource_namespace", rt.namespace)
			return nil
		})
		switch {
		case lockErr != nil:
			slog.Error("Rollback: kept freshly-created BGPVRFInstance, could not check its VRF for siblings; GC reclaims it",
				"err", lockErr, "resource_name", vrfInst.Name, "resource_namespace", rt.namespace)
		case deleteErr != nil:
			slog.Error("Rollback: failed to delete freshly-created BGPVRFInstance", "err", deleteErr,
				"resource_name", vrfInst.Name, "resource_namespace", rt.namespace)
		}
	}
}

// lockedDeleteTimeout bounds the instance delete rollback makes while holding
// the node's VRF lock.
const lockedDeleteTimeout = 5 * time.Second

// vrfLockedFn runs a function under the node's VRF lock; a variable so
// unprivileged tests, which cannot create the lock file, can run without it.
var vrfLockedFn = vrf.Locked

// listLinksFn lists the links in this process's network namespace; a
// variable so tests can substitute fabricated links.
var listLinksFn = nldump.LinkList

// siblingHostLinks returns the links enslaved to vpc's VRF other than
// vpcAttachment's own host link. Any such link belongs to another attachment,
// or an edge attachment, that shares the VPC's BGPVRFInstance, even before
// its own ADD has written anything. No VRF means no siblings.
func siblingHostLinks(vpc, vpcAttachment string) ([]string, error) {
	links, err := listLinksFn()
	if err != nil {
		return nil, err
	}
	vrfName := intf.GenerateInterfaceNameVRF(vpc)
	own := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	vrfIndex := 0
	for _, l := range links {
		if l.Attrs().Name == vrfName && l.Type() == "vrf" {
			vrfIndex = l.Attrs().Index
			break
		}
	}
	if vrfIndex == 0 {
		return nil, nil
	}
	var siblings []string
	for _, name := range vrf.EnslavedTo(links, vrfIndex) {
		if name != own {
			siblings = append(siblings, name)
		}
	}
	return siblings, nil
}
