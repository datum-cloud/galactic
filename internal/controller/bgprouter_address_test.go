// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/rbaccheck"
	"go.datum.net/galactic/internal/reconcile"
)

const (
	routerFailureAdvertisement = "advertisement"
	routerFailureAnchor        = "anchor"
	routerRetiredAddress       = "router-retired-address"
)

func TestRouterCoordinatedAdvertisementShippedRBAC(t *testing.T) {
	cfg := rbaccheck.Start(t)
	admin, err := client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	rbaccheck.Apply(t, admin, filepath.Join("..", "..", "config", "galactic-router", "rbac.yaml"))
	user, groups := rbaccheck.ServiceAccount("galactic-system", "galactic-router")
	const group = "galactic.datumapis.com"
	allowed := rbaccheck.Each([]string{rbaccheck.Get, rbaccheck.List, rbaccheck.Watch, rbaccheck.Patch, rbaccheck.Delete},
		group, "tenant", "bgpadvertisements")
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Get, rbaccheck.Patch, rbaccheck.Update},
		group, "tenant", "bgpadvertisements/status")...)
	denied := rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Update}, group, "tenant", "bgpadvertisements")
	denied = append(denied, rbaccheck.Each([]string{rbaccheck.Patch}, group, "tenant", "bgpvrfinstances")...)
	rbaccheck.Check(t, admin, user, groups, allowed, denied)
}

type routerAuthorityReader struct {
	client.Reader
	failKind string
	reads    int
}

func (r *routerAuthorityReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("unexpected uncached list")
}

func (r *routerAuthorityReader) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	r.reads++
	switch obj.(type) {
	case *api.BGPAdvertisement:
		if r.failKind == routerFailureAdvertisement {
			return errors.New("advertisement unavailable")
		}
	case *api.NetworkServiceAddress:
		if r.failKind == routerFailureAnchor {
			return errors.New("anchor unavailable")
		}
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

type routerAdvertisementPatchClient struct{ client.Client }

func (c routerAdvertisementPatchClient) Patch(
	ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption,
) error {
	if _, ok := obj.(*api.BGPAdvertisement); ok {
		return errors.New("advertisement patch forbidden")
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func TestRouterCoordinatedFailureIsolatesAdvertisement(t *testing.T) {
	for _, failure := range []string{routerFailureAdvertisement, routerFailureAnchor, "patch"} {
		t.Run(failure, func(t *testing.T) {
			f := newLeaseRouterFixture(t)
			ctx := context.Background()
			address, _ := sharedAddressFixture()
			if err := f.c.Create(ctx, address); err != nil {
				t.Fatal(err)
			}
			if err := f.c.Get(ctx, client.ObjectKeyFromObject(f.leased), f.leased); err != nil {
				t.Fatal(err)
			}
			f.leased.Labels = map[string]string{
				serviceAddressLabel: address.Name, serviceAddressNamespaceLabel: address.Namespace,
				serviceAddressUIDLabel: string(address.UID)}
			f.leased.Spec.ExpiresAt = nil
			if err := f.c.Update(ctx, f.leased); err != nil {
				t.Fatal(err)
			}
			live := &routerAuthorityReader{Reader: f.c, failKind: failure}
			f.r.APIReader = live
			f.r.Reconciler.SetAPIReader(live)
			if failure == "patch" {
				f.r.Client = routerAdvertisementPatchClient{f.c}
			}
			result, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)})
			if err != nil {
				t.Fatal(err)
			}
			if result.RequeueAfter != advertisementLeaseRequeue {
				t.Fatalf("failed authority retry = %v", result.RequeueAfter)
			}
			if f.rm.applies != 2 || len(f.rm.desired.Advertisements) != 1 ||
				f.rm.desired.Advertisements[0].Name != leaseLegacyName {
				t.Fatalf("affected advertisement not isolated: %+v", f.rm.desired.Advertisements)
			}
			if err := f.c.Get(ctx, client.ObjectKeyFromObject(f.leased), f.leased); err != nil {
				t.Fatal(err)
			}
			if failure == routerFailureAnchor &&
				!slices.Contains(f.leased.Finalizers, reconcile.CoordinatedAdvertisementFinalizer) {
				t.Fatal("authority read error removed withdrawal proof guard")
			}
		})
	}
}

func TestRouterLegacyAdvertisementsNeedNoLiveReads(t *testing.T) {
	f := newLeaseRouterFixture(t)
	other := f.leased.DeepCopy()
	other.Name = "other-router"
	other.ResourceVersion = ""
	other.Spec.RouterRef.Name = "elsewhere"
	other.Labels = map[string]string{serviceAddressLabel: "unrelated"}
	if err := f.c.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	live := &routerAuthorityReader{Reader: f.c, failKind: routerFailureAdvertisement}
	f.r.APIReader = live
	f.r.Reconciler.SetAPIReader(live)
	if _, err := f.r.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)}); err != nil {
		t.Fatal(err)
	}
	if live.reads != 0 {
		t.Fatalf("legacy-only router made %d live reads", live.reads)
	}
}

func TestRouterFinalizerPatchFailurePreservesGuard(t *testing.T) {
	f := newLeaseRouterFixture(t)
	ctx := context.Background()
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(f.leased), f.leased); err != nil {
		t.Fatal(err)
	}
	f.leased.Labels = map[string]string{serviceAddressLabel: routerRetiredAddress}
	f.leased.Finalizers = []string{reconcile.CoordinatedAdvertisementFinalizer}
	if err := f.c.Update(ctx, f.leased); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Delete(ctx, f.leased); err != nil {
		t.Fatal(err)
	}
	f.r.Client = routerAdvertisementPatchClient{f.c}
	for range 2 {
		if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(f.leased), f.leased); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.leased.Finalizers, reconcile.CoordinatedAdvertisementFinalizer) ||
		f.leased.DeletionTimestamp.IsZero() {
		t.Fatal("lost guard without successful withdrawal acknowledgement")
	}
	if len(f.rm.desired.Advertisements) != 1 || f.rm.desired.Advertisements[0].Name != leaseLegacyName {
		t.Fatal("unrelated route affected by guard patch failure")
	}
}

type unavailableRouterStatus struct{ *leaseRuntimeManager }

func (r unavailableRouterStatus) Status(context.Context, types.NamespacedName) (model.RuntimeStatus, error) {
	return model.RuntimeStatus{}, errors.New("runtime status unavailable")
}

func TestRouterStatusFailurePreservesWithdrawalGuard(t *testing.T) {
	f := newLeaseRouterFixture(t)
	ctx := context.Background()
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(f.leased), f.leased); err != nil {
		t.Fatal(err)
	}
	f.leased.Labels = map[string]string{serviceAddressLabel: routerRetiredAddress}
	f.leased.Finalizers = []string{reconcile.CoordinatedAdvertisementFinalizer}
	if err := f.c.Update(ctx, f.leased); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Delete(ctx, f.leased); err != nil {
		t.Fatal(err)
	}
	f.r.RuntimeManager = unavailableRouterStatus{f.rm}
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.router)}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(f.leased), f.leased); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.leased.Finalizers, reconcile.CoordinatedAdvertisementFinalizer) {
		t.Fatal("missing runtime status acknowledged terminal withdrawal")
	}
	if len(f.rm.desired.Advertisements) != 1 || f.rm.desired.Advertisements[0].Name != leaseLegacyName {
		t.Fatal("unrelated routes blocked by withdrawal status failure")
	}
}
