// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// argumentLockDir holds the node-local lock that serializes Argument
// allocation across galactic-bgp processes. It sits beside the VRF lock, in
// the directory every Galactic component that touches host VRFs already
// mounts. A variable so unprivileged tests can point it at a temporary
// directory.
var argumentLockDir = "/var/lib/cni/galactic-vrf"

const argumentLockFileName = "argument.lock"

// maxArgumentReallocations bounds how many times one ADD moves its own
// freshly created BGPVRFInstance to another Argument after a collision.
const maxArgumentReallocations = 3

// errArgumentCollision is wrapped by claimArgument when another
// BGPVRFInstance holds the same Argument and this ADD cannot move its own.
var errArgumentCollision = errors.New("SID Argument collision")

// lockArguments takes the node-local Argument lock, blocking until it is
// free, and returns the function that releases it.
//
// Each CNI ADD is its own process, so two first ADDs for different VPCs on
// one node otherwise read the same free Argument and both write it.
func lockArguments() (release func(), err error) {
	if err := os.MkdirAll(argumentLockDir, 0o700); err != nil {
		return nil, fmt.Errorf("create Argument lock dir %q: %w", argumentLockDir, err)
	}
	path := filepath.Join(argumentLockDir, argumentLockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open Argument lock file %q: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock Argument lock file %q: %w", path, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// claimArgument creates or reuses the BGPVRFInstance named vrfName under
// routerName, with the spec build returns for its Argument, and returns that
// Argument and whether this call created the instance.
//
// Allocation, the write and the collision check all run under the node's
// Argument lock, so no other galactic-bgp process on the node can take the
// same free value in between. A collision can still come from a writer that
// does not take the lock. When this ADD created the instance (createdBefore
// says an earlier attempt of the same ADD did), the instance is moved to the
// next free Argument, at most maxArgumentReallocations times, since nothing
// has used its value yet. An instance this ADD reused already carries a value
// other attachments use, so a collision there is an error wrapping
// errArgumentCollision, naming both instances.
func claimArgument(
	ctx context.Context, k8s client.Client, namespace, routerName, vrfName string, createdBefore bool,
	build func(vrfID int32) bgpv1alpha1.BGPVRFInstanceSpec,
) (vrfID int32, created bool, err error) {
	release, err := lockArguments()
	if err != nil {
		return 0, false, err
	}
	defer release()

	vrfID, err = allocateArgument(ctx, k8s, namespace, routerName, vrfName)
	if err != nil {
		return 0, false, err
	}
	vrfInst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: vrfName, Namespace: namespace},
	}
	op, err := controllerutil.CreateOrUpdate(ctx, k8s, vrfInst, func() error {
		vrfInst.Spec = build(vrfID)
		return nil
	})
	if err != nil {
		return 0, false, fmt.Errorf("apply BGPVRFInstance: %w", err)
	}
	created = op == controllerutil.OperationResultCreated
	ours := created || createdBefore

	for moves := 0; ; moves++ {
		holder, err := argumentHolder(ctx, k8s, namespace, routerName, vrfName, vrfID)
		if err != nil {
			return vrfID, created, err
		}
		if holder == "" {
			return vrfID, created, nil
		}
		if !ours {
			return vrfID, created, fmt.Errorf(
				"%w: BGPVRFInstance %s holds Argument %d, which existing BGPVRFInstance %s also holds",
				errArgumentCollision, holder, vrfID, vrfName)
		}
		if moves == maxArgumentReallocations {
			return vrfID, created, fmt.Errorf(
				"%w: BGPVRFInstance %s still collides on Argument %d with %s after %d reallocations",
				errArgumentCollision, vrfName, vrfID, holder, moves)
		}
		next, err := nextFreeArgument(ctx, k8s, namespace, routerName, vrfName)
		if err != nil {
			return vrfID, created, err
		}
		slog.Warn("BGP: Argument taken by another writer, reallocating this ADD's BGPVRFInstance",
			"resource_name", vrfName, "resource_namespace", namespace, "holder", holder,
			"argument", vrfID, "next", next)
		vrfID = next
		if _, err := controllerutil.CreateOrUpdate(ctx, k8s, vrfInst, func() error {
			vrfInst.Spec = build(vrfID)
			return nil
		}); err != nil {
			return vrfID, created, fmt.Errorf("reallocate BGPVRFInstance %s: %w", vrfName, err)
		}
	}
}

// argumentHolder returns the name of another BGPVRFInstance under routerName
// that holds vrfID, or "" if none does.
func argumentHolder(
	ctx context.Context, k8s client.Client, namespace, routerName, vrfName string, vrfID int32,
) (string, error) {
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return "", fmt.Errorf("list BGPVRFInstances to verify Argument uniqueness: %w", err)
	}
	for _, inst := range list.Items {
		if inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name != routerName {
			continue
		}
		if inst.Name != vrfName && inst.Spec.VRFID == vrfID {
			return inst.Name, nil
		}
	}
	return "", nil
}

// nextFreeArgument returns the lowest Argument under routerName that no
// BGPVRFInstance other than vrfName holds.
func nextFreeArgument(ctx context.Context, k8s client.Client, namespace, routerName, vrfName string) (int32, error) {
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return 0, fmt.Errorf("list BGPVRFInstances in namespace %s: %w", namespace, err)
	}
	return lowestFreeArgument(list.Items, routerName, vrfName)
}

// lowestFreeArgument returns the lowest value in [uformat.ArgumentMin,
// uformat.ArgumentMax] that no instance in items under routerName, other
// than the one named self, holds.
func lowestFreeArgument(items []bgpv1alpha1.BGPVRFInstance, routerName, self string) (int32, error) {
	used := make(map[int32]struct{}, len(items))
	for _, inst := range items {
		if inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name != routerName || inst.Name == self {
			continue
		}
		used[inst.Spec.VRFID] = struct{}{}
	}
	for arg := int32(uformat.ArgumentMin); arg <= int32(uformat.ArgumentMax); arg++ {
		if _, ok := used[arg]; !ok {
			return arg, nil
		}
	}
	return 0, fmt.Errorf("allocate SID argument: router %s has no free Argument in [%#x,%#x] (all %d in use)",
		routerName, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax), len(used))
}
