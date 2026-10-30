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
	"time"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// argumentLockDir holds the node-local lock that serializes Argument
// allocation across galactic-bgp processes. It sits beside the VRF lock, in
// the directory every Galactic component that touches host VRFs already
// mounts. A variable so unprivileged tests can point it at a temporary
// directory.
var argumentLockDir = vrf.LockDir

const argumentLockFileName = "argument.lock"

// maxArgumentReallocations bounds how many times one ADD moves its own
// freshly created BGPVRFInstance to another Argument after a collision.
const maxArgumentReallocations = 3

// errArgumentCollision is wrapped by claimArgument when another
// BGPVRFInstance holds the same Argument and this ADD cannot move its own.
var errArgumentCollision = errors.New("SID Argument collision")

// argumentLockPoll is how often lockArguments retries a held lock.
const argumentLockPoll = 20 * time.Millisecond

// lockArguments takes the node-local Argument lock, waiting until it is free
// or ctx ends, and returns the function that releases it.
//
// Each CNI ADD is its own process, so two first ADDs for different VPCs on
// one node otherwise read the same free Argument and both write it. A holder
// makes API calls under the lock, so a waiter gives up with ctx rather than
// outliving its own ADD's budget behind a slow API server.
func lockArguments(ctx context.Context) (release func(), err error) {
	if err := os.MkdirAll(argumentLockDir, 0o700); err != nil {
		return nil, fmt.Errorf("create Argument lock dir %q: %w", argumentLockDir, err)
	}
	path := filepath.Join(argumentLockDir, argumentLockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open Argument lock file %q: %w", path, err)
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("flock Argument lock file %q: %w", path, err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("wait for Argument lock file %q: %w", path, ctx.Err())
		case <-time.After(argumentLockPoll):
		}
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
// does not take the lock. When this attempt created the instance, the
// instance is moved to the next free Argument, at most
// maxArgumentReallocations times, since nothing has used its value yet: a
// sibling ADD would need the lock this attempt holds to reuse it. An instance
// this ADD reused already carries a value other attachments use, so a
// collision there is an error wrapping errArgumentCollision, naming both
// instances.
//
// createdBefore says an earlier attempt of this ADD created the instance.
// The lock was released in between, so a sibling ADD may have reused it
// since; it is moved only while siblings, the links of other attachments in
// the VPC's VRF, reports none.
//
// After each move, releaseArgument is called with the Argument the instance left. An
// earlier attempt may have registered the datapath under it, and the writer
// now holding it must not have its traffic delivered into this VPC. A release
// error fails the claim.
func claimArgument(
	ctx context.Context, k8s client.Client, namespace, routerName, vrfName string, createdBefore bool,
	siblings func() ([]string, error), build func(vrfID int32) bgpv1alpha1.BGPVRFInstanceSpec,
	releaseArgument func(argument int32) error,
) (vrfID int32, created bool, err error) {
	release, err := lockArguments(ctx)
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
	ours := created

	for moves := 0; ; moves++ {
		holder, err := argumentHolder(ctx, k8s, namespace, routerName, vrfName, vrfID)
		if err != nil {
			return vrfID, created, err
		}
		if holder == "" {
			return vrfID, created, nil
		}
		if !ours && createdBefore {
			others, err := siblings()
			if err != nil {
				return vrfID, created, fmt.Errorf("check for siblings before moving BGPVRFInstance %s: %w", vrfName, err)
			}
			ours = len(others) == 0
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
		left := vrfID
		vrfID = next
		if _, err := controllerutil.CreateOrUpdate(ctx, k8s, vrfInst, func() error {
			vrfInst.Spec = build(vrfID)
			return nil
		}); err != nil {
			return vrfID, created, fmt.Errorf("reallocate BGPVRFInstance %s: %w", vrfName, err)
		}
		if err := releaseArgument(left); err != nil {
			return vrfID, created, fmt.Errorf("release Argument %d after moving BGPVRFInstance %s: %w",
				left, vrfName, err)
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
