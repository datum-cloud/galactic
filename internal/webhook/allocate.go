// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// ErrIDSpaceExhausted is returned by AllocateVPCAttachmentID when every
// 16-bit VPCAttachment ID (0-65535) for a VPC is already taken.
var ErrIDSpaceExhausted = errors.New("VPCAttachment ID space exhausted for this VPC")

// AllocateVPCAttachmentID picks the lowest free 16-bit VPCAttachment ID for
// vpc, base62-encoded. It scans the NADs this webhook has already created
// for vpc (labelVPC + labelAttachmentID), not the VPCAttachment CRD:
// galactic-cni creates that object later, at ADD time, so it may not exist
// yet for a given ID — scanning it would risk double-allocating an ID whose
// NAD already exists but whose pod hasn't been scheduled/attached yet. The
// NAD is the object this webhook creates synchronously with the allocation
// decision, so it's the only object that can't lag behind it.
//
// This is scan-then-create, not a true compare-and-swap on the ID itself:
// callers are expected to retry (re-list, re-pick) on a NAD Create conflict,
// bounded — see the caller in pod_mutator.go.
func AllocateVPCAttachmentID(
	ctx context.Context, k8s client.Client, vpc *cloudv1alpha1.VPC, namespace string,
) (string, error) {
	nadList := &unstructured.UnstructuredList{}
	nadList.SetGroupVersionKind(nadGVK)
	err := k8s.List(ctx, nadList, client.InNamespace(namespace), client.MatchingLabels{labelVPC: vpc.Name})
	if err != nil {
		return "", fmt.Errorf("list NADs for vpc %q: %w", vpc.Name, err)
	}

	used := make(map[uint16]bool, len(nadList.Items))
	for _, nad := range nadList.Items {
		hex, err := intf.Base62ToHex(nad.GetLabels()[labelAttachmentID])
		if err != nil {
			continue // malformed/foreign label — ignore, don't block allocation
		}
		id, err := strconv.ParseUint(hex, 16, 16)
		if err != nil {
			continue
		}
		used[uint16(id)] = true
	}

	id, ok := lowestFree(used)
	if !ok {
		return "", ErrIDSpaceExhausted
	}
	base62, err := intf.HexToBase62(fmt.Sprintf("%04x", id))
	if err != nil {
		return "", fmt.Errorf("encode VPCAttachment id %d as base62: %w", id, err)
	}
	return base62, nil
}

// lowestFree returns the smallest uint16 not present in used, and false if
// every value in [0, 65535] is taken.
func lowestFree(used map[uint16]bool) (uint16, bool) {
	for id := range 65536 {
		if !used[uint16(id)] {
			return uint16(id), true
		}
	}
	return 0, false
}
