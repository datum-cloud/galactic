// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
)

type vipRangeTranslationTable interface {
	RegisterIngressRange(
		block uint64,
		argument, slot uint16,
		proto uint8,
		vip net.IP,
		start, end uint16,
		backend net.IP,
	) error
	RegisterEgressRange(block uint64, argument uint16, proto uint8, backend net.IP, start, end uint16, vip net.IP) error
	UnregisterRangeBindingAt(
		block uint64,
		argument, slot uint16,
		proto uint8,
		vip net.IP,
		start, end uint16,
		backend net.IP,
	) error
	RangeBindingPresent(
		block uint64,
		argument, slot uint16,
		proto uint8,
		vip net.IP,
		start, end uint16,
		backend net.IP,
	) (bool, error)
	ListRanges() ([]vipxlatmap.RangeEntry, error)
}

func (r *ServiceVIPBindingReconciler) registerVIPRange(rows vipBindingRows) error {
	table, ok := r.VIPTranslationTable.(vipRangeTranslationTable)
	if !ok {
		return errors.New("UDP range translation is unavailable on this node")
	}
	if err := table.RegisterIngressRange(rows.ingress.block, rows.ingress.argument, rows.ingress.slot, rows.ingress.proto,
		rows.vipAddr, rows.vipPort, rows.end, rows.backendAddr); err != nil {
		return err
	}
	if err := table.RegisterEgressRange(rows.egress.block, rows.egress.argument, rows.egress.proto,
		rows.backendAddr, rows.backendPort, rows.end, rows.vipAddr); err != nil {
		cleanup := table.UnregisterRangeBindingAt(
			rows.ingress.block,
			rows.ingress.argument,
			rows.ingress.slot,
			rows.ingress.proto,
			rows.vipAddr,
			rows.vipPort,
			rows.end,
			rows.backendAddr,
		)
		return errors.Join(err, cleanup)
	}
	present, err := table.RangeBindingPresent(
		rows.ingress.block,
		rows.ingress.argument,
		rows.ingress.slot,
		rows.ingress.proto,
		rows.vipAddr,
		rows.vipPort,
		rows.end,
		rows.backendAddr,
	)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("UDP range translation was not confirmed")
	}
	return nil
}

const rangeContextsAnnotation = "galactic.datum.net/range-contexts"

type rangeContext struct {
	Block    uint64 `json:"block"`
	Argument uint16 `json:"argument"`
}

func (r *ServiceVIPBindingReconciler) rememberRangeContext(
	ctx context.Context,
	binding *bgpv1alpha1.ServiceVIPBinding,
	block uint64,
	argument uint16,
) error {
	contexts := make([]rangeContext, 0, 1)
	if value := binding.Annotations[rangeContextsAnnotation]; value != "" {
		if err := json.Unmarshal([]byte(value), &contexts); err != nil {
			return fmt.Errorf("read range cleanup receipt: %w", err)
		}
	}
	for _, current := range contexts {
		if current.Block == block && current.Argument == argument {
			return nil
		}
	}
	contexts = append(contexts, rangeContext{Block: block, Argument: argument})
	encoded, err := json.Marshal(contexts)
	if err != nil {
		return err
	}
	base := binding.DeepCopy()
	if binding.Annotations == nil {
		binding.Annotations = map[string]string{}
	}
	binding.Annotations[rangeContextsAnnotation] = string(encoded)
	return r.Patch(ctx, binding, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func (r *ServiceVIPBindingReconciler) unregisterVIPRange(
	ctx context.Context,
	binding *bgpv1alpha1.ServiceVIPBinding,
) error {
	table, ok := r.VIPTranslationTable.(vipRangeTranslationTable)
	if !ok {
		return errors.New("UDP range translation is unavailable on this node")
	}
	rows, err := parseVIPBindingRows(binding)
	if err != nil {
		return err
	}
	twin, err := r.liveTwin(ctx, binding, rows.ingress.proto, rows.vipAddr, rows.backendAddr)
	if err != nil {
		return err
	}
	if twin != nil {
		return nil
	}
	var contexts []rangeContext
	if value := binding.Annotations[rangeContextsAnnotation]; value != "" {
		if err := json.Unmarshal([]byte(value), &contexts); err != nil {
			return fmt.Errorf("read range cleanup receipt: %w", err)
		}
	}
	// The receipt is persisted before any map write, so its absence proves this
	// binding has never installed a range. It also survives loss of the VRF.
	var errs []error
	for _, current := range contexts {
		errs = append(
			errs,
			table.UnregisterRangeBindingAt(current.Block, current.Argument, rows.ingress.slot, rows.ingress.proto,
				rows.vipAddr, rows.vipPort, rows.end, rows.backendAddr),
		)
	}
	return errors.Join(errs...)
}
