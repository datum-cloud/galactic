// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/store"
)

var (
	condTrue    = workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE
	condFalse   = workerv1alpha1.ConditionStatus_CONDITION_STATUS_FALSE
	condUnknown = workerv1alpha1.ConditionStatus_CONDITION_STATUS_UNKNOWN
)

func cond(t string, s workerv1alpha1.ConditionStatus, reason, msg string) *workerv1alpha1.Condition {
	return &workerv1alpha1.Condition{Type: t, Status: s, Reason: reason, Message: msg}
}

func protoKey(k module.ClaimKey) *workerv1alpha1.ClaimKey {
	return &workerv1alpha1.ClaimKey{Node: k.Node, Vpc: k.VPC, AttachmentUid: k.AttachmentUID}
}

// initialStatus is the status of an accepted claim before reconciliation
// reports on its generation.
func (w *Worker) initialStatus(c *claim, observed uint64) *workerv1alpha1.ClaimStatus {
	st := &workerv1alpha1.ClaimStatus{
		Key:                protoKey(c.key()),
		Generation:         c.rec.Generation,
		ObservedGeneration: observed,
		Conditions: []*workerv1alpha1.Condition{
			cond(workerv1alpha1.ConditionAdmitted, condTrue, workerv1alpha1.ReasonAsExpected, ""),
			cond(workerv1alpha1.ConditionResolved, condUnknown, workerv1alpha1.ReasonPending, ""),
			cond(workerv1alpha1.ConditionProgrammed, condUnknown, workerv1alpha1.ReasonPending, ""),
			cond(workerv1alpha1.ConditionReady, condUnknown, workerv1alpha1.ReasonPending, ""),
			cond(workerv1alpha1.ConditionWithdrawing, condFalse, workerv1alpha1.ReasonAsExpected, ""),
		},
	}
	c.status = st
	if c.rec.Releasing {
		w.setWithdrawing(c)
	}
	return c.status
}

func withdrawalScope(s string) workerv1alpha1.WithdrawalScope {
	if s == store.WithdrawCaller {
		return workerv1alpha1.WithdrawalScope_WITHDRAWAL_SCOPE_CALLER
	}
	return workerv1alpha1.WithdrawalScope_WITHDRAWAL_SCOPE_CLAIM
}

// setWithdrawing marks a releasing claim's status Withdrawing.
func (w *Worker) setWithdrawing(c *claim) {
	st := c.status
	st.WithdrawalScope = withdrawalScope(c.rec.Withdrawal)
	setCond(st, cond(workerv1alpha1.ConditionWithdrawing, condTrue, c.rec.WithdrawReason, "removing programmed state"))
	setCond(st, cond(workerv1alpha1.ConditionReady, condFalse, c.rec.WithdrawReason, "the claim is being withdrawn"))
	if c.rec.WithdrawReason == workerv1alpha1.ReasonAuthorizationRevoked {
		setCond(st, cond(workerv1alpha1.ConditionAdmitted, condFalse, workerv1alpha1.ReasonAuthorizationRevoked,
			"the claim's attachment is no longer authorized"))
	}
}

func setCond(st *workerv1alpha1.ClaimStatus, c *workerv1alpha1.Condition) {
	for i, cur := range st.Conditions {
		if cur.GetType() == c.GetType() {
			st.Conditions[i] = c
			return
		}
	}
	st.Conditions = append(st.Conditions, c)
}

// subscriber is one Observe stream.
type subscriber struct {
	caller string
	// key selects one claim; nil selects every claim of the caller.
	key     *module.ClaimKey
	notify  chan struct{}
	pending map[module.ClaimKey]*workerv1alpha1.ClaimStatus
}

func (s *subscriber) wants(owner string, k module.ClaimKey) bool {
	return owner == s.caller && (s.key == nil || *s.key == k)
}

// publish stamps a new revision on c's status and queues a copy for every
// matching subscriber. w.mu must be held.
func (w *Worker) publish(c *claim) {
	c.status.Revision = w.nextRevision()
	w.fanout(c.rec.Owner, c.key(), c.status)
}

// fanout queues st for subscribers. w.mu must be held.
func (w *Worker) fanout(owner string, k module.ClaimKey, st *workerv1alpha1.ClaimStatus) {
	for s := range w.subs {
		if !s.wants(owner, k) {
			continue
		}
		s.pending[k] = proto.Clone(st).(*workerv1alpha1.ClaimStatus)
		select {
		case s.notify <- struct{}{}:
		default:
		}
	}
}
