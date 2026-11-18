// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"slices"
	"testing"
	"time"
)

const (
	optDone     = "opt-done"
	optReview   = "opt-review"
	optProgress = "opt-progress"

	// Change names in TestCompute.
	chRemove  = "remove"
	chAdd     = "add"
	chReview  = "review"
	chArchive = "archive"
)

func TestCompute(t *testing.T) {
	board := Board{DoneID: optDone, InReviewID: optReview}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	const retention = 14 * 24 * time.Hour

	// Each row is one piece of content. onBoard places it on the board
	// with status; closedAgo > 0 makes it a closed issue; open lists it as
	// an open repository issue with ready reporting a ready pull request.
	rows := []struct {
		name      string
		pr        bool
		onBoard   bool
		status    string
		closedAgo time.Duration
		open      bool
		ready     bool
		want      []string
	}{
		{name: "pull request", pr: true, onBoard: true, want: []string{chRemove}},
		{name: "done past retention", onBoard: true, status: optDone, closedAgo: retention + time.Second,
			want: []string{chArchive}},
		{name: "done at retention", onBoard: true, status: optDone, closedAgo: retention},
		{name: "done recently", onBoard: true, status: optDone, closedAgo: time.Hour},
		{name: "closed outside done", onBoard: true, status: optProgress, closedAgo: retention + time.Hour},
		{name: "open in done", onBoard: true, status: optDone, open: true},
		{name: "ready in progress", onBoard: true, status: optProgress, open: true, ready: true,
			want: []string{chReview}},
		{name: "ready without status", onBoard: true, open: true, ready: true, want: []string{chReview}},
		{name: "ready in review", onBoard: true, status: optReview, open: true, ready: true},
		{name: "not ready in review", onBoard: true, status: optReview, open: true},
		{name: "missing", open: true, want: []string{chAdd}},
		{name: "missing and ready", open: true, ready: true, want: []string{chAdd, chReview}},
	}

	var items []Item
	var open []Issue
	for _, r := range rows {
		if r.onBoard {
			it := Item{ID: "item " + r.name, Kind: KindIssue, ContentID: r.name, Ref: r.name, StatusID: r.status}
			if r.pr {
				it.Kind = KindPullRequest
			}
			if r.closedAgo > 0 {
				it.Closed, it.ClosedAt = true, now.Add(-r.closedAgo)
			}
			items = append(items, it)
		}
		if r.open {
			open = append(open, Issue{ID: r.name, Ref: r.name, InReview: r.ready})
		}
	}

	p := Compute(board, items, open, now, retention)

	got := map[string][]string{}
	for _, it := range p.Remove {
		got[it.Ref] = append(got[it.Ref], chRemove)
	}
	for _, is := range p.Add {
		got[is.Ref] = append(got[is.Ref], chAdd)
	}
	for _, is := range p.Review {
		got[is.Ref] = append(got[is.Ref], chReview)
	}
	for _, it := range p.Archive {
		got[it.Ref] = append(got[it.Ref], chArchive)
	}
	changes := 0
	for _, r := range rows {
		changes += len(r.want)
		if !slices.Equal(got[r.name], r.want) {
			t.Errorf("%s: changes %v, want %v", r.name, got[r.name], r.want)
		}
	}
	if p.Empty() {
		t.Error("Empty() = true for a plan with changes")
	}
	if n := len(p.Lines()); n != changes {
		t.Errorf("Lines() has %d entries, want %d", n, changes)
	}
}

func TestComputeNoChanges(t *testing.T) {
	board := Board{DoneID: optDone, InReviewID: optReview}
	const id = "issue"
	items := []Item{{ID: "item", Kind: KindIssue, ContentID: id, Ref: id, StatusID: optReview}}
	open := []Issue{{ID: id, Ref: id, InReview: true}}
	if p := Compute(board, items, open, time.Now(), time.Hour); !p.Empty() {
		t.Errorf("Compute() = %+v, want no changes", p)
	}
}
