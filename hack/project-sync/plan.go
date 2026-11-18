// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"
)

// Kind is the type of content a project item holds.
type Kind string

const (
	KindIssue       Kind = "Issue"
	KindPullRequest Kind = "PullRequest"
)

// Item is a project item that is not archived.
type Item struct {
	ID        string
	Kind      Kind
	ContentID string
	// Ref names the content for output, such as "datum-cloud/galactic#12".
	Ref string
	// StatusID is the selected Status option's ID, or empty when unset.
	StatusID string
	// Closed and ClosedAt describe an issue; they are unset for other kinds.
	Closed   bool
	ClosedAt time.Time
}

// Issue is an open issue in the synchronized repository.
type Issue struct {
	ID  string
	Ref string
	// InReview reports whether a linked pull request is open and not a
	// draft.
	InReview bool
}

// Board identifies the Status options the rules set and read.
type Board struct {
	DoneID     string
	InReviewID string
}

// Plan lists the changes that bring a project in line with the rules.
type Plan struct {
	// Remove holds pull request items; the project tracks only issues.
	Remove []Item
	// Add holds open issues that have no visible item, including issues
	// whose item is archived.
	Add []Issue
	// Review holds open issues with a ready pull request whose Status is
	// not In review, including issues in Add.
	Review []Issue
	// Archive holds Done issues closed longer than the retention period.
	Archive []Item
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool {
	return len(p.Remove)+len(p.Add)+len(p.Review)+len(p.Archive) == 0
}

// Lines describes each change in the order Apply makes them.
func (p Plan) Lines() []string {
	lines := make([]string, 0, len(p.Remove)+len(p.Add)+len(p.Review)+len(p.Archive))
	for _, it := range p.Remove {
		lines = append(lines, "remove pull request "+it.Ref)
	}
	for _, is := range p.Add {
		lines = append(lines, "add issue "+is.Ref)
	}
	for _, is := range p.Review {
		lines = append(lines, "set issue "+is.Ref+" to In review")
	}
	for _, it := range p.Archive {
		lines = append(lines, fmt.Sprintf("archive issue %s, closed %s", it.Ref, it.ClosedAt.UTC().Format(time.RFC3339)))
	}
	return lines
}

// Compute returns the changes the rules require for the project's visible
// items and the repository's open issues. The pull request and archive
// rules apply to every item on the board, whatever its repository. An issue
// counts as Done for archiving only once it is closed, and its age is
// measured from closing; a closed issue without a close time is kept.
func Compute(board Board, items []Item, open []Issue, now time.Time, retention time.Duration) Plan {
	var p Plan
	byContent := make(map[string]Item, len(items))
	cutoff := now.Add(-retention)
	for _, it := range items {
		switch it.Kind {
		case KindPullRequest:
			p.Remove = append(p.Remove, it)
		case KindIssue:
			byContent[it.ContentID] = it
			if it.Closed && it.StatusID == board.DoneID && !it.ClosedAt.IsZero() && it.ClosedAt.Before(cutoff) {
				p.Archive = append(p.Archive, it)
			}
		}
	}
	for _, is := range open {
		it, ok := byContent[is.ID]
		if !ok {
			p.Add = append(p.Add, is)
		}
		if is.InReview && (!ok || it.StatusID != board.InReviewID) {
			p.Review = append(p.Review, is)
		}
	}
	return p
}
