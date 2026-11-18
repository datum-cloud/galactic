// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "test-token"

// Fixture pages for the fake GraphQL API. The board's first page holds a pull
// request and a draft issue; its second holds a Done issue, closed at the
// time formatted into it, and an issue In progress.
const boardPage1 = `{"organization": {"projectV2": {
  "id": "proj",
  "field": {"id": "status", "options": [
    {"id": "opt-progress", "name": "In progress"},
    {"id": "opt-review", "name": "In review"},
    {"id": "opt-done", "name": "Done"}]},
  "items": {"pageInfo": {"hasNextPage": true, "endCursor": "c1"}, "nodes": [
    {"id": "item-pr", "isArchived": false, "fieldValueByName": null,
     "content": {"__typename": "PullRequest", "id": "pr-1", "number": 9,
                 "repository": {"nameWithOwner": "o/r"}}},
    {"id": "item-draft", "isArchived": false, "fieldValueByName": null,
     "content": {"__typename": "DraftIssue", "id": "draft-1"}}]}}}}`

const boardPage2 = `{"organization": {"projectV2": {
  "id": "proj",
  "field": {"id": "status", "options": [
    {"id": "opt-progress", "name": "In progress"},
    {"id": "opt-review", "name": "In review"},
    {"id": "opt-done", "name": "Done"}]},
  "items": {"pageInfo": {"hasNextPage": false, "endCursor": "c2"}, "nodes": [
    {"id": "item-old", "isArchived": false, "fieldValueByName": {"optionId": "opt-done"},
     "content": {"__typename": "Issue", "id": "issue-old", "number": 1,
                 "state": "CLOSED", "closedAt": "%s",
                 "repository": {"nameWithOwner": "o/r"}}},
    {"id": "item-ready", "isArchived": false, "fieldValueByName": {"optionId": "opt-progress"},
     "content": {"__typename": "Issue", "id": "issue-ready", "number": 2,
                 "state": "OPEN", "closedAt": null,
                 "repository": {"nameWithOwner": "o/r"}}}]}}}}`

const issuesPage1 = `{"repository": {"issues": {
  "pageInfo": {"hasNextPage": true, "endCursor": "i1"}, "nodes": [
    {"id": "issue-ready", "number": 2, "closedByPullRequestsReferences": {"nodes": [
      {"state": "OPEN", "isDraft": true}, {"state": "OPEN", "isDraft": false}]}}]}}}`

const issuesPage2 = `{"repository": {"issues": {
  "pageInfo": {"hasNextPage": false, "endCursor": "i2"}, "nodes": [
    {"id": "issue-new", "number": 3, "closedByPullRequestsReferences": {"nodes": [
      {"state": "OPEN", "isDraft": false}]}},
    {"id": "issue-drafting", "number": 4, "closedByPullRequestsReferences": {"nodes": [
      {"state": "OPEN", "isDraft": true}]}}]}}}`

const noReviewOption = `{"organization": {"projectV2": {
  "id": "proj",
  "field": {"id": "status", "options": [{"id": "opt-done", "name": "Done"}]},
  "items": {"pageInfo": {"hasNextPage": false}, "nodes": []}}}}`

// fakeGitHub serves the fixture pages and records each mutation as
// "<mutation> <item or content ID>":
//
//   - item-pr holds a pull request;
//   - item-old holds issue-old, closed in Done well past retention;
//   - item-ready holds issue-ready, In progress with a ready pull request;
//   - issue-new, not on the board, has a ready pull request;
//   - issue-drafting, not on the board, has only a draft pull request.
type fakeGitHub struct {
	t *testing.T
	// failID makes mutations on this item or content ID fail.
	failID string
	// archivedID makes adding this content return an archived item.
	archivedID string

	mu        sync.Mutex
	mutations []string
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
		return
	}
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.t.Errorf("decode request: %v", err)
		return
	}
	vars := map[string]string{}
	for k, v := range req.Variables {
		vars[k] = fmt.Sprint(v)
	}
	reply := func(data string) { _, _ = fmt.Fprintf(w, `{"data": %s}`, data) }

	if strings.HasPrefix(req.Query, "mutation") {
		f.mutate(w, req.Query, vars, reply)
		return
	}
	pages := map[string]string{
		"projectV2(number": boardPage1,
		"repository(owner": issuesPage1,
	}
	next := map[string]string{
		"projectV2(number": fmt.Sprintf(boardPage2, time.Now().Add(-30*24*time.Hour).Format(time.RFC3339)),
		"repository(owner": issuesPage2,
	}
	for marker, first := range pages {
		if !strings.Contains(req.Query, marker) {
			continue
		}
		if vars["after"] == "" {
			reply(first)
		} else {
			reply(next[marker])
		}
		return
	}
	f.t.Errorf("unexpected query: %s", req.Query)
}

func (f *fakeGitHub) mutate(w http.ResponseWriter, query string, vars map[string]string, reply func(string)) {
	name := query[strings.Index(query, "{")+1:]
	name = strings.TrimSpace(name[:strings.Index(name, "(")])
	id := vars["item"]
	if id == "" {
		id = vars["content"]
	}
	if id == f.failID {
		_, _ = fmt.Fprint(w, `{"data":null,"errors":[{"message":"denied"}]}`)
		return
	}
	rec := name + " " + id
	if opt := vars["option"]; opt != "" {
		rec += " " + vars["field"] + "=" + opt
	}
	f.mu.Lock()
	f.mutations = append(f.mutations, rec)
	f.mu.Unlock()
	if name == "addProjectV2ItemById" {
		reply(fmt.Sprintf(`{"addProjectV2ItemById": {"item": {"id": "item-%s", "isArchived": %t}}}`, id, id == f.archivedID))
		return
	}
	reply(`{}`)
}

var validArgs = []string{"-org", "o", "-project", "1", "-repo", "o/r"}

func runAgainst(t *testing.T, f *fakeGitHub, extra ...string) error {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Setenv("GH_TOKEN", testToken)
	t.Setenv("GITHUB_GRAPHQL_URL", srv.URL)
	return run(context.Background(), append(slices.Clone(validArgs), extra...))
}

func TestRunAppliesRules(t *testing.T) {
	f := &fakeGitHub{t: t}
	if err := runAgainst(t, f); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{
		"deleteProjectV2Item item-pr",
		"addProjectV2ItemById issue-new",
		"addProjectV2ItemById issue-drafting",
		"updateProjectV2ItemFieldValue item-ready status=" + optReview,
		"updateProjectV2ItemFieldValue item-issue-new status=" + optReview,
		"archiveProjectV2Item item-old",
	}
	if !slices.Equal(f.mutations, want) {
		t.Errorf("mutations:\n got %q\nwant %q", f.mutations, want)
	}
}

func TestRunRestoresArchivedOpenIssue(t *testing.T) {
	f := &fakeGitHub{t: t, archivedID: "issue-new"}
	if err := runAgainst(t, f); err != nil {
		t.Fatalf("run: %v", err)
	}
	restore := slices.Index(f.mutations, "unarchiveProjectV2Item item-issue-new")
	review := slices.Index(f.mutations, "updateProjectV2ItemFieldValue item-issue-new status="+optReview)
	if restore < 0 || review < restore {
		t.Errorf("archived open issue not restored before its status was set; mutations: %q", f.mutations)
	}
}

func TestRunContinuesAfterFailedChange(t *testing.T) {
	f := &fakeGitHub{t: t, failID: "issue-new"}
	err := runAgainst(t, f)
	if err == nil || !strings.Contains(err.Error(), "add issue o/r#3") || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("run error = %v, want the failed add reported", err)
	}
	for _, m := range f.mutations {
		if strings.Contains(m, "item-issue-new") {
			t.Errorf("changed an issue whose add failed: %s", m)
		}
	}
	if !slices.Contains(f.mutations, "archiveProjectV2Item item-old") {
		t.Errorf("later changes skipped after a failure; mutations: %q", f.mutations)
	}
}

func TestRunDryRunMutatesNothing(t *testing.T) {
	f := &fakeGitHub{t: t}
	if err := runAgainst(t, f, "-dry-run"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.mutations) != 0 {
		t.Errorf("dry run made mutations: %q", f.mutations)
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	t.Setenv("GH_TOKEN", testToken)
	// set returns validArgs with one flag's value replaced or removed.
	set := func(flag, value string) []string {
		args := slices.Clone(validArgs)
		i := slices.Index(args, flag)
		if value == "" {
			return slices.Delete(args, i, i+2)
		}
		args[i+1] = value
		return args
	}
	for _, args := range [][]string{
		set("-org", ""),
		set("-project", ""),
		set("-project", "-1"),
		set("-repo", "r"),
		set("-repo", "o/r/x"),
		append(slices.Clone(validArgs), "-done-retention", "0s"),
	} {
		if err := run(context.Background(), args); err == nil {
			t.Errorf("run(%q) succeeded, want an error", args)
		}
	}
	t.Setenv("GH_TOKEN", "")
	if err := run(context.Background(), validArgs); err == nil {
		t.Error("run without GH_TOKEN succeeded, want an error")
	}
}

func TestDoRejectsErrors(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"http status": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "rate limited", http.StatusForbidden)
		},
		"graphql errors with partial data": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, `{"data":{"x":1},"errors":[{"message":"Resource not accessible by integration"}]}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			c := &Client{URL: srv.URL, Token: "t", HTTP: srv.Client()}
			var out json.RawMessage
			if err := c.Do(context.Background(), "query { x }", nil, &out); err == nil {
				t.Error("Do succeeded, want an error")
			}
		})
	}
}

func TestLoadProjectRequiresStatusOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data": %s}`, noReviewOption)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Token: "t", HTTP: srv.Client()}
	if _, err := LoadProject(context.Background(), c, "o", 1); err == nil || !strings.Contains(err.Error(), "In review") {
		t.Errorf("LoadProject error = %v, want missing In review option", err)
	}
}
