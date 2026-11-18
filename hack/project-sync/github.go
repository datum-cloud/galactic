// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls the GitHub GraphQL API.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

type gqlError struct {
	Message string `json:"message"`
}

// Do runs a GraphQL operation and decodes its data into out. It fails on an
// HTTP error status or when the response lists any error, so a partial
// result is never used.
func (c *Client) Do(ctx context.Context, query string, vars map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("graphql: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []gqlError      `json:"errors"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("graphql: decode response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		msgs := make([]string, len(envelope.Errors))
		for i, e := range envelope.Errors {
			msgs[i] = e.Message
		}
		return fmt.Errorf("graphql: %s", strings.Join(msgs, "; "))
	}
	return json.Unmarshal(envelope.Data, out)
}

type pageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

const projectQuery = `query($org: String!, $number: Int!, $after: String) {
  organization(login: $org) {
    projectV2(number: $number) {
      id
      field(name: "Status") {
        ... on ProjectV2SingleSelectField { id options { id name } }
      }
      items(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isArchived
          fieldValueByName(name: "Status") {
            ... on ProjectV2ItemFieldSingleSelectValue { optionId }
          }
          content {
            __typename
            ... on Issue { id number state closedAt repository { nameWithOwner } }
            ... on PullRequest { id number repository { nameWithOwner } }
          }
        }
      }
    }
  }
}`

// Project is an organization project with its Status field.
type Project struct {
	ID            string
	StatusFieldID string
	Board         Board
	Items         []Item
}

// LoadProject reads the project, the IDs of its Done and In review Status
// options, and every visible item. It fails when the project has no Status
// field or either option is missing.
func LoadProject(ctx context.Context, c *Client, org string, number int) (*Project, error) {
	var p Project
	vars := map[string]any{"org": org, "number": number}
	for {
		var data struct {
			Organization struct {
				ProjectV2 *struct {
					ID    string `json:"id"`
					Field *struct {
						ID      string `json:"id"`
						Options []struct {
							ID   string `json:"id"`
							Name string `json:"name"`
						} `json:"options"`
					} `json:"field"`
					Items struct {
						PageInfo pageInfo `json:"pageInfo"`
						Nodes    []struct {
							ID         string `json:"id"`
							IsArchived bool   `json:"isArchived"`
							Status     *struct {
								OptionID string `json:"optionId"`
							} `json:"fieldValueByName"`
							Content *struct {
								Typename   string     `json:"__typename"`
								ID         string     `json:"id"`
								Number     int        `json:"number"`
								State      string     `json:"state"`
								ClosedAt   *time.Time `json:"closedAt"`
								Repository struct {
									NameWithOwner string `json:"nameWithOwner"`
								} `json:"repository"`
							} `json:"content"`
						} `json:"nodes"`
					} `json:"items"`
				} `json:"projectV2"`
			} `json:"organization"`
		}
		if err := c.Do(ctx, projectQuery, vars, &data); err != nil {
			return nil, fmt.Errorf("load project %s/%d: %w", org, number, err)
		}
		proj := data.Organization.ProjectV2
		if proj == nil {
			return nil, fmt.Errorf("project %s/%d not found", org, number)
		}
		if p.ID == "" {
			if proj.Field == nil || proj.Field.ID == "" {
				return nil, fmt.Errorf("project %s/%d has no single-select Status field", org, number)
			}
			p.ID, p.StatusFieldID = proj.ID, proj.Field.ID
			for _, o := range proj.Field.Options {
				switch o.Name {
				case "Done":
					p.Board.DoneID = o.ID
				case "In review":
					p.Board.InReviewID = o.ID
				}
			}
			if p.Board.DoneID == "" || p.Board.InReviewID == "" {
				return nil, fmt.Errorf("project %s/%d Status field needs both Done and In review options", org, number)
			}
		}
		for _, n := range proj.Items.Nodes {
			if n.IsArchived || n.Content == nil {
				continue
			}
			kind := Kind(n.Content.Typename)
			if kind != KindIssue && kind != KindPullRequest {
				continue
			}
			it := Item{
				ID:        n.ID,
				Kind:      kind,
				ContentID: n.Content.ID,
				Ref:       fmt.Sprintf("%s#%d", n.Content.Repository.NameWithOwner, n.Content.Number),
			}
			if n.Status != nil {
				it.StatusID = n.Status.OptionID
			}
			if kind == KindIssue && n.Content.State == "CLOSED" {
				it.Closed = true
				if n.Content.ClosedAt != nil {
					it.ClosedAt = *n.Content.ClosedAt
				}
			}
			p.Items = append(p.Items, it)
		}
		if !proj.Items.PageInfo.HasNextPage {
			return &p, nil
		}
		vars["after"] = proj.Items.PageInfo.EndCursor
	}
}

const issuesQuery = `query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    issues(states: OPEN, first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id
        number
        closedByPullRequestsReferences(first: 25, includeClosedPrs: false) {
          nodes { state isDraft }
        }
      }
    }
  }
}`

// LoadOpenIssues reads every open issue in owner/name and whether any linked
// pull request is open and ready for review.
func LoadOpenIssues(ctx context.Context, c *Client, owner, name string) ([]Issue, error) {
	var issues []Issue
	vars := map[string]any{"owner": owner, "name": name}
	for {
		var data struct {
			Repository *struct {
				Issues struct {
					PageInfo pageInfo `json:"pageInfo"`
					Nodes    []struct {
						ID     string `json:"id"`
						Number int    `json:"number"`
						PRs    struct {
							Nodes []struct {
								State   string `json:"state"`
								IsDraft bool   `json:"isDraft"`
							} `json:"nodes"`
						} `json:"closedByPullRequestsReferences"`
					} `json:"nodes"`
				} `json:"issues"`
			} `json:"repository"`
		}
		if err := c.Do(ctx, issuesQuery, vars, &data); err != nil {
			return nil, fmt.Errorf("load issues of %s/%s: %w", owner, name, err)
		}
		if data.Repository == nil {
			return nil, fmt.Errorf("repository %s/%s not found", owner, name)
		}
		for _, n := range data.Repository.Issues.Nodes {
			is := Issue{ID: n.ID, Ref: fmt.Sprintf("%s/%s#%d", owner, name, n.Number)}
			for _, pr := range n.PRs.Nodes {
				if pr.State == "OPEN" && !pr.IsDraft {
					is.InReview = true
				}
			}
			issues = append(issues, is)
		}
		if !data.Repository.Issues.PageInfo.HasNextPage {
			return issues, nil
		}
		vars["after"] = data.Repository.Issues.PageInfo.EndCursor
	}
}

const (
	removeMutation = `mutation($project: ID!, $item: ID!) {
  deleteProjectV2Item(input: {projectId: $project, itemId: $item}) { deletedItemId }
}`
	addMutation = `mutation($project: ID!, $content: ID!) {
  addProjectV2ItemById(input: {projectId: $project, contentId: $content}) { item { id isArchived } }
}`
	unarchiveMutation = `mutation($project: ID!, $item: ID!) {
  unarchiveProjectV2Item(input: {projectId: $project, itemId: $item}) { item { id } }
}`
	statusMutation = `mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {
    projectId: $project, itemId: $item, fieldId: $field, value: {singleSelectOptionId: $option}
  }) { projectV2Item { id } }
}`
	archiveMutation = `mutation($project: ID!, $item: ID!) {
  archiveProjectV2Item(input: {projectId: $project, itemId: $item}) { item { id } }
}`
)

// Apply makes the plan's changes: it removes pull requests, adds missing
// issues and restores any whose item was archived, sets In review, and
// archives old Done issues. A failed change does not stop the others;
// every failure is returned. Each change is idempotent, so the next run
// retries what failed.
func Apply(ctx context.Context, c *Client, proj *Project, p Plan) error {
	var errs []error
	// onItem runs a mutation on one project item and reports its outcome.
	onItem := func(query, itemID, done string, extra map[string]any) bool {
		vars := map[string]any{"project": proj.ID, "item": itemID}
		for k, v := range extra {
			vars[k] = v
		}
		var out json.RawMessage
		if err := c.Do(ctx, query, vars, &out); err != nil {
			err = fmt.Errorf("%s: %w", done, err)
			errs = append(errs, err)
			fmt.Println("error:", err)
			return false
		}
		fmt.Println(done)
		return true
	}

	for _, it := range p.Remove {
		onItem(removeMutation, it.ID, "remove pull request "+it.Ref, nil)
	}

	itemOf := make(map[string]string, len(proj.Items))
	for _, it := range proj.Items {
		itemOf[it.ContentID] = it.ID
	}
	for _, is := range p.Add {
		var out struct {
			Add struct {
				Item struct {
					ID         string `json:"id"`
					IsArchived bool   `json:"isArchived"`
				} `json:"item"`
			} `json:"addProjectV2ItemById"`
		}
		if err := c.Do(ctx, addMutation, map[string]any{"project": proj.ID, "content": is.ID}, &out); err != nil {
			err = fmt.Errorf("add issue %s: %w", is.Ref, err)
			errs = append(errs, err)
			fmt.Println("error:", err)
			continue
		}
		item := out.Add.Item
		if !item.IsArchived {
			itemOf[is.ID] = item.ID
			fmt.Println("add issue", is.Ref)
			continue
		}
		if onItem(unarchiveMutation, item.ID, "restore archived issue "+is.Ref, nil) {
			itemOf[is.ID] = item.ID
		}
	}

	for _, is := range p.Review {
		// An issue whose add or restore failed was already reported.
		if item, ok := itemOf[is.ID]; ok {
			onItem(statusMutation, item, "set issue "+is.Ref+" to In review",
				map[string]any{"field": proj.StatusFieldID, "option": proj.Board.InReviewID})
		}
	}

	for _, it := range p.Archive {
		onItem(archiveMutation, it.ID, "archive issue "+it.Ref, nil)
	}
	return errors.Join(errs...)
}
