// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command project-sync keeps an organization project board in line with a
// repository's issues:
//
//   - every open issue in the repository is on the board and not archived;
//   - pull requests are removed from the board;
//   - an open issue with a linked pull request that is open and not a draft
//     has Status In review;
//   - a closed issue with Status Done is archived once it has been closed
//     longer than the retention period.
//
// Linked pull requests are those GitHub lists as closing the issue, from a
// closing keyword or the issue's Development panel. The board's Status field
// must have Done and In review options. The command never moves an issue out
// of In review and never touches draft issues.
//
// It reads a token with read access to the repository's issues and write
// access to the project from GH_TOKEN, and the GraphQL endpoint from
// GITHUB_GRAPHQL_URL, defaulting to https://api.github.com/graphql.
//
//	GH_TOKEN=... go run ./hack/project-sync -org datum-cloud -project 88 -repo datum-cloud/galactic -dry-run
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "project-sync:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("project-sync", flag.ContinueOnError)
	org := fs.String("org", "", "organization that owns the project")
	number := fs.Int("project", 0, "project number")
	repo := fs.String("repo", "", "repository whose issues the project tracks, as owner/name")
	retention := fs.Duration("done-retention", 14*24*time.Hour, "how long a closed Done issue stays on the board")
	dryRun := fs.Bool("dry-run", false, "print the changes without making them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	owner, name, ok := strings.Cut(*repo, "/")
	if *org == "" || *number <= 0 || !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return errors.New("-org, -project and -repo owner/name are required")
	}
	if *retention <= 0 {
		return errors.New("-done-retention must be positive")
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return errors.New("GH_TOKEN is not set")
	}
	url := os.Getenv("GITHUB_GRAPHQL_URL")
	if url == "" {
		url = "https://api.github.com/graphql"
	}
	c := &Client{URL: url, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}

	proj, err := LoadProject(ctx, c, *org, *number)
	if err != nil {
		return err
	}
	issues, err := LoadOpenIssues(ctx, c, owner, name)
	if err != nil {
		return err
	}
	plan := Compute(proj.Board, proj.Items, issues, time.Now(), *retention)
	fmt.Printf("%d visible items, %d open issues\n", len(proj.Items), len(issues))
	if plan.Empty() {
		fmt.Println("no changes")
		return nil
	}
	if *dryRun {
		for _, l := range plan.Lines() {
			fmt.Println("would", l)
		}
		return nil
	}
	return Apply(ctx, c, proj, plan)
}
