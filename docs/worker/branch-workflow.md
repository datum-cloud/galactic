# Integration branch workflow

Status: in use (D15). Every Task of
[epic #1430](https://github.com/datum-cloud/galactic/issues/1430) follows it.

## Branch and base

| Item         | Value                                                                                                        |
| ------------ | ------------------------------------------------------------------------------------------------------------ |
| Branch       | `integration/galactic-worker`                                                                                |
| Main base    | `11323a99642aecb0e53220c1dbc49f61652f0b52`, the planning baseline and the comparison point for qualification |
| Branch start | `451eb40ec1ee6238f1e59dfeda8d69e594a4d8a8`, a signed empty commit whose parent is the main base              |
| PR target    | `integration/galactic-worker`, for every implementation and evidence PR                                      |

### Why the start commit exists

`publish.yaml` tags images and the bundle with the short commit SHA,
`v0.0.0-<sha>`. If the branch started at the main base, its first push would
publish `v0.0.0-11323a9` again. A branch build is amd64 only, so that push
would replace the multi-architecture images main already published under the
same tag. The empty start commit gives the branch its own SHA, and every later
commit on the branch has a SHA that main does not.

### Upstream changes

The branch takes changes from `main` only on purpose. Record each one here,
with the main commit and the reason, in the PR that brings it in.

| Main commit | Brought in by | Reason |
| ----------- | ------------- | ------ |
| None yet    |               |        |

## CI

`ci.yaml` and `required-ci.yaml` run on `pull_request` without a base-branch
filter, so they run on every PR to `integration/galactic-worker`. Each PR runs
`task ci` locally before review and reports the CI runs against its base.

## Artifacts

`publish.yaml` runs on every branch push. The reusable workflows in
`datum-cloud/actions` (pinned at `v1.27.1`) tag a push to
`integration/galactic-worker` as follows:

| Tag                                                  | Meaning                                                           |
| ---------------------------------------------------- | ----------------------------------------------------------------- |
| `v0.0.0-integration-galactic-worker`                 | Moves with every push to the branch                               |
| `v0.0.0-integration-galactic-worker-YYYYMMDD-HHmmss` | One per push, from the commit date                                |
| `v0.0.0-<short-sha>`                                 | One per commit, for example `v0.0.0-451eb40` for the start commit |

Branch images are amd64 only. The workflow publishes images for every
component except `galactic-debug`, which publishes only from `main` and release
tags, and a `galactic-kustomize` bundle. A branch push never moves
`v0.0.0-main`, which the staging labs follow, and never creates a `v*` release.
Qualification ([#1442](https://github.com/datum-cloud/galactic/issues/1442))
pins artifacts by `v0.0.0-<short-sha>`.

Pushing a Task's own branch (for example `docs/issue-1431`) also runs
`publish.yaml` and tags `v0.0.0-<that-branch>`. Those artifacts are for review
only and are never used for qualification.

The [publish run for the push of the start commit](https://github.com/datum-cloud/galactic/actions/runs/44399031276)
is the evidence that branch pushes publish only the tags above.

## Closing a Task

1. The PR targets `integration/galactic-worker`, carries the Task's acceptance
   evidence, and says `Fixes datum-cloud/galactic#<task>`.
2. GitHub closes issues only from merges to the default branch, so after the
   merge, check the PR's base and merged SHA.
3. Close the Task by hand with a comment naming the PR and the merged SHA.
4. Keep the epic open until the integrated evidence of #1442 is reviewed.
   Merging the branch into `main`, publishing a release and rolling out to the
   fleet each need a separate decision.
