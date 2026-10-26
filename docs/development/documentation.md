# Maintain the documentation

Documentation describes the code at the checked-out revision. A deployment's
enabled features and qualification results are separate facts. Keep those
distinctions visible when writing a guide or reporting a test result.

## Choose one home

| Content                                        | Home                                                                        |
| ---------------------------------------------- | --------------------------------------------------------------------------- |
| What Galactic does and who owns each boundary  | [Overview](../overview.md)                                                  |
| First local run                                | [Getting started](../getting-started.md)                                    |
| Build, test, release workflow and coding rules | [Development](README.md)                                                    |
| Component behavior and invariants              | The component's architecture or feature guide                               |
| Supported settings and defaults                | The component's configuration reference                                     |
| Deployment, recovery and rollback              | The component's deployment/operations guide                                 |
| Cross-component host procedures and migrations | [Operations](../operations/README.md)                                       |
| Metric semantics and scrape setup              | [Observability](../observability/README.md)                                 |
| API fields                                     | Generated [API references](../api/README.md), with source comments as input |
| Future behavior or a retained design decision  | [Designs](../designs/README.md)                                             |
| Dated review or measurement                    | [Archive](../archive/README.md)                                             |

Link to the canonical explanation instead of copying tables, defaults or build
steps into every architecture page. Document source entry points that help a
reader change the feature; avoid exhaustive function and repository inventories.

## Make status explicit

Designs state whether behavior is proposed, partially implemented, implemented
or superseded, and identify remaining work. Implementation does not imply a
production rollout. Preserve exact revision, environment and limitations with
historical measurements. A release guide must name current prerequisites rather
than treating an old review's open-findings table as a permanent release gate.

Retain migrations while supported deployments need them. Before archiving a
document, move any current instructions or unresolved requirements into an
indexed maintained page, and link to that page from the historical record.

## Keep links and examples usable

Add new maintained pages to a reachable index. When moving a widely referenced
page, update repository links and keep a short compatibility pointer at its old
path. Preserve important old fragments with explicit HTML anchors when headings
change. Compatibility pages contain navigation, not a second maintained copy.

Examples use illustrative addresses and clearly named placeholders. State the
working directory, prerequisites, expected outcome and rollback for operational
commands. Prefer links to tested lab fixtures over large copied manifests.

## Validate a change

Install the pinned Markdown parser in a virtual environment using the
[API reference instructions](../api/README.md#checking-documentation), then run
`task docs:check` for local links, anchors and generated API coverage. Run
`task docs:check-generated` when changing API comments or generator configuration. Regenerate rendered diagrams whenever their source
changes, following the [diagram instructions](../architecture/README.md).

These checks cannot establish that prose correctly describes runtime behavior.
Review changed defaults against configuration code, placement against manifests,
and lifecycle claims against implementation and tests. When a check is not run,
say so; do not add a fresh verification date as a substitute.

Follow the repository's pre-PR checks as well. A docs-only change should not
claim it executed a deployment, incident procedure or load test merely because
the commands parse and their links resolve.
