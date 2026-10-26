# Coding Conventions

This document defines the coding standards, naming rules, error handling patterns, testing conventions, and idioms enforced across this codebase. All contributors must follow these rules. Automated checks (golangci-lint) enforce many of them; the rest are enforced in code review.

---

## Go

### Package boundaries

Use `internal/` for implementation packages unless another repository must
import the API. Keep kernel primitives, reconciliation and API types separate.
The [system overview](../overview.md) and component architecture guides describe
ownership and the useful entry points; do not duplicate their source inventories
here.

### Import grouping

Use three groups, separated by blank lines:

1. Standard library
2. `go.datum.net` packages
3. Other third-party and Kubernetes packages

The configured `gci` order is standard library, `go.datum.net`-prefixed
packages, then other dependencies. Follow [.golangci.yaml](../../.golangci.yaml)
when formatting; `goimports` also adds and removes imports.
Alias imports use a short, descriptive name — typically the API group + version
for generated clients (`metav1`, `corev1`, `bgpv1alpha1` for
`go.datum.net/galactic/api/network/v1alpha1`, `apierrors`, `clientgoscheme`,
`utilruntime`) or a package-role name to disambiguate collisions
(`vrfpkg`, `galacticruntime`).

```go
import (
    "context"
    "fmt"

    "go.datum.net/galactic/internal/plumbing/intf"

    "google.golang.org/grpc"
)
```

### Naming

| Element                      | Convention                                                          | Example                                                                                      |
| ---------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Package                      | lowercase, single word, matches directory                           | `package srv6`                                                                               |
| Exported type                | `CapWords`                                                          | `PoolAllocator` (`internal/cni/ipam`)                                                        |
| Exported function / method   | `CamelCase`                                                         | `RouteIngressAdd`                                                                            |
| Unexported function / method | `camelCase`                                                         | `parseSID`, `addIngressRoute` (`internal/plumbing/srv6`)                                     |
| Exported constant            | `CamelCase`, descriptive                                            | `BGPPolicyDirectionImport` (`internal/model`, re-exports the BGP API enum)                   |
| Test package                 | same package as norm; `<name>_test` for the rare external-test case | `package cni` (internal, the norm); `package intf_test` (external, `internal/plumbing/intf`) |
| K8s API import aliases       | domain-prefixed group-version                                       | `bgpv1alpha1`, `metav1`, `corev1`                                                            |

Do not use `_` in Go identifiers except in test package names.

### Docstrings

A function or method docstring describes the function itself: what it does,
what its parameters mean, and what it returns — including the error
conditions it can produce. Nothing else belongs in it.

- Do not describe historical context: no "used to do X", "replaced an
  earlier Y design", "added after an incident", or any other narration of
  how the function changed over time. That belongs in the commit message
  that made the change, not in text every future reader has to read.
- Do not link out to other documents for context: no URLs, no "see
  docs/...", no "see ARCHITECTURE-*.md". A docstring must stand on its own —
  a reader should never have to leave the function to understand its
  contract. Design rationale that genuinely needs a home belongs in the
  relevant component architecture guide, not folded into
  the docstring.
- Do not name specific deployment environments, infra vendors, or site names,
  and do not claim something was "found live in production" — describe the
  general mechanism and failure mode a function guards against, not the
  specific incident or platform that surfaced it.
- Keep it short: state the contract in as few sentences as the behavior
  actually requires.

```go
// Good — the function, its inputs, and its output, nothing else
// resolveBGPLocalAddress returns explicit when non-empty, and otherwise calls
// detect to read the BGP local address from the host's loopback. A detection
// failure is an error; there is no silent fallback to an unset address.
func resolveBGPLocalAddress(explicit string, detect func() (string, error)) (string, error) { ... }

// Bad — historical narrative and an external link instead of the contract
// resolveBGPLocalAddress was added when the router moved off a hardcoded
// address; see docs/router/configuration.md for the full migration history.
// It used to just read GALACTIC_ROUTER_BGP_LOCAL_ADDRESS directly...
func resolveBGPLocalAddress(explicit string, detect func() (string, error)) (string, error) { ... }
```

This applies to exported and unexported function/method docstrings alike.

### Error handling

- Wrap errors with context using `fmt.Errorf("what failed: %w", err)`. The context string must complete the sentence "could not `<what>`".
- Collect multiple independent errors with `errors.Join(errs...)` and return the joined error.
- Never swallow errors silently. If an error truly cannot be actionable, log it before discarding.
- Do not add error handling for scenarios that the code guarantees cannot happen.

```go
// from internal/cni/ops_check.go:cmdCheck — multiple independent checks
var errs []error
if err := checkGuestInterface(args.Netns, guestName); err != nil {
    errs = append(errs, fmt.Errorf("guest interface %q: %w", guestName, err))
}
if err := checkTerminationRoutes(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.Terminations); err != nil {
    errs = append(errs, fmt.Errorf("termination routes: %w", err))
}
if len(errs) > 0 {
    return fmt.Errorf("CHECK failed: %w", errors.Join(errs...))
}
```

### Constants

Define sentinel / limit values as typed or untyped constants at package level, grouped in a `const (...)` block when there are several related ones. Re-exported BGP API enums live in `internal/model` (e.g. `BGPPolicyDirectionImport = bgpv1alpha1.BGPPolicyDirectionImport`).

### Linting

Run `task lint` before every PR. The enabled linters, formatters and narrow
source/path exclusions are defined in [.golangci.yaml](../../.golangci.yaml).
Suppressions require an explanation. Do not maintain a second list of enabled
linters or exclusions in this guide.

---

## Testing

### Go — unit tests

Use the standard `testing` package. Follow table-driven test style:

```go
// from internal/plumbing/intf/intf_test.go (package intf_test)
tests := []struct {
    name      string
    input     string
    want      string
    wantError bool
}{
    {"VPCValue", testVPCHex, testVPCBase62, false},
    {"VPCAttachmentValue", testVPCAttachmentHex, testVPCAttachmentB62, false},
    {"Zero", "0", "0", false},
    {"UppercaseInput", "4D2", testVPCBase62, false}, // input normalised to lowercase
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        got, err := intf.HexToBase62(tt.input)
        if (err != nil) != tt.wantError {
            t.Errorf("HexToBase62(%s) error = %v, wantError = %v", tt.input, err, tt.wantError)
        }
        if !tt.wantError && got != tt.want {
            t.Errorf("HexToBase62(%s) = %s, want %s", tt.input, got, tt.want)
        }
    })
}
```

- Use the same package as the code under test when tests need internal state.
  Use an external `<name>_test` package when the public API is sufficient.
- Name test cases using `UpperCamelCase` (e.g., `"VPCValue"`, `"UppercaseInput"`).
- Use `wantError bool` to test error presence; do not test error message strings unless the message is part of the contract.

### Kernel and API tests

Use focused unit tests for pure logic. Test kernel behavior with real-kernel
tests rather than mocks that only restate netlink calls. `internal/plumbing/vrf`
includes privileged tests for VRF sharing, allocation, unreachable defaults and
cleanup. Root-gated tests run through `task test:unit-root`; they skip in an
unprivileged run. API admission tests also require envtest assets.

The [development guide](README.md) explains the test tiers and prerequisites.
Use lab/e2e checks for behavior that spans components, and report any skipped
coverage explicitly.

---

## YAML files

Always use the `.yaml` extension, never `.yml`. This applies to all YAML files in the repository: Taskfiles, ContainerLab topologies, Kubernetes manifests, CI workflows, and configuration files.

---

## Markdown

Align all table columns so that the `|` delimiters are vertically flush. Pad cells with spaces to match the widest value in each column. Apply this to every table in `.md` files, including CLAUDE.md, CONVENTIONS.md, every `ARCHITECTURE*.md` file, and inline doc comments.

```markdown
// unaligned — not allowed
| Element | Convention | Example |
|---------|-----------|---------|
| Package | lowercase  | `package srv6` |

// aligned — required
| Element | Convention | Example        |
|---------|------------|----------------|
| Package | lowercase  | `package srv6` |
```

---

## Commit messages

Use Conventional Commits format: `<type>(<scope>): <description>`. First line ≤ 72 characters. Reference issues where applicable.

Common types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`.

```
feat(agent): embed GoBGP and manage lifecycle via bootstrap
fix(lint): resolve CI lint and yamllint failures
chore(deps): update github actions
```

---

## Pre-PR checklist

Before opening a pull request, run:

```sh
task ci   # lint → build → test:unit → test:e2e
```

This matches the repository instructions. Run the additional privileged,
API-server, alert or lab checks appropriate to the changed behavior, as described
in the [development guide](README.md).
