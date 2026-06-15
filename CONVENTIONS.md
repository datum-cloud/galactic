# Coding Conventions

This document defines the coding standards, naming rules, error handling patterns, testing conventions, and idioms enforced across this codebase. All contributors must follow these rules. Automated checks (golangci-lint) enforce many of them; the rest are enforced in code review.

---

## Go

### Module and package layout

- Module: `go.datum.net/galactic`
- `cmd/galactic/main.go` — binary entry point; all Cobra subcommands registered here
- `pkg/common/` — utilities shared between agent and CNI
- `pkg/proto/local/` — gRPC / protobuf generated files plus hand-written convenience wrapper for CNI-to-agent communication
- `internal/agent/` — agent entry point and gRPC server; `srv6/` subdirectory owns kernel SRv6 route and VRF management
- `internal/cni/` — CNI plugin (cmdAdd / cmdDel implementation)
- `internal/cmd/` — one sub-package per Cobra subcommand (`cni`, `version`)
- `internal/gobgp/` — embedded GoBGP server lifecycle
- `internal/bootstrap/` — agent startup sequencing (BGPProvider resource management)
- `internal/metrics/` — Prometheus metrics registration

Place new code in `internal/` unless it must be imported by an external caller. Prefer creating a focused sub-package over adding to an existing large one.

### Import grouping

Use three groups, separated by blank lines:

1. Standard library
2. Third-party and Kubernetes packages
3. Internal packages (`go.datum.net/galactic/...`)

`goimports` enforces this automatically. Alias imports use the last meaningful path segment as the short name (`nadv1`, `localgrpc`).

```go
import (
    "context"
    "fmt"

    "google.golang.org/grpc"

    "go.datum.net/galactic/pkg/proto/local"
)
```

### Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Package | lowercase, single word, matches directory | `package srv6` |
| Exported type | `CapWords` | `RouteIngress` |
| Exported function / method | `CamelCase` | `RouteIngressAdd` |
| Unexported function / method | `camelCase` | `buildSRv6Encap` |
| Exported constant | `CamelCase`, descriptive | `MaxVPC`, `MaxVPCAttachment` |
| Test package | `<name>_test` | `package util_test` |
| K8s API import aliases | domain-prefixed group-version | `nadv1`, `metav1` |

Do not use `_` in Go identifiers except in test package names.

### Error handling

- Wrap errors with context using `fmt.Errorf("what failed: %w", err)`. The context string must complete the sentence "could not `<what>`".
- Collect multiple independent errors with `errors.Join(errs...)` and return the joined error.
- Never swallow errors silently. If an error truly cannot be actionable, log it before discarding.
- Do not add error handling for scenarios that the code guarantees cannot happen.

```go
// correct — multiple independent operations
var errs []error
if err := neighborproxy.Add(...); err != nil {
    errs = append(errs, fmt.Errorf("neighborproxy add failed: %w", err))
}
if err := routeegress.Add(...); err != nil {
    errs = append(errs, fmt.Errorf("routeegress add failed: %w", err))
}
return errors.Join(errs...)
```

### Constants

Define sentinel / limit values as typed or untyped constants at package level. Use hex notation for bit-mask constants:

```go
const MaxVPC uint64 = 0xFFFFFFFFFFFF
const MaxVPCAttachment uint64 = 0xFFFF
```

### Code generation

Generated protobuf files (`*.pb.go`, `*_grpc.pb.go` in `pkg/proto/local/`) must never be hand-edited. Regenerate them using the `protoc` toolchain when `.proto` files change. Generated files are committed to version control.

### Linting

Run `task lint` before every PR. All linters listed in `.golangci.yaml` must pass. Suppressions require a comment explaining why. Active linters: `copyloopvar`, `dupl`, `errcheck`, `goconst`, `gocyclo`, `govet`, `ineffassign`, `lll`, `misspell`, `nakedret`, `prealloc`, `revive`, `staticcheck`, `unconvert`, `unparam`, `unused`.

Exclusions by path:
- `lll` and `dupl` are excluded from `internal/*`
- The `lab/` directory is entirely excluded

---

## Testing

### Go — unit tests

Use the standard `testing` package. Follow table-driven test style:

```go
tests := []struct {
    name           string
    value          uint64
    wantIdentifier string
    wantError      bool
}{
    {"InvalidSpecialMin", 0, "", true},
    {"Valid", 12345, "000000003039", false},
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        got, err := id.FromValue(tt.value, MaxVPC)
        if (err != nil) != tt.wantError {
            t.Errorf("FromValue() error = %v, wantError = %v", err, tt.wantError)
        }
        if got != tt.wantIdentifier {
            t.Errorf("FromValue() got = %v, want = %v", got, tt.wantIdentifier)
        }
    })
}
```

- Test package name: `package <name>_test` (external test package).
- Name test cases using `UpperCamelCase` (e.g., `"ValidMin"`, `"InvalidSpecialMax"`).
- Use `wantError bool` to test error presence; do not test error message strings unless the message is part of the contract.

### What not to test

- Do not write tests for generated code (`*.pb.go`, `*_grpc.pb.go`).
- Agent and CNI kernel-path code (`internal/agent/srv6/`, `internal/cni/`) currently has no unit coverage; new code in those paths should prefer integration/e2e over fragile mock-heavy unit tests.

---

## Protobuf / gRPC

- `.proto` files live in `pkg/proto/local/` (CNI-to-agent local gRPC).
- Generated `*.pb.go` / `*_grpc.pb.go` files must never be hand-edited.
- Each proto package has a hand-written convenience wrapper (`local.go`) that exposes a cleaner Go API over the generated types. Add helpers there rather than importing generated types directly in application code.

---

## YAML files

Always use the `.yaml` extension, never `.yml`. This applies to all YAML files in the repository: Taskfiles, ContainerLab topologies, Kubernetes manifests, CI workflows, and configuration files.

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

Before opening a pull request, run all of the following and ensure they pass:

```sh
task lint test
```

Agent and CNI kernel-path code is not covered by unit tests. New code in those paths should prefer integration or e2e tests over mock-heavy unit tests.
