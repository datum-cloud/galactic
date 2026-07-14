# Coding Conventions

This document defines the coding standards, naming rules, error handling patterns, testing conventions, and idioms enforced across this codebase. All contributors must follow these rules. Automated checks (golangci-lint) enforce many of them; the rest are enforced in code review.

---

## Go

### Module and package layout

- Module: `go.datum.net/galactic`
- `cmd/galactic-cni/main.go` — CNI plugin entry point; a cobra command (no viper) with the plugin invocation on the root command (calls `cni.RunPlugin()`) and `init`/`run` subcommands wrapping `internal/installer.Bootstrap`/`Run` for the DaemonSet
- `cmd/galactic-router/main.go` / `root.go` — router entry point; `main.go` is a thin wrapper, startup logic (reads `GALACTIC_ROUTER_NODE_NAME`/`GALACTIC_ROUTER_ROUTER_MODE`, starts the controller-runtime manager) lives in `root.go`
- `internal/plumbing/` — low-level kernel and network primitives shared between router and CNI (`intf`, `srv6`, `sysctl`, `vrf`)
- `internal/controller/` — controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance, BGPPolicy, Secret, Node, GC); also contains field index registration (`indexer.go`) and CRD status helpers (`status.go`)
- `internal/reconcile/` — CRD → DesiredRouter translation
- `internal/runtime/` — RouterRuntime interface; `gobgp/` (tenant mode) and `frr/` (fabric mode stub)
- `internal/gc/` — orphaned `BGPAdvertisement`/`BGPVRFInstance` CRD and stale kernel VRF cleanup, invoked by the GC controller's ticker
- `internal/cni/` — CNI plugin (`cmdAdd`/`cmdDel`/`cmdCheck`, split across `ops_add.go`/`ops_del.go`/`ops_check.go`/`bgp.go`); `ipam/`, `route/`, `tap/`, `veth/` subpackages
- `internal/installer/` — `galactic-cni` DaemonSet `init`/`run` support (binary staging, conflist/kubeconfig templating, credential refresh, gRPC health server); not a subpackage of `internal/cni`
- `internal/model/` — internal BGP model types
- `internal/hash/` — SHA-256 change detection over DesiredRouter
- `internal/metadata/` — build-time version vars (`Version`, `GitCommit`, etc.) stamped via `-ldflags`

There is no dedicated metrics package — `cmd/galactic-router/root.go` wires
controller-runtime's built-in `metricsserver.Options` to expose Prometheus metrics;
`prometheus/client_golang` is only an indirect dependency pulled in transitively.

Place new code in `internal/` unless it must be imported by an external caller. Prefer creating a focused sub-package over adding to an existing large one.

### Import grouping

Use three groups, separated by blank lines:

1. Standard library
2. Third-party and Kubernetes packages
3. Internal packages (`go.datum.net/galactic/...`)

`goimports` enforces this automatically, with `gci` grouping standard library,
then `go.datum.net`-prefixed packages, then everything else (see `.golangci.yaml`).
Alias imports use a short, descriptive name — typically the API group + version
for generated clients (`metav1`, `corev1`, `bgpv1alpha1` for
`go.datum.net/network/api/v1alpha1`, `apierrors`, `clientgoscheme`,
`utilruntime`) or a package-role name to disambiguate collisions
(`vrfpkg`, `galacticruntime`).

```go
import (
    "context"
    "fmt"

    "google.golang.org/grpc"

    "go.datum.net/galactic/internal/plumbing/intf"
)
```

### Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Package | lowercase, single word, matches directory | `package srv6` |
| Exported type | `CapWords` | `PoolAllocator` (`internal/cni/ipam`) |
| Exported function / method | `CamelCase` | `RouteIngressAdd` |
| Unexported function / method | `camelCase` | `parseSID`, `addIngressRoute` (`internal/plumbing/srv6`) |
| Exported constant | `CamelCase`, descriptive | `BGPPolicyDirectionImport` (`internal/model`, re-exports the BGP API enum) |
| Test package | same package as norm; `<name>_test` for the rare external-test case | `package cni` (internal, the norm); `package intf_test` (external, `internal/plumbing/intf`) |
| K8s API import aliases | domain-prefixed group-version | `bgpv1alpha1`, `metav1`, `corev1` |

Do not use `_` in Go identifiers except in test package names.

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

Run `task lint` before every PR. All linters listed in `.golangci.yaml` must pass. Suppressions require a comment explaining why. Active linters (golangci-lint v2): `copyloopvar`, `errcheck`, `errname`, `errorlint`, `goconst`, `gocyclo`, `govet`, `ineffassign`, `intrange`, `lll`, `misspell`, `nakedret`, `noctx`, `perfsprint`, `prealloc`, `revive`, `staticcheck`, `unconvert`, `unparam`, `unused`. Formatters: `gci`, `gofmt`, `goimports`.

There are no path-based lint exclusions — `.golangci.yaml` has no `issues.exclude-rules` block, so every linter applies uniformly across the module (there is no `lab/` directory to exclude; the ContainerLab tree lives at `deploy/containerlab/`).

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

- Test package name: same package as the code under test is the norm (e.g. `package cni`, `package srv6`) — used by 11 of the 12 `_test.go` files under `internal/`. The external `<name>_test` package (e.g. `package intf_test` for `internal/plumbing/intf`) is the exception, used when a package's public API alone is enough to exercise the tests.
- Name test cases using `UpperCamelCase` (e.g., `"VPCValue"`, `"UppercaseInput"`).
- Use `wantError bool` to test error presence; do not test error message strings unless the message is part of the contract.

### What not to test

- `internal/plumbing/vrf` has no unit tests — it requires `CAP_NET_ADMIN` and a real kernel; new code there should prefer e2e tests (`task test:e2e`).
- `internal/cni` and `internal/plumbing/srv6` now have unit coverage for their pure-logic paths (config parsing, route-target math, SID validation) — kernel-mutating calls within them are still better covered by e2e than mocks.

---

## YAML files

Always use the `.yaml` extension, never `.yml`. This applies to all YAML files in the repository: Taskfiles, ContainerLab topologies, Kubernetes manifests, CI workflows, and configuration files.

---

## Markdown

Align all table columns so that the `|` delimiters are vertically flush. Pad cells with spaces to match the widest value in each column. Apply this to every table in `.md` files, including CLAUDE.md, CONVENTIONS.md, ARCHITECTURE.md, and inline doc comments.

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

This matches the "Before every PR" guidance in `AGENTS.md`/`CLAUDE.md`. `internal/plumbing/vrf` is not covered by unit tests (requires `CAP_NET_ADMIN`); new code there should prefer e2e tests over mock-heavy unit tests.
