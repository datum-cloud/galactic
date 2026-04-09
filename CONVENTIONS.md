# Coding Conventions

This document defines the coding standards, naming rules, error handling patterns, testing conventions, and idioms enforced across this codebase. All contributors must follow these rules. Automated checks (golangci-lint, flake8) enforce many of them; the rest are enforced in code review.

---

## Go

### Module and package layout

- Module: `go.datum.net/galactic`
- `cmd/galactic/main.go` — binary entry point; all Cobra subcommands registered here
- `pkg/apis/v1alpha/` — public CRD types; only add types here that are part of the Kubernetes API surface
- `pkg/common/` — utilities shared between operator, agent, and CNI
- `pkg/proto/local/` / `pkg/proto/remote/` — gRPC / protobuf generated files plus hand-written convenience wrappers
- `internal/operator/` — operator reconcilers, identifier logic, CNI config generation, webhooks
- `internal/agent/srv6/` — kernel SRv6 route and VRF management
- `internal/cni/` — CNI plugin (cmdAdd / cmdDel implementation)
- `internal/cmd/` — one sub-package per Cobra subcommand (`agent`, `cni`, `operator`, `version`)

Place new code in `internal/` unless it must be imported by an external caller. Prefer creating a focused sub-package over adding to an existing large one.

### Import grouping

Use three groups, separated by blank lines:

1. Standard library
2. Third-party and Kubernetes packages
3. Internal packages (`go.datum.net/galactic/...`)

`goimports` enforces this automatically. Alias imports use the last meaningful path segment as the short name (`ctrl`, `metav1`, `corev1`, `nadv1`, `galacticv1alpha`).

```go
import (
    "context"
    "fmt"

    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    galacticv1alpha "go.datum.net/galactic/pkg/apis/v1alpha"

    "go.datum.net/galactic/internal/operator/identifier"
)
```

### Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Package | lowercase, single word, matches directory | `package controller` |
| Exported type | `CapWords` | `VPCAttachmentReconciler` |
| Exported function / method | `CamelCase` | `RouteIngressAdd` |
| Unexported function / method | `camelCase` | `vpcAttachmentsToIdentifiers` |
| Exported constant | `CamelCase`, descriptive | `MaxVPC`, `MaxIdentifierAttemptsVPCAttachment` |
| Test package | `<name>_test` | `package identifier_test` |
| K8s API import aliases | domain-prefixed group-version | `galacticv1alpha`, `nadv1`, `metav1` |

Do not use `_` in Go identifiers except in test package names.

### Error handling

- Wrap errors with context using `fmt.Errorf("what failed: %w", err)`. The context string must complete the sentence "could not `<what>`".
- Collect multiple independent errors with `errors.Join(errs...)` and return the joined error.
- In controllers, return `ctrl.Result{}, client.IgnoreNotFound(err)` on the initial resource fetch (expected not-found on deletion).
- Return `ctrl.Result{RequeueAfter: duration}, nil` when waiting for a dependency (e.g., VPC not yet ready). Do not return an error for expected transient states.
- Never swallow errors silently. If an error truly cannot be actionable, log it before discarding.
- Do not add error handling for scenarios that the code guarantees cannot happen.

```go
// correct
if err := r.Get(ctx, req.NamespacedName, &vpc); err != nil {
    return ctrl.Result{}, client.IgnoreNotFound(err)
}

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

### Reconciler structure

- Reconciler struct embeds `client.Client` and `Scheme *runtime.Scheme`; add service dependencies as named pointer fields.
- All state assignments must be idempotent — guard with conditions before mutating:
  ```go
  if vpcAttachment.Status.Identifier == "" {
      // assign once
  }
  ```
- Use `controllerutil.CreateOrUpdate` for Kubernetes resources the reconciler manages.
- Always call `controllerutil.SetControllerReference` to wire ownership for garbage collection.
- Named the controller in `SetupWithManager` using `.Named("lowercase-kind")`.

### Kubebuilder markers (API types)

Every field in an API type must have either `// +required` or `// +optional`. Required fields must not carry `omitempty`. Optional fields must carry `omitempty`. Embedded structs (`TypeMeta`, `ObjectMeta`) carry both `omitempty` and `omitzero`.

```go
// +required
Spec VPCSpec `json:"spec"`

// +optional
Status VPCStatus `json:"status,omitempty,omitzero"`
```

RBAC markers live on the `Reconcile` method of each controller, not on the struct.

### Code generation

Generated files (`zz_generated.deepcopy.go`, CRD YAML in `config/crd/bases/`, protobuf `*.pb.go`) must never be hand-edited. After any change to API types:

```
make generate   # regenerates DeepCopy methods
make manifests  # regenerates CRD YAML and RBAC
```

Both commands must be run together. Generated files are committed to version control.

The boilerplate license header (`hack/boilerplate.go.txt`) is injected automatically by controller-gen.

### Linting

Run `make lint` before every PR. All linters listed in `.golangci.yml` must pass. Suppressions require a comment explaining why. Notable active linters: `errcheck`, `staticcheck`, `govet`, `revive`, `gocyclo`, `dupl`, `unused`, `ginkgolinter`.

Exclusions by path:
- `lll` is excluded from `api/*` and `internal/*`
- `dupl` is excluded from `internal/*`
- The `lab/` directory is entirely excluded

---

## Python (router service)

### Python version

Requires Python ≥ 3.13. Do not use compatibility shims for older versions.

### Naming

| Element | Convention |
|---------|-----------|
| Module / file | `snake_case` |
| Function / method | `snake_case` |
| Variable | `snake_case` |
| Class | `CapWords` |
| Constant (module level) | `UPPER_SNAKE_CASE` |

### Formatting and style

- 4-space indent; no tabs.
- `flake8` with `wemake-python-styleguide` enforces all style rules. Run from `router/`: `flake8 .`
- Suppress only specific codes with inline `# noqa: WPSxxx` comments at the end of the offending line. Do not use bare `# noqa`.
- Common suppressions used in this codebase:
  - `# noqa: WPS211,WPS216` — many arguments in CLI entry-point functions
  - `# noqa: WPS457` — `while True:` event loops
  - `# noqa: WPS432` — magic hex bit-mask constants
  - `# noqa: WPS214,WPS338` — classes with many methods / method overrides

### Type annotations

Use type hints on all function signatures. Use `->` return type annotations. Use `pydantic` / `sqlmodel` type-annotated models instead of plain dicts for structured data.

```python
async def handle_register(self, event: RegisterEvent) -> bool:
```

### Async patterns

- Service classes implement an async `run()` coroutine.
- Concurrent service startup uses `asyncio.TaskGroup`:
  ```python
  async with asyncio.TaskGroup() as tg:
      for service in services:
          tg.create_task(service)
  ```
- Top-level entry via `aiorun.run(...)` with `stop_on_unhandled_errors=True`.
- Event dispatch via `bubus` `EventBus`; handlers receive typed event objects (`RegisterEvent`, `DeregisterEvent`, `RouteEvent`).

### Static methods for pure functions

Elevate pure functions that do not access `self` to `@staticmethod`:

```python
def extract_vpc_from_srv6_endpoint(endpoint: str) -> tuple[str, str]:
    ...
```

### Database

- Use `sqlmodel` with SQLAlchemy for ORM.
- Use `Session` as a context manager: `with Session(engine) as session:`.
- All schema changes go through Alembic migrations in `router/alembic/versions/`. Never modify tables outside of migrations.
- Migrations are not auto-applied at startup by default; run `alembic upgrade head` before deploying a new router version.

### Logging

Use the standard `logging` module. Obtain a logger per module: `logger = logging.getLogger("ModuleName")`. Use `logger.info`, `logger.warning`, `logger.error`. Prefer structured f-strings in log messages.

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
        got, err := id.FromValue(tt.value, identifier.MaxVPC)
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

### Go — controller / integration tests (Ginkgo + Gomega)

- Dot-import both `ginkgo/v2` and `gomega` in controller test files.
- Each controller has its own `_test.go` file and shares a `suite_test.go` in the same package.
- Suite bootstrap in `suite_test.go`: one `TestXxx(t *testing.T)` function that calls `RegisterFailHandler(Fail)` then `RunSpecs(t, "Suite Name")`.
- envtest provides a real Kubernetes API server. CRDs are loaded from `config/crd/bases`. Run `make setup-envtest` before running tests.
- Annotate test steps with `By("description")` to produce readable output on failure.
- Lifecycle: `BeforeEach` for setup, `AfterEach` for cleanup; always clean up created objects.
- Assert status fields are falsy/empty immediately after creation before reconciliation:
  ```go
  Expect(resource.Status.Ready).To(BeFalse())
  Expect(resource.Status.Identifier).To(BeEmpty())
  ```

### Python — BDD tests (behave)

- Feature files live in `router/features/` using Gherkin syntax (`Feature:`, `Scenario:`, `Given`/`When`/`Then`).
- Step definitions live in `router/features/steps/`.
- Step functions are async: `async def step_xxx(context, ...)`.
- Use `deepdiff.DeepDiff` with `ignore_order=True` for comparing unordered collections of route events.
- Run: `behave` from `router/`.

### What not to test

- Do not mock the Kubernetes API server in controller tests — use envtest.
- Do not write tests for generated code (`zz_generated.deepcopy.go`, `*.pb.go`).
- Agent and CNI kernel-path code (`internal/agent/srv6/`, `internal/cni/`) currently has no unit coverage; new code in those paths should prefer integration/e2e over fragile mock-heavy unit tests.

---

## Protobuf / gRPC

- `.proto` files live in `pkg/proto/local/` (CNI-to-agent local gRPC) and `pkg/proto/remote/` (agent-to-router MQTT).
- Generated `*.pb.go` / `*_grpc.pb.go` files must never be hand-edited.
- Each proto package has a hand-written convenience wrapper (`local.go`, `remote.go`) that exposes a cleaner Go API over the generated types. Add helpers there rather than importing generated types directly in application code.

---

## Kubernetes manifests (Kustomize)

- `config/` uses Kustomize. `config/default/` is the base overlay for production deployment.
- CRD manifests in `config/crd/bases/` are generated — never edit by hand.
- RBAC roles are generated from kubebuilder markers — never edit `config/rbac/role.yaml` by hand.
- `config/samples/` contains working examples of VPC, VPCAttachment, and annotated Pod; keep samples up to date with API changes.

---

## Commit messages

Use imperative mood, sentence case, present tense. First line ≤ 72 characters. Reference issues where applicable.

```
Add SRv6 egress route cleanup on VPCAttachment deletion

Fixes #42
```

---

## Pre-PR checklist

Before opening a pull request, run all of the following and ensure they pass:

```sh
# Go
make lint test

# Python (if router changed)
cd router && flake8 . && behave
```

e2e tests (`make test-e2e`) run only on `main` and release branches, not on PRs. Do not rely on them to catch regressions — write unit or integration tests instead.
