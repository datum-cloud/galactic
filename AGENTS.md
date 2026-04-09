# Repository Guidelines

## Purpose & Architecture

Galactic is a Kubernetes network operator that gives pods declarative multi-cloud VPC connectivity using SRv6 and kernel VRF isolation. Users create two CRDs (`VPC`, `VPCAttachment`) and annotate pods; Galactic handles all routing. The control plane is a Go operator (`internal/operator/controller/`) that assigns identifiers and generates Multus `NetworkAttachmentDefinition` resources. A DaemonSet agent (`internal/agent/srv6/`) manages kernel SRv6 routes and VRFs per node. The CNI plugin (`internal/cni/`) runs in-process with the agent, registering container endpoints via gRPC. A Python router service (`router/`) receives endpoint registrations over MQTT, computes all-pairs routes, and broadcasts them back to agents.

**Data flow:** VPC/VPCAttachment CRDs → operator assigns 48-bit/16-bit hex IDs → NetworkAttachmentDefinition written → pod annotation triggers webhook (adds Multus annotation) → CNI runs → gRPC registers endpoint with agent → MQTT publishes to router → router computes routes → MQTT broadcasts route updates → agents configure SRv6 + VRF forwarding.

**Non-obvious decisions:**
- VPC identifiers are 48-bit hex; VPCAttachment identifiers are 16-bit hex. These are embedded into IPv6 SRv6 endpoint addresses for deterministic route lookups.
- Identifiers are also Base62-encoded for interface naming (VRF: `vrfX-Y`, veth host side: `galX-Y`) to keep kernel interface name length within limits.
- The binary auto-detects CNI mode via the `CNI_COMMAND` env var; otherwise runs as a Cobra CLI with `operator`, `agent`, `cni`, `version` subcommands.

## Tech Stack

- **Go 1.24** (toolchain 1.24.2) — operator, agent, CNI plugin
- **Python ≥3.13** — router service (async via `aiorun`, ORM via `sqlmodel` + Alembic)
- **controller-runtime v0.21 / k8s v1.33** — operator framework
- **Multus CNI** — multi-network for pods; Galactic generates NADs automatically
- **gRPC + protobuf** — CNI-to-agent local communication (`pkg/proto/local/`)
- **MQTT (paho / aiomqtt)** — agent-to-router remote messaging (`pkg/proto/remote/`)
- **SRv6 + netlink** — kernel-level routing; `github.com/vishvananda/netlink`
- **Ginkgo/Gomega** — Go BDD-style tests; **behave** — Python BDD tests
- **controller-gen v0.18 / kustomize v5.6** — code + manifest generation (managed by Makefile, vendored to `bin/`)

## Development Workflow

```
make build          # produces bin/galactic
make test           # gen + fmt + vet + unit tests with coverage
make lint           # golangci-lint; lint-fix applies safe auto-fixes
make run-operator   # run operator against current kubeconfig
make run-agent      # run agent (requires root / CAP_NET_ADMIN)
make test-e2e       # requires Kind; setup-test-e2e creates the cluster
make manifests      # regenerate CRDs + RBAC from Go types (run after API changes)
make generate       # regenerate DeepCopy methods (run after API type changes)
```

Router (run from `router/`):
```
pip install -e .[test]   # installs runtime + test deps
flake8 .                 # Python lint (wemake-python-styleguide strict)
behave                   # runs all BDD feature scenarios
```

**Before every PR:** `make lint test` (Go) and `flake8 . && behave` (router changes).

**Envtest binaries** are downloaded to `bin/` by `make setup-envtest`. CI pins Kubernetes 1.31 for controller tests.

## Code Standards

See [CONVENTIONS.md](CONVENTIONS.md) for the full, prescriptive coding standards covering Go and Python naming, error handling, testing patterns, API type conventions, code generation, linting, and commit messages.

Summary:
- Go: `gofmt`/`goimports` enforced; golangci-lint with `errcheck`, `staticcheck`, `govet`, `revive`, `gocyclo`, `dupl`, `unused` (see `.golangci.yml`). `lll` excluded from `api/` and `internal/`.
- Python: `flake8` + `wemake-python-styleguide`; `snake_case` modules/functions, `CapWords` classes, 4-space indent.
- Generated files (`zz_generated.deepcopy.go`, CRD YAMLs) are committed; regenerate with `make generate manifests` after type changes. Never hand-edit them.
- Kubebuilder marker annotations (`+kubebuilder:rbac`, `+kubebuilder:object:root`, etc.) drive code + manifest generation — keep them accurate.

## Current State

- **Known debt:** e2e tests only run on `main`/release branches (not PRs), so regressions in cluster behavior can merge undetected. Unit coverage exists for `identifier`, `cniconfig`, and `pkg/common/util`; controller reconciler logic has envtest coverage but agent/CNI paths do not.
- **In flux:** The SRv6 route management (`internal/agent/srv6/`) and VRF utilities (`pkg/common/vrf/`) are the least tested and most likely to change as multi-cloud routing matures.
- **Router migrations:** Alembic migrations in `router/alembic/versions/` must be run before deploying a new router version; they're not auto-applied in the operator.

## New Developer Entry Points

1. Run `make build` to verify toolchain; run `make test` to confirm envtest and unit tests pass.
2. Read `pkg/apis/v1alpha/vpc_types.go` and `vpcattachment_types.go` — the CRD types are the core abstraction.
3. Trace `internal/operator/controller/vpcattachment_controller.go` — it wires operator reconciliation to Multus NAD generation.
4. Read `internal/cni/cni.go` (cmdAdd/cmdDel) to understand the container attach path.
5. Read `router/galactic_router/__init__.py` → `router/static.py` for route computation logic.
6. `config/samples/` has working VPC, VPCAttachment, and annotated Pod examples.

**Likely trip-ups:**
- `make run-agent` requires elevated privileges (netlink, VRF, SRv6 operations need `CAP_NET_ADMIN`).
- After modifying API types, you must run both `make generate` and `make manifests` or CRD YAML and DeepCopy will be out of sync.
- The router uses Python ≥3.13 features; older interpreters will fail silently or with confusing errors.
