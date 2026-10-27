# Develop Galactic

Start with the [system overview](../overview.md) and the component guide for the
code you will change. [Coding conventions](conventions.md) define the repository's
rules; [documentation maintenance](documentation.md) explains where docs belong.

## Tools and environment

The runtime and networking tests require Linux. Use Go at the version declared
in [go.mod](../../go.mod), Task, a C compiler, clang and LLVM with the BPF target,
and the Linux headers needed by code generation. The
[development container](../../.devcontainer/galactic/) supplies a starting
environment. Tool pins in [Taskfile.yaml](../../Taskfile.yaml) and the
[CI workflow](../../.github/workflows/ci.yaml) take precedence over copied
version lists.

End-to-end tests also need a Docker daemon, kubectl, Kind and permission to
load the VRF kernel module. Real-kernel unit tests require root and the kernel
features they exercise. Run them on an isolated development host.

## Build and test

Run commands from the repository root:

```sh
task build
task test:unit
```

The build regenerates eBPF objects before Go formatting, vetting and compilation,
then writes binaries to `bin/`. The unit task runs race detection and coverage
and checks the separate reference-provider module. An unprivileged unit run
skips root-gated networking tests; it does not validate the kernel datapath.

For a focused Go test, first generate the objects the module embeds:

```sh
task build:ebpf
go test ./internal/plumbing/intf/...
```

Use `task test:unit-root` in an appropriately privileged environment for the
root-gated packages. Preserve the selected Go/Task/clang tools and any envtest
assets when elevating privileges; the CI root-test job shows the supported
environment setup. Tests that need an API server use `KUBEBUILDER_ASSETS` from
controller-runtime's setup-envtest tool. Read test skip messages as missing
coverage, not passed assertions.

Before every PR:

```sh
task ci
```

This runs lint, build, unit tests and the Kind lifecycle e2e test. It does not
include every feature's lab acceptance test, root unit tests, alert tests or
full-table fabric diagnostics load test. Run the additional checks appropriate
to the change, and report skipped or unavailable checks explicitly.

`task test:e2e` creates and deletes its Kind cluster and builds/loads the CNI
image. It is separate from the multi-cluster [ContainerLab walkthrough](../getting-started.md).

## Generated artifacts

| Artifact                          | Command                  | Policy                                                                              |
| --------------------------------- | ------------------------ | ----------------------------------------------------------------------------------- |
| eBPF Go bindings and object files | `task build:ebpf`        | Generated before builds; ignored artifacts must not be committed.                   |
| CRDs and deepcopy methods         | `task generate:crd`      | Commit the generated output with API changes. Requires controller-gen.              |
| Protobuf bindings                 | `task generate:proto`    | Commit generated Go files; never hand-edit them. Requires the buf/plugin toolchain. |
| API documentation                 | `task generate:api-docs` | Commit the output with source changes; see the [API index](../api/README.md).       |

The Taskfile defines the actual generation commands. Avoid independently
maintaining copies of those commands or dependency versions in component docs.

## CI and release artifacts

The [CI workflow](../../.github/workflows/ci.yaml) separates lint, ordinary unit
tests, privileged unit tests, builds and e2e checks. The privileged job loads
kernel support and runs root-gated tests that the ordinary unit job cannot
exercise. The eBPF compiler is pinned in CI because verifier behavior depends
on the generated program as well as its C source.

The [publish workflow](../../.github/workflows/publish.yaml) builds per-component
images from [containers/](../../containers/) and publishes the configuration
bundle. A local `task build` is not an image release. Component docs describe
their runtime requirements; the workflow and Dockerfiles define release
artifacts and build dependencies.

When a failure occurs, record the failing command, commit, toolchain, relevant
kernel capabilities and any skipped checks. Do not infer production readiness
from an unprivileged test run or a documentation-only CI result.
