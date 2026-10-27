# Logging

Every long-running Galactic binary (`galactic-router`, `galactic-gateway`,
`galactic-nat`, `galactic-vrf`, `galactic-controller`, `galactic-edge`,
`galactic-cni`, `fabric-router-controller`, `fabric-api` and
`fabric-config-agent`) installs one logger at startup through
`internal/logging`. The same handler writes the binary's own `slog` lines, the
standard `log` package, controller-runtime (reconciler errors, cache and leader
election) and klog (client-go), so every line has one format and one level
threshold. For `galactic-cni` that covers the `install-cni` init container and
the `credential-refresh` daemon; for `fabric-config-agent`, the `frr-init` init
container and the `config-agent` sidecar.

| Flag           | Env          | Default | Meaning                            |
| -------------- | ------------ | ------- | ---------------------------------- |
| `--log-level`  | `LOG_LEVEL`  | `info`  | `debug`, `info`, `warn` or `error` |
| `--log-format` | `LOG_FORMAT` | `json`  | `json` or `text`                   |

An explicit flag wins over the environment variable. `--log-level` also
accepts what Go's `slog` parses beyond the four names: any case, and an offset
such as `info+2`.

An unsupported value stops the binary at startup, before it does anything
else, whether it comes from the flag or the environment variable. A DaemonSet
with one crash-loops on every node. `task test:manifests`, which CI runs,
renders every kustomization under `config/` and `deploy/` and fails on an
unsupported value for a container running one of these binaries.
`hack/check-log-settings` applies the same rules (`internal/logging`'s
`ValidateLevel` and `ValidateFormat`) to any YAML, so downstream manifests
should run it on their rendered output, with a Galactic release that includes
it:

```sh
kustomize build <overlay> | go run go.datum.net/galactic/hack/check-log-settings@<version> -
```

It recognizes a Galactic container by its image repository name, and checks
only literal values, not ones read from a ConfigMap or Secret. An empty
`LOG_LEVEL` or `LOG_FORMAT` counts as unset. In source YAML that isn't
rendered, such as the containerlab overlays, it reads strategic-merge patches
but not JSON 6902 patches.

Production runs the defaults: one JSON object per line on stderr, with
`time`, `level` and `msg` keys. controller-runtime's lines also carry a
`logger` key naming the component. Its verbose lines (`V(1)` and up) appear
only at `--log-level=debug`. klog keeps its own verbosity setting, which these
flags don't change, so client-go's `klog.V(n)` lines stay off.

A binary that fails after reading its flags logs the error as one `error`
line through the same handler, then exits 1. A bad flag or an invalid
`--log-level` or `--log-format` fails before the handler exists, so that one
line is Go's default text.

For local runs, `--log-format=text --log-level=debug` gives readable output
with the verbose lines. No binary enables controller-runtime's zap development
mode: `internal/logging`'s `TestBinariesUseThisPackage` fails when a command
under `cmd/` imports controller-runtime's zap package or calls `SetLogger`
itself, and `TestLongRunningBinariesInstallTheHandler` fails when a command
under `cmd/` doesn't import `internal/logging` at all.

Two kinds of command are exempt. The CNI plugins (`galactic-veth`,
`galactic-tap`, `galactic-ipam`, `galactic-bgp` and `galactic-route`) run once
per CNI call and write JSON to their own log file; see the
[CNI environment variables](../cni/environment-variables.md).
`galactic-usid` is a one-shot codec command in the debug image.
