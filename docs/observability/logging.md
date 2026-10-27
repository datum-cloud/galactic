# Logging

Every Galactic binary that runs controller-runtime (`galactic-router`,
`galactic-gateway`, `galactic-nat`, `galactic-vrf`, `galactic-controller`,
`galactic-edge`, `fabric-router-controller` and `fabric-api`) installs one
logger at startup through `internal/logging`. The same handler writes the
binary's own `slog` lines, the standard `log` package, controller-runtime
(reconciler errors, cache and leader election) and klog (client-go), so every
line has one format and one level threshold.

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
should run it on their rendered output:

```sh
kustomize build <overlay> | go run go.datum.net/galactic/hack/check-log-settings@<version> -
```

It recognizes a Galactic container by its image repository name, and checks
only literal values, not ones read from a ConfigMap or Secret.

Production runs the defaults: one JSON object per line on stderr, with
`time`, `level` and `msg` keys. controller-runtime's lines also carry a `logger` key naming the
component. Its verbose lines (`V(1)` and up) appear only at
`--log-level=debug`. klog keeps its own verbosity setting, which these flags
don't change, so client-go's `klog.V(n)` lines stay off.

For local runs, `--log-format=text --log-level=debug` gives readable output
with the verbose lines. No binary enables controller-runtime's zap development
mode: `internal/logging`'s `TestBinariesUseThisPackage` fails when a command
under `cmd/` imports controller-runtime's zap package or calls `SetLogger`
itself.

The CNI plugins, the `galactic-cni` installer and `fabric-config-agent` don't
run controller-runtime's logger and configure their logging separately; see
the [CNI environment variables](../cni/environment-variables.md) for the
plugins' log file.
