# Logging

Every long-running Galactic binary (`galactic-router`, `galactic-gateway`,
`galactic-nat`, `galactic-vrf`, `galactic-controller`, `galactic-edge`,
`galactic-cni`, `fabric-router-controller`, `fabric-api` and
`fabric-config-agent`) installs one logger at startup through
`internal/logging`, which builds it with the shared Milo instrumentation
library ([`go.miloapis.com/instrumentation/logging`](https://github.com/milo-os/instrumentation)).
The same logger writes the binary's own `slog` lines, the standard `log`
package, controller-runtime (reconciler errors, cache and leader election),
klog (client-go) and the embedded GoBGP server in `galactic-router`, so every
line has one format and one level threshold. For `galactic-cni` that covers
the `install-cni` init container and the `credential-refresh` daemon; for
`fabric-config-agent`, the `frr-init` init container and the `config-agent`
sidecar.

| Flag                     | Env         | Default | Meaning                                         |
| ------------------------ | ----------- | ------- | ----------------------------------------------- |
| `--log-level`            | `LOG_LEVEL` | `info`  | `debug`, `info`, `warn` or `error`              |
| `--zap-devel`            |             | off     | Console output for local runs                   |
| `--zap-log-level`        |             |         | zap's level; overrides `--log-level` when given |
| `--zap-encoder`          |             | `json`  | `json` or `console`                             |
| `--zap-stacktrace-level` |             | `error` | Lowest level that carries a stack trace         |
| `--zap-time-encoding`    |             | RFC3339 | zap's time encoding                             |

The `--zap-*` flags are controller-runtime's standard zap flags, the same in
every Milo service. An explicit `--log-level` wins over `LOG_LEVEL`.
`--log-level` also accepts what Go's `slog` parses beyond the four names: any
case, and an offset such as `info+2`.

An unsupported value stops the binary at startup, before it does anything
else, whether it comes from the flag or the environment variable. A DaemonSet
with one crash-loops on every node. `task test:manifests`, which CI runs,
renders every kustomization under `config/` and `deploy/` and fails on an
unsupported level for a container running one of these binaries. It also fails
on `--zap-devel`, which is for local runs only, and on the removed
`--log-format` flag and `LOG_FORMAT` variable. `hack/check-log-settings`
applies the same rules (`internal/logging`'s `ValidateLevel`) to any YAML, so
downstream manifests should run it on their rendered output, with a Galactic
release that includes it:

```sh
kustomize build <overlay> | go run go.datum.net/galactic/hack/check-log-settings@<version> -
```

It recognizes a Galactic container by its image repository name, or by a
command that runs one of these binaries: `fabric-config-agent` ships in the
`fabric-router` image, run directly by `config-agent` and from a shell script
by `frr-init`. It checks only literal values, not ones read from a ConfigMap or
Secret. An empty `LOG_LEVEL` counts as unset. In source YAML that isn't
rendered, such as the containerlab overlays, it reads strategic-merge patches
but not JSON 6902 patches.

## Output

Production runs the defaults: one JSON object per line on stderr. Every line
has these keys:

| Key                       | Value                                                        |
| ------------------------- | ------------------------------------------------------------ |
| `ts`                      | RFC 3339 timestamp in UTC, to the nanosecond                 |
| `level`                   | `debug`, `info`, `warn` or `error`                           |
| `msg`                     | The message                                                  |
| `build_version`           | The binary's release tag, from `internal/metadata.Version`   |
| `instrumentation_version` | The instrumentation library's version linked into the binary |

Lines may also carry `logger` (the component, such as controller-runtime's
`controller-runtime.client.config` or `gobgp`), `caller` (file and line of a
`slog` call), `error`, and `stacktrace` on `error` lines. controller-runtime's
verbose lines (`V(1)` and up) and `slog.Debug` lines appear only at
`--log-level=debug`, with level `debug`. klog keeps its own verbosity setting,
which these flags don't change, so client-go's `klog.V(n)` lines stay off.

Galactic's own log keys avoid the names the collection pipeline reserves for
its labels, such as `node`, `namespace`, `pod` and `service`. A Kubernetes
object a line is about is `resource_name` and `resource_namespace`; other
values use specific names such as `nodeName` or `podNamespace`.
controller-runtime's reconciler lines still carry its own `namespace` and
`name` keys.

A binary that fails after reading its flags logs the error as one `error`
line through the same logger, then exits 1. A bad flag or an invalid
`--log-level` fails before the logger exists, so that one line is Go's default
text.

For local runs, `--zap-devel --log-level=debug` gives console output with the
verbose lines. No binary turns on development mode itself:
`internal/logging`'s `TestLoggerAdopted` runs the instrumentation library's
logger check over the whole module, which fails on any logger not built by the
library and on development mode turned on in source.
`TestBinariesUseThisPackage` fails when a command under `cmd/` imports
controller-runtime's zap package or calls `SetLogger` itself, and
`TestLongRunningBinariesInstallTheHandler` fails when a command under `cmd/`
doesn't import `internal/logging` at all.

Two kinds of command are exempt. The CNI plugins (`galactic-veth`,
`galactic-tap`, `galactic-ipam`, `galactic-bgp` and `galactic-route`) run once
per CNI call and write the same JSON lines to their own log file, through
`internal/logging.SetupFile`; see the
[CNI environment variables](../cni/environment-variables.md).
`galactic-usid` is a one-shot codec command in the debug image.

## Changes from the slog format

Releases before the instrumentation library wrote lines with Go's `slog` JSON
handler. Queries that read log fields need these changes:

| Before                                   | Now                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------- |
| `time`, local time zone                  | `ts`, UTC                                                           |
| `level` `DEBUG`, `INFO`, `WARN`, `ERROR` | `level` `debug`, `info`, `warn`, `error`                            |
| controller-runtime `err`                 | `error`                                                             |
| controller-runtime `logger` with `/`     | `logger` with `.`, such as `controller-runtime.webhook`             |
| no version                               | `build_version` and `instrumentation_version`                       |
| no source location or stack trace        | `caller` on `slog` lines, `stacktrace` on `error` lines             |
| `node`                                   | `nodeName`                                                          |
| `namespace`                              | `resource_namespace`, or `podNamespace` for a pod's                 |
| `name` beside `namespace`                | `resource_name`                                                     |
| `pod`                                    | `podRef` or `podName`                                               |
| `service`                                | `serviceName`, `serviceUID`, or `caller` for a Looking Glass caller |
| `endpoint`                               | `serviceEndpoint`                                                   |
| `instance`                               | `instanceName`                                                      |
| `cluster`                                | `clusterName`                                                       |
| `--log-format`, `LOG_FORMAT`             | removed; `--zap-devel` for local console output                     |
| GoBGP lines discarded                    | GoBGP lines at the binary's level, logger `gobgp`                   |
