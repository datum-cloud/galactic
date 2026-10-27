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

An explicit flag wins over the environment variable. Production runs the
defaults: one JSON object per line on stderr, with `time`, `level` and `msg`
keys. controller-runtime's lines also carry a `logger` key naming the
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
