# Operate fabric-api

Use this guide after [deployment](deployment.md). Sidecar image changes recreate the fabric-router pod and restart FRR, so follow the routing rollout procedure below. Certificate rotation is described in [security](security.md).

## Observability

Scrape config and alert rules are in `config/monitoring/` (not part of
`config/kustomization.yaml`; they need the Prometheus Operator CRDs):

- The `fabric-router` PodMonitor's `api-metrics` endpoint scrapes the sidecar's
  port 9345 as `job="fabric-api-node"`, with a `node` label. A pod without the port
  yields no target.
- `podmonitor-fabric-api-gateway.yaml` scrapes the gateway's port 9347 as
  `job="fabric-api-gateway"`.
- The `fabric-api` group in `prometheusrule.yaml`, unit-tested by `task test:alerts`.
  None fires merely because nobody ran a query.

| Alert                                 | Fires when                                                                                                                                             | For |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --- |
| `FabricAPIExecutionStalled`           | A gateway has executions in flight and finished none in 10 minutes                                                                                     | 10m |
| `FabricAPINodeDiagnosticsUnavailable` | `fabric_api_node_diagnostics_available` is 0                                                                                                           | 15m |
| `FabricAPINodeUnreachable`            | More than half of at least 5 node calls in 30 minutes were `NodeUnreachable` or `Timeout`                                                              | 15m |
| `FabricAPIResultsOversized`           | 10 or more `ResponseTooLarge` outcomes on a node in an hour                                                                                            | 15m |
| `FabricAPICleanupBacklog`             | More than 50 stale `FabricQuery` objects                                                                                                               | 1h  |
| `FabricAPICertificateRenewalFailing`  | A loaded certificate has less than 4 hours left                                                                                                        | 15m |
| `FabricAPICredentialsMissing`         | `fabric_api_credentials_loaded` is 0                                                                                                                   | 15m |
| `FabricAPISearchIndexUnsynced`        | `fabric_api_node_search_index_synced` is 0 on a node whose index has held routes (a node with no `bmp targets fabric-api` block never fires)           | 15m |
| `FabricAPILimiterUnavailable`         | No gateway replica in a cell has had a ready aggregate limiter (`fabric_api_gateway_limiter_state{state="ready"}`), so every probe is refused          | 10m |
| `FabricAPIClockUnsynchronized`        | A gateway with `--aggregate-budgets` or a node with `--probe-permits` runs on a kernel clock not synchronised within 500 ms                            | 10m |
| `FabricAPIServiceThrottled`           | More than half of at least 20 Looking Glass requests in 30 minutes were refused `Throttled`, `QueueFull` or `LimiterUnavailable`                       | 15m |
| `FabricAPIServiceExecutionFailing`    | More than half of at least 10 executed Looking Glass requests in 30 minutes ended `ExecutionFailed`, `NoNodesAvailable`, `OwnershipLost` or `Internal` | 15m |
| `FabricAPIMetricsDown`                | A fabric-api target cannot be scraped                                                                                                                  | 10m |

All are `severity: warning`, `service: galactic`, `team: connect`. A deployment that
evaluates its own copy of the rules changes them here first, with their tests, then
updates that copy.

Node metrics (port 9345, a private registry with Go and process collectors):
`fabric_api_node_requests_total{type,outcome}`,
`fabric_api_node_request_duration_seconds{type}`,
`fabric_api_node_response_bytes{type}`,
`fabric_api_node_truncated_responses_total{type}`,
`fabric_api_node_in_flight_requests`,
`fabric_api_node_duplicate_requests_total`,
`fabric_api_node_duplicate_cache_entries`,
`fabric_api_node_diagnostics_available`,
`fabric_api_node_frr_info{version,supported}`,
`fabric_api_node_expensive_breaker_open`,
`fabric_api_node_probe_packets_total`,
`fabric_api_node_identity_refreshes_total{outcome}`,
`fabric_api_node_permits_total{outcome}` (`accepted`, or why a permit was
refused: `invalid`, `malformed`, `mismatch`, `expired`, `starting`, `clock`, `lease`,
`epoch`, `replayed`, `full`),
`fabric_api_certificate_expiry_timestamp_seconds` and
`fabric_api_credentials_loaded`. With `--probe-permits` the node also exports
`fabric_api_node_clock_synchronized`.

Gateway metrics (port 9347, on controller-runtime's registry, so its own metrics
appear too): `fabric_api_gateway_queries_total{type,reason}`,
`fabric_api_gateway_node_outcomes_total{outcome}`,
`fabric_api_gateway_node_rpc_duration_seconds{type,code}`,
`fabric_api_gateway_queue_depth`, `fabric_api_gateway_status_writes_total{kind,outcome}`,
`fabric_api_gateway_status_bytes`, `fabric_api_gateway_truncated_results_total`,
`fabric_api_gateway_stage_latency_seconds{stage}` (`receipt`, `execution`,
`completion`), `fabric_api_gateway_executions_in_flight`,
`fabric_api_gateway_queue_wait_seconds` (time a node RPC waited for a cell slot),
`fabric_api_gateway_stale_objects`, `fabric_api_certificate_expiry_timestamp_seconds`
and `fabric_api_credentials_loaded`. For the Looking Glass service:
`fabric_api_gateway_service_enabled`,
`fabric_api_gateway_service_requests_total{operation,reason}`,
`fabric_api_gateway_service_router_outcomes_total{operation,outcome}` and
`fabric_api_gateway_service_request_duration_seconds{operation}`. With
`--aggregate-budgets`: `fabric_api_gateway_admission_refusals_total{class,scope,reason}`,
`fabric_api_gateway_probe_packets_charged_total{class}`,
`fabric_api_gateway_limiter_state{state}`, `fabric_api_gateway_limiter_keys{kind}`,
`fabric_api_gateway_service_streams` and `fabric_api_gateway_clock_synchronized`.
Request, project and service IDs, node names and targets are never labels;
[Telemetry and diagnosis](#telemetry-and-diagnosis) walks them.

## Rollout

The `fabric-api` sidecar lives in the `fabric-router` pod, and `/run/frr` stays a
pod-scoped `emptyDir` so FRR's sockets are never exposed beyond the pod. The cost
is that changing the sidecar's tag, flags or the Component itself changes the
DaemonSet's pod template, and the rolling update recreates the whole pod, FRR
included. **A sidecar release is a routing rollout.**

1. **Do the prerequisites first**, outside the pods: cert-manager with its
   csi-driver on every fabric node, the Issuer, the cell ConfigMap and the CRD. Roll out the
   gateway and janitor first; they do not touch `fabric-router`.
2. **Canary one node.** Stage the change so only one node's pod is recreated
   first, however your delivery system stages a DaemonSet change (the per-node
   overlays used for `galactic-gateway` pin an instance to one node; the same idea
   applies). Do not let the first change reach every node at once.
3. **Check underlay sessions and convergence** on the canary: every `frr_bgp_peer_state`
   for the node back to Established for both families (frr-exporter on port 9342),
   no `FabricBGPSessionDown` or `FabricBGPPrefixesDropped`, and `fabric-router` Ready.
   Shallow daemon liveness is not a convergence gate. Then check the looking glass:
   `fabric_api_node_diagnostics_available` 1, `fabric_api_credentials_loaded` 1, and
   a direct `fabric-api query --info`.
4. **Pace the expansion**, one site or a small batch at a time, repeating step 3.
   Stop on any session loss.
5. **Roll back** by restoring the previous tag or removing the Component from the
   overlay; that is another rolling restart, so pace it the same way. Probe success
   is not evidence of routing health.

Keep the gateway's and the sidecar's tags in step. They are the same image, and
this repository does not test a gateway and sidecars at different versions. The
publish pipeline stamps one tag into both `config/fabric-api/base` and the
Component.

A failing sidecar must not gate any of this, and a certificate that cannot be issued
stalls only the `fabric-api-certs` pod. If a `fabric-api-certs` pod hangs in
`ContainerCreating`, the csi-driver is missing on that node or the Issuer cannot
issue; the node then shows `NoCertificatePod` to the gateway. A `fabric-router` pod
that hangs on `fabric-api-tls` should not occur, since that is a hostPath; check the
Component's patch. If the sidecar runs but reports diagnostics
unavailable, FRR and the underlay are unaffected; read `unavailableReason`.

### Enabling aggregate probe budgets

Opt-in Kustomize Components set the
[aggregate probe budget](configuration.md#aggregate-probe-budgets) flags. Turn them on in this order,
each step cell by cell:

1. **Nodes verify permits.** Add
   `config/fabric-router/components/fabric-api-permits` after
   `components/fabric-api` in the cell's `fabric-router` overlay. It adds
   `--probe-permits` to the sidecar, mounts the `fabric-router`
   ServiceAccount's token into it and grants `get` on the gateway's Lease
   alone (Role `fabric-api-node-lease`). This changes the pod template, so it
   is a routing rollout: follow [Rollout](#rollout).
2. **The gateway enforces budgets.** Add
   `config/fabric-api/components/aggregate-budgets` to the cell's gateway
   overlay. Expect operator and `FabricQuery` probes to be refused for 125
   seconds after each gateway restart.
3. **Nodes require permits.** Until this step, probes operators send nodes
   directly are not charged, and the Looking Glass service must not be
   enabled. Add `config/fabric-router/components/fabric-api-require-permits`
   after `components/fabric-api-permits`. It adds `--require-probe-permits`
   and `--gateway-address=fabric-api-gateway.galactic-system.svc:9346` (the
   gateway Service), so direct operator probes are charged too. Another
   routing rollout. It also issues each node's certificate for client auth
   as well as server auth, since the sidecar asks the gateway for those
   permits as a TLS client; that recreates the `fabric-api-certs` pods.
4. **The gateway serves the Looking Glass service, switched off.** Add
   `config/fabric-api/components/service` after
   `components/aggregate-budgets`. See
   [Operating the Looking Glass service](#operating-the-looking-glass-service)
   for turning it on.

Each Component that needs an earlier one fails the build without it, so an
overlay cannot list them out of order. Roll back in the reverse order.
Removing `--aggregate-budgets` while nodes still require permits refuses
every gateway probe (`LimiterUnavailable`).

## Operating the Looking Glass service

### Turning execution on and off

A gateway executes a Looking Glass request only when all of these hold:

- it runs with `--aggregate-budgets`;
- `--service-config-map` names a ConfigMap in its namespace whose key
  `service` is exactly `enabled`;
- the caller's service identity is in `--service-identities`.

`config/fabric-api/components/service` sets `--service-config-map` to
`fabric-api-service`, `--service-identities` to `looking-glass`, and creates
that ConfigMap with `service: disabled` and a Role that lets the gateway
`get` it and no other ConfigMap. Each replica reads it, uncached, every
second. A missing ConfigMap or key, `disabled`, a failed read and any other
value all mean off; the last two log a warning once. The gateway refuses to
start with `--service-config-map` but without `--aggregate-budgets`.

The ConfigMap carries `kustomize.toolkit.fluxcd.io/ssa: IfNotPresent`, so Flux
creates it once and never overwrites it: the value in the cluster is the
switch, and a reconcile never turns the service back on after an operator
stopped it. To manage it from Git instead, drop the annotation in the
overlay.

To stop new customer execution:

```sh
kubectl -n galactic-system patch configmap fabric-api-service --type merge \
  -p '{"data":{"service":"disabled"}}'
```

Each replica reads the change within a second, and from then on, without a
restart:

- a new `RunDiagnostic` is refused with `ServiceDisabled` (`FAILED_PRECONDITION`),
  and `GetCapabilities` reports `enabled: false`;
- every running request's queued and running routers are cancelled within 2
  seconds. Each such router's outcome is `Cancelled`, and the stream ends
  with `complete` reason `Cancelled` while its consumer is still reading. A
  request still in router discovery is refused with `ServiceDisabled`;
- nothing resumes when the service is turned back on. Request tokens and
  probe packets already charged stay charged, so the customer service starts
  any new attempt itself, with a new request ID.

Routing, operator `Query`/`ListNodes`, direct node probes, `FabricQuery`
execution and the limiter's buckets and election are untouched: turning the
switch never starts a recovery hold. Turn it back on with
`{"data":{"service":"enabled"}}`.

### Telemetry and diagnosis

The gateway logs one line per Looking Glass request the leader ran,
`Looking Glass request finished`, with the service name, project, request ID,
operation, reason, router counts (`routers`, `selected`, `successful`,
`failed`, `omitted`, `truncated`) and duration; a request refused before its
snapshot is logged at debug level only. No log line or metric label carries
a target, a result, node error text, or node or pod names, and no metric
label carries a project, request or service name.

To find out why requests fail:

1. `fabric_api_gateway_service_requests_total{operation,reason}` gives each
   request's end: a terminal coverage reason (`Succeeded`, `PartialResults`,
   `ExecutionFailed`, ...), the refusal's reason before the snapshot
   (`Throttled`, `QueueFull`, `ServiceDisabled`, `LimiterUnavailable`, ...),
   or `DeliveryFailed` when the stream broke. A follower counts only what it
   refused itself; the leader counts the rest, including forwarded requests
   it refused.
2. For throttling, `fabric_api_gateway_admission_refusals_total{class,scope,reason}`
   splits refusals by traffic class (`service`, `operator`, `fabricquery`)
   and limiter scope; see [Limits and capacity](configuration.md#limits-and-capacity).
3. For `LimiterUnavailable`, `fabric_api_gateway_limiter_state` shows whether
   the leader is `ready`, `recovering` or `unavailable`, and
   `fabric_api_gateway_clock_synchronized` whether its clock is trusted.
   `fabric_api_gateway_limiter_keys{kind}` near 4096 project or 16384
   destination keys means new keys are refused until old ones refill.
4. For failed routers, `fabric_api_gateway_service_router_outcomes_total{operation,outcome}`
   gives each router's failure or omission reason, and
   `fabric_api_node_permits_total{outcome}` on the node why it refused a
   permit.
5. A specific request's log line, found by its request ID, gives its counts.

### Upgrade and rollback

Roll out in the [Enabling](#enabling-aggregate-probe-budgets) order, then switch the service on only
after the cell's qualification. Every replica must run an image that knows
`--service-config-map` before `components/service` is applied; an older
image refuses to start on the unknown flag. A node without `--probe-permits`
never runs a probe for the gateway under `--aggregate-budgets` (its router
fails `QueryTypeUnavailable`), so mixed node versions reduce coverage, not
the budgets.

To roll back:

1. Switch the service off (above); running requests stop within 2 seconds.
2. Remove `components/service`. Its ConfigMap is pruned, which also reads as
   off.
3. Remove `components/fabric-api-require-permits`, a routing rollout. Direct
   operator probes are no longer charged.
4. Remove `components/aggregate-budgets`. Probes are no longer charged to
   the aggregate budgets.
5. Remove `components/fabric-api-permits`, a routing rollout.

Keep step 4 after step 3: nodes requiring permits refuse every probe while
no gateway issues them.

## Verifying

```sh
# Per node (lab): ASN, router ID, both address families' sessions, exact and
# longest-match lookups with zebra evidence, operator probes, then each gateway
# and a FabricQuery end to end.
cd deploy/containerlab && task verify:fabric-api

# Disruptive: break the Issuer, recreate one fabric-router pod, check FRR and the
# underlay come up with diagnostics unavailable, then repair the Issuer.
cd deploy/containerlab && task verify:fabric-api-bootstrap
```

Before switching the Looking Glass service on in a cell, qualify the build
with the [qualification suite](qualification.md).

In a real cell, read the same facts from the cluster:

```sh
kubectl -n galactic-system get pods -l app.kubernetes.io/name=fabric-router \
  -o custom-columns=NODE:.spec.nodeName,POD:.metadata.name,READY:.status.containerStatuses[*].ready
kubectl -n galactic-system logs deploy/fabric-api-gateway | grep -i "fabric query"
kubectl get fabricqueries -A      # short name: fq
```

## Troubleshooting

| Symptom                                             | Likely cause and where to look                                                                                                                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `fabric-api-certs` pod stuck in `ContainerCreating` | csi-driver not installed or not on this node, or the Issuer cannot issue. FRR is unaffected; the node reports no credentials and the gateway omits it as `NoCertificatePod`                |
| `unavailableReason` starts with `credentials:`      | Issuer missing or not ready, `certsync` has not copied files yet, or `CELL_NAME` in the `fabric-api-certs` volume is not the ConfigMap's `cell`; check the certs pod and the sidecar's log |
| `unavailableReason` is `FRRVersionUnsupported`      | FRR is not 10.7; ship a fabric-api that supports the new release before the `fabric-router` image                                                                                          |
| `unavailableReason` is `FRRUnavailable`             | `bgpd.vty`/`zebra.vty` not reachable: FRR restarting, or the container lacks group 102                                                                                                     |
| Sidecar logs "fabric-api node is not configured"    | `CELL` is empty: the ConfigMap or its `cell` key is missing. Fix it and recreate the pod                                                                                                   |
| Gateway pod `CreateContainerConfigError`            | The `fabric-api` ConfigMap or one of `site`, `cell`, `cluster-name` is missing                                                                                                             |
| `FabricQuery` stays untouched                       | `spec.site` or `spec.clusterName` does not equal this gateway's; or this replica is not the leader                                                                                         |
| `NodeUnreachable` for every node                    | Gateway cannot reach `hostIP:9344` (host firewall) or the TLS handshake fails; check identities and cell values                                                                            |
| `Unauthorized`                                      | The caller's role may not make this call: a node identity cannot call anything, and a gateway identity may call only the debug `Query`                                                     |
| `DestinationNotAllowed` on a ping                   | Public policy applied; a direct node call with an operator identity may carry `--operator-allow-prefixes` in the lab                                                                       |
| `ProbeSourceUnavailable`                            | No probe source for that family; see [Source](security.md#source)                                                                                                                          |
| `QueryTypeUnavailable`                              | Expensive types are gated, or the breaker is open after a timed-out scan                                                                                                                   |
| `NodeBusy`                                          | Node or cell budget full; expensive and probe budgets have no queue                                                                                                                        |
| `ResponseTooLarge`                                  | FRR's answer exceeded 4 MiB, or did not fit the node's budget even when shaped; see `FabricAPIResultsOversized`                                                                            |
| `DuplicateConflict`                                 | A request ID was reused with different arguments                                                                                                                                           |

For the typed codes carried in results, see [api.md](api.md#error-codes).
