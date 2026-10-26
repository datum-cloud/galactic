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

| Alert                                 | Fires when                                                                                                                                   | For |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| `FabricAPIExecutionStalled`           | A gateway has executions in flight and finished none in 10 minutes                                                                           | 10m |
| `FabricAPINodeDiagnosticsUnavailable` | `fabric_api_node_diagnostics_available` is 0                                                                                                 | 15m |
| `FabricAPINodeUnreachable`            | More than half of at least 5 node calls in 30 minutes were `NodeUnreachable` or `Timeout`                                                    | 15m |
| `FabricAPIResultsOversized`           | 10 or more `ResponseTooLarge` outcomes on a node in an hour                                                                                  | 15m |
| `FabricAPICleanupBacklog`             | More than 50 stale `FabricQuery` objects                                                                                                     | 1h  |
| `FabricAPICertificateRenewalFailing`  | A loaded certificate has less than 4 hours left                                                                                              | 15m |
| `FabricAPICredentialsMissing`         | `fabric_api_credentials_loaded` is 0                                                                                                         | 15m |
| `FabricAPISearchIndexUnsynced`        | `fabric_api_node_search_index_synced` is 0 on a node whose index has held routes (a node with no `bmp targets fabric-api` block never fires) | 15m |
| `FabricAPIMetricsDown`                | A fabric-api target cannot be scraped                                                                                                        | 10m |

All are `severity: warning`, `service: galactic`, `team: connect`. On Datum's infra
the PodMonitors are scraped on each edge cluster but the rules are evaluated from
infra's copy; change the rules here, with their tests, then update infra's copy.

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
`fabric_api_certificate_expiry_timestamp_seconds` and
`fabric_api_credentials_loaded`.

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
and `fabric_api_credentials_loaded`. Request IDs and targets are never labels.

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

The deployment manifests do not set the [aggregate probe budget](configuration.md#aggregate-probe-budgets) flags yet. Turn them on in this
order, each step cell by cell:

1. **Nodes verify permits.** Give the `fabric-router` ServiceAccount `get` on
   the gateway's Lease and mount its token into the `fabric-api` container (the
   Component mounts it only into `frr-init` and `config-agent`):

   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: fabric-api-node-lease
     namespace: galactic-system
   rules:
     - apiGroups: ["coordination.k8s.io"]
       resources: ["leases"]
       resourceNames: ["fabric-api-gateway"]
       verbs: ["get"]
   ```

   Bind it to the `fabric-router` ServiceAccount and add `--probe-permits` to
   the sidecar's args. This changes the pod template, so it is a routing
   rollout: follow [Rollout](#rollout).
2. **The gateway enforces budgets.** Add `--aggregate-budgets` to the gateway.
   Expect operator and `FabricQuery` probes to be refused for 125 seconds after
   each gateway restart.
3. **Nodes require permits.** Until this step, probes operators send nodes
   directly are not charged, and the Looking Glass service must not be
   enabled. Add `--require-probe-permits` and
   `--gateway-address=fabric-api-gateway.galactic-system.svc:9346` (the gateway
   Service) to the sidecar, so direct operator probes are charged too. Another
   routing rollout.

Roll back in the reverse order. Removing `--aggregate-budgets` while nodes still
require permits refuses every gateway probe (`LimiterUnavailable`).

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
