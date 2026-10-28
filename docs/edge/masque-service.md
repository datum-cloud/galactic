# MASQUE connector service

`cmd/masque-provider` is the CONNECT-IP service a MASQUE connector reaches. It serves CONNECT-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)) over HTTP/3 on UDP and runs as an unprivileged Galactic Edge provider. It forwards each admitted connector's packets into the connector's gVPC through the [provider adapter](masque-provider.md). The [grant authority](masque-authority.md) authorizes every request. The service accepts no credential of its own.

The service and the conformance fixture (`tests/edgeconformance/masqueprovider`) run the same code, `internal/edge/masque/service`. They differ only in where grants come from: the fixture can also use static test credentials.

Images:

- `ghcr.io/datum-cloud/masque-provider` (`containers/masque-provider/Dockerfile`)
- `ghcr.io/datum-cloud/masque-authority` (`containers/masque-authority/Dockerfile`)

`.github/workflows/publish.yaml` publishes both.

## Configuration

| Flag                      | Default                                   | Meaning                                                                               |
| ------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------- |
| `--provider`              | none, required                            | The `EdgeProvider` the pod runs as                                                    |
| `--authority`             | none, required                            | The `host[:port]` clients send as `:authority`; a request naming another one gets 400 |
| `--listen`                | `:8443`                                   | UDP address of the HTTP/3 server                                                      |
| `--health-listen`         | `:9188`                                   | TCP address of `/healthz`, `/readyz` and `/metrics`                                   |
| `--tls-cert`, `--tls-key` | `/etc/masque-provider/tls/tls.{crt,key}`  | Server certificate and key, reread when either file changes                           |
| `--grant-authority-url`   | none, required                            | `https://` base URL of `masque-authority serve`                                       |
| `--grant-authority-ca`    | `/etc/masque-provider/authority/ca.crt`   | PEM roots the authority's certificate must chain to, reread when the file changes     |
| `--grant-authority-token` | `/var/run/secrets/masque-authority/token` | Projected ServiceAccount token with audience `masque-authority`, reread on every call |
| `--log-level`             | `LOG_LEVEL`, then `info`                  | Log level                                                                             |

The pod also needs the downward-API variables `POD_NAMESPACE`, `POD_NAME`, `POD_UID` and `NODE_NAME`, the in-cluster API credentials of its ServiceAccount, and a TUN device from a device plugin. The [adapter's setup](masque-provider.md#setup) lists the cluster side.

The server applies the per-pod limits of the [MASQUE contract](../designs/masque/contract.md#resource-budgets-and-benchmark-contract) with these values:

| Limit                                | Value                  | Over the limit                             |
| ------------------------------------ | ---------------------- | ------------------------------------------ |
| Open QUIC connections                | 128                    | Connection closed with `H3_EXCESSIVE_LOAD` |
| Open QUIC connections per source IP  | 8                      | Connection closed with `H3_EXCESSIVE_LOAD` |
| QUIC handshake                       | 5 s                    | Connection dropped                         |
| Request streams per connection       | 2                      | QUIC refuses the stream                    |
| Request header section               | 8 KiB                  | Request refused                            |
| Requests in admission                | 16                     | 503                                        |
| Requests in admission per credential | 2                      | 503                                        |
| Authorization of one request         | 3 s                    | 503                                        |
| Admitted requests                    | 64                     | 503                                        |
| Queued packets toward one client     | 128 packets or 256 KiB | Packet dropped                             |

A connection counts toward its source IP once its QUIC handshake completes, so spoofed packets cannot use up another client's slots. The source-IP limit counts every client behind one NAT as one source.

## Startup and readiness

At start the service registers the pod's `EdgeInstance`, opens its UDP listener and starts renewing the instance's Lease. `/readyz` answers 200 only while the listener is open and the pod holds the Lease at a valid epoch. A pod without its Lease admits no request, so a readiness gate keeps it out of a Service's endpoints until then. `/healthz` answers 200 while the process runs.

A request is admitted only after the authority authorizes its credential and the adapter's attachment and route are ready ([readiness](masque-provider.md#readiness)). The first request of a connector on a pod can take several seconds while galactic-edge programs the attachment.

## Shutdown

SIGTERM or SIGINT starts shutdown:

1. `/readyz` fails and the UDP listener closes, which ends every session.
2. The adapter stops renewing, releases each route claim, deletes its attachments and releases the Lease ([drain and shutdown](masque-provider.md#drain-and-shutdown)).

Step 2 has 20 seconds, so give the pod a termination grace period of at least 30 seconds. A pod killed before it finishes leaves its routes to expire: galactic-edge closes their gates at the Lease deadline, and core reaps the pod's objects.

## Metrics

`/metrics` serves the instrumentation library's registry, including `galactic_connectip_packets_denied_total{direction, reason}` ([packet policy](masque-provider.md#packet-policy)).
