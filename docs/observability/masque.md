# MASQUE connector — `galactic_connectip_*` and `galactic_masque_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [the MASQUE service](../edge/masque-service.md#metrics).

`masque-provider` serves both families on `--health-listen`. `galactic_connectip_*` comes from the CONNECT-IP server (`internal/edge/connectip`) and covers each request and tunnel by transport. `galactic_masque_*` comes from the provider adapter (`internal/edge/masque`) and covers admission, route claims and whether admitted requests forward. The foundation's own view of the same attachments and routes is [`galactic_edge_foundation_*`](edge.md).

No label names a connector, principal, VPC, prefix, service, attachment or address. `transport` is `h3` (HTTP/3 over QUIC) or `h2` (HTTP/2 over TLS), and `http1` only for a request the server refuses as the wrong HTTP version. Every other label is one of the fixed values below. Find the request behind a series in the logs, as [the troubleshooting guide](../edge/troubleshooting.md#diagnose-a-masque-connector) shows.

## CONNECT-IP server

| Metric                                          | Type      | Labels                   | Meaning                                                                       |
| ----------------------------------------------- | --------- | ------------------------ | ----------------------------------------------------------------------------- |
| `galactic_connectip_requests_total`             | counter   | `transport`, `outcome`   | CONNECT-IP requests answered, by outcome                                      |
| `galactic_connectip_admission_duration_seconds` | histogram | `transport`              | Time spent waiting on the adapter's admission                                 |
| `galactic_connectip_connections`                | gauge     | `transport`              | Open QUIC (`h3`) or TCP (`h2`) connections                                    |
| `galactic_connectip_connections_rejected_total` | counter   | `transport`, `reason`    | Connections closed for exceeding a connection cap                             |
| `galactic_connectip_admissions`                 | gauge     | `transport`              | Requests waiting on admission                                                 |
| `galactic_connectip_tunnels`                    | gauge     | `transport`              | Accepted requests proxying packets                                            |
| `galactic_connectip_tunnel_ends_total`          | counter   | `transport`, `cause`     | Accepted requests that ended, by cause                                        |
| `galactic_connectip_packets_total`              | counter   | `transport`, `direction` | Packets forwarded, after the packet policy                                    |
| `galactic_connectip_bytes_total`                | counter   | `transport`, `direction` | Bytes of IP packets forwarded                                                 |
| `galactic_connectip_packets_denied_total`       | counter   | `direction`, `reason`    | Packets the [packet policy](../edge/masque-provider.md#packet-policy) refused |

- `outcome`: `accepted`; `bad_request` (not a CONNECT-IP request for this server); `unauthenticated` (401); `forbidden` (403); `limited` (a session or admission cap, 503); `unavailable` (server closing, or admission failed for another reason, 503); `invalid_grant`; `expired` (the admission ended before the tunnel opened); `mtu` (the path cannot carry 1280 bytes); `backend_unavailable` (the adapter would not open the packet path); `accept_failed`.
- Connection `reason`: `max_connections` or `max_connections_per_source`.
- `cause`, first match wins: `lease_ended` (expiry, revocation, replacement or the adapter stopping forwarding); `server_closed`; `path_mtu` (the path toward the client no longer carries 1280 bytes); `slow_client` (a write toward the client stayed blocked for 5 s); `backend_error` (the device failed a read or write); `setup_failed` (address assignment or route advertisement failed); `client_closed`.
- `direction`: `to_vpc` or `to_client`.

## Provider adapter

| Metric                               | Type    | Labels    | Meaning                                                                  |
| ------------------------------------ | ------- | --------- | ------------------------------------------------------------------------ |
| `galactic_masque_admissions_total`   | counter | `outcome` | Admissions, by outcome                                                   |
| `galactic_masque_requests`           | gauge   | `state`   | Open requests: `admitted`, `programmed` or `forwarding`                  |
| `galactic_masque_request_ends_total` | counter | `reason`  | Admitted requests that stopped forwarding, by reason                     |
| `galactic_masque_route_claims_total` | counter | `outcome` | Connector /96 route claims: `accepted`, `refused`, `failed` or `revoked` |
| `galactic_masque_device_drops_total` | counter | none      | Client packets dropped because the attachment's packet device was full   |
| `galactic_masque_lease_held`         | gauge   | none      | 1 while the provider instance holds a valid lease                        |
| `galactic_masque_lease_losses_total` | counter | none      | Times the instance lost its lease, which ends every request              |

- Admission `outcome`: `admitted`; `unauthenticated`, `forbidden` or `authorizer_failed` from the authority; `invalid_grant`; `no_lease`; `shutting_down`; `busy` (the connector already has a request being admitted); `attachment_failed` (core refused the attachment, or it was not programmed and served in time); `route_refused` (core refuses the /96 for good, such as a prefix conflict); `route_failed` (the claim was not accepted in time); `cancelled` (the client disconnected during admission); `replace_failed` (the connector's previous request did not stop); `changed` (the lease, attachment or route changed, or the connector was revoked, during admission).
- `state`: `forwarding` may carry a packet now. `programmed` has its attachment serving and its route claim accepted, but its packet path is not open, or its grant or lease ended. `admitted` is registered, but its attachment or route claim is no longer current.
- End `reason`: `closed` (the transport ended it); `grant_expired`, `grant_revoked`, `grant_changed`, `grant_invalid` (refresh results); `replaced` (a newer request of the same connector); `revoked` (`Adapter.Revoke`); `lease_lost`; `route_moved`, `route_released`, `route_revoked` (core no longer accepts the claim); `attachment_gone`, `attachment_draining`, `attachment_unprogrammed`, `attachment_closed`.
- Route claim `revoked` counts an accepted claim that core stopped accepting. `refused` and `failed` count claims that never were. `failed` excludes a claim cancelled because the client disconnected.

```promql
# Refused CONNECT-IP requests by transport and outcome
sum by (transport, outcome) (rate(galactic_connectip_requests_total{outcome!="accepted"}[5m]))

# Admitted requests that do not forward
sum by (state) (galactic_masque_requests{state!="forwarding"})

# Why requests stopped forwarding in the last hour
sum by (reason) (increase(galactic_masque_request_ends_total[1h]))

# Throughput per transport and direction, for capacity runs
sum by (transport, direction) (rate(galactic_connectip_bytes_total[1m]))
```
