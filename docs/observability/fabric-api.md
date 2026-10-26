# Fabric looking glass — `fabric_api_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

The opt-in fabric-api exports `fabric_api_node_*` from each node sidecar
(9345) and `fabric_api_gateway_*` from each cell gateway (9347). Both
export `fabric_api_credentials_loaded` and
`fabric_api_certificate_expiry_timestamp_seconds` for their mTLS identity.
Its full metric list, with labels and meanings, lives with the rest of
its operator reference in
[fabric-api/configuration.md](../fabric-api/configuration.md).
