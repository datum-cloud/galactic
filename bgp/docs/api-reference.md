# API Reference

> Last verified: 2026-03-16 against go.miloapis.com/bgp v1alpha1

All resources are in API group `bgp.miloapis.com`, version `v1alpha1`. All resources are cluster-scoped (no namespace).

---

## BGPConfiguration

**Short name:** `bgpconfig`

Declares the local BGP speaker identity. There should be exactly one `BGPConfiguration` per cluster named `default`. The controller reads this resource at startup and after any change to configure GoBGP's global parameters.

### Spec Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `asNumber` | `uint32` | required | AS number for this BGP speaker. Range: 1–4294967295. For iBGP all nodes share one AS; for eBGP each cluster has a unique AS. |
| `listenPort` | `int32` | `1790` | TCP port GoBGP listens on for incoming BGP sessions. Range: 1–65535. Port 1790 is used by convention (non-privileged). |
| `routerIDSource` | `string` | `NodeIP` | How the router ID is determined. `NodeIP` uses the node's IPv6 InternalIP. `Manual` requires `routerID` to be set explicitly. |
| `routerID` | `string` | — | BGP router ID in dotted-decimal IPv4 notation. Required when `routerIDSource` is `Manual`. |
| `addressFamilies` | `[]AddressFamily` | IPv6 Unicast | Address families the speaker activates. Defaults to IPv6 unicast if omitted. |

#### AddressFamily

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `afi` | `string` | required | Address Family Indicator. One of: `IPv4`, `IPv6`. |
| `safi` | `string` | `Unicast` | Subsequent Address Family Indicator. One of: `Unicast`, `Multicast`. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `observedASNumber` | `uint32` | AS number currently configured in GoBGP. |
| `observedRouterID` | `string` | Router ID currently configured in GoBGP. |
| `conditions` | `[]Condition` | Standard Kubernetes conditions. |

### Conditions

| Type | Meaning |
|------|---------|
| `SpeakerReady` | GoBGP is running and configured with this spec. |

### Verbs

`get`, `list`, `watch` (the controller reads this resource; update is via `kubectl apply`)

### Example

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPConfiguration
metadata:
  name: default
spec:
  asNumber: 65001
  listenPort: 1790
  routerIDSource: NodeIP
  addressFamilies:
    - afi: IPv6
      safi: Unicast
```

---

## BGPEndpoint

**Short name:** `bgpep`

Declares a BGP speaker endpoint — an address and AS number that other speakers can peer with. An endpoint is a self-advertisement: "I exist at this IPv6 address, with this AS number."

Endpoints are typically created by a node operator (one per node) but can also be created manually. `BGPPeeringPolicy` resources select endpoints via label selectors to automate session creation.

### Spec Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `address` | `string` | required | IPv6 address of this BGP speaker. Must be a valid IPv6 address. |
| `asNumber` | `uint32` | required | AS number this endpoint belongs to. Range: 1–4294967295. |
| `addressFamilies` | `[]AddressFamily` | IPv6 Unicast | Address families this endpoint supports. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]Condition` | Standard Kubernetes conditions. |

### Verbs

`get`, `list`, `watch`

### Example

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPEndpoint
metadata:
  name: node-worker-01
  labels:
    bgp.miloapis.com/role: node
    bgp.miloapis.com/cluster: cluster-a
    topology.kubernetes.io/zone: us-central1-a
spec:
  address: "2001:db8:1::1"
  asNumber: 65001
  addressFamilies:
    - afi: IPv6
      safi: Unicast
```

---

## BGPSession

**Short name:** `bgpsess`

Declares a BGP peering relationship between two `BGPEndpoint` resources. Sessions are typically created by the `PeeringPolicyReconciler` but can be created manually for custom topologies or debugging.

Each node's BGP controller reconciles all `BGPSession` resources where `spec.localEndpoint` names an endpoint on that node. It calls `AddPeer` or `UpdatePeer` on the local GoBGP instance.

### Spec Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `localEndpoint` | `string` | required | Name of the local `BGPEndpoint` resource. |
| `remoteEndpoint` | `string` | required | Name of the remote `BGPEndpoint` resource. |
| `holdTime` | `int32` | `90` | BGP hold time in seconds. Minimum: 3. |
| `keepaliveTime` | `int32` | `30` | BGP keepalive interval in seconds. Minimum: 1. |
| `routeReflector` | `RouteReflectorConfig` | — | When set, the local speaker treats the remote peer as a route reflector client. |
| `ebgpConfig` | `EBGPSessionConfig` | — | eBGP-specific parameters. Only meaningful when endpoints are in different AS numbers. |

#### RouteReflectorConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clusterID` | `string` | required | Route reflector cluster ID in dotted-decimal IPv4 notation. |

#### EBGPSessionConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `multiHop` | `EBGPMultiHop` | — | Enables eBGP multi-hop. Mutually exclusive with `ttlSecurity`. |
| `ttlSecurity` | `EBGPTTLSecurity` | — | Enables GTSM (Generalized TTL Security Mechanism). Mutually exclusive with `multiHop`. |

#### EBGPMultiHop

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ttl` | `uint32` | required | Maximum hop count permitted. Range: 1–255. |

#### EBGPTTLSecurity

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ttl` | `uint32` | required | Minimum expected TTL for incoming eBGP packets. Range: 1–255. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `sessionState` | `string` | Current BGP FSM state as reported by GoBGP. One of: `Unknown`, `Idle`, `Connect`, `Active`, `OpenSent`, `OpenConfirm`, `Established`. |
| `receivedPrefixes` | `int64` | Count of prefixes received from the remote peer. |
| `advertisedPrefixes` | `int64` | Count of prefixes advertised to the remote peer. |
| `lastTransitionTime` | `Time` | When the session state last changed. |
| `flapCount` | `int64` | Number of times this session transitioned from `Established` to a non-`Established` state. |
| `conditions` | `[]Condition` | Standard Kubernetes conditions. |

### Conditions

| Type | Meaning |
|------|---------|
| `SessionEstablished` | The BGP session is in `Established` state. |
| `Configured` | The session has been successfully added to GoBGP. |

### Verbs

`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`

### Example

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPSession
metadata:
  name: worker-01-to-worker-02
spec:
  localEndpoint: node-worker-01
  remoteEndpoint: node-worker-02
  holdTime: 90
  keepaliveTime: 30
```

eBGP session example with multi-hop:

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPSession
metadata:
  name: cluster-a-to-border-01
spec:
  localEndpoint: cluster-a-edge
  remoteEndpoint: border-01
  ebgpConfig:
    multiHop:
      ttl: 2
```

---

## BGPPeeringPolicy

**Short name:** `bgppp`

Automates `BGPSession` creation by selecting `BGPEndpoint` resources via label selectors and creating sessions based on the chosen topology mode.

The `PeeringPolicyReconciler` owns the `BGPSession` resources it creates. If a policy is deleted, its sessions are deleted. If the endpoint selector changes, sessions for endpoints that no longer match are removed and sessions for newly matched endpoints are created.

### Spec Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `selector` | `LabelSelector` | required | Selects `BGPEndpoint` resources to include in this policy. |
| `mode` | `string` | `mesh` | How selected endpoints are peered. `mesh` creates a session between every pair. `route-reflector` creates sessions between the reflector and each client. |
| `sessionTemplate` | `BGPSessionTemplate` | — | Default values for created `BGPSession` resources. |
| `routeReflectorConfig` | `PeeringPolicyRRConfig` | — | Route-reflector parameters. Required when `mode` is `route-reflector`. |

#### BGPSessionTemplate

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `holdTime` | `int32` | — | BGP hold time for created sessions. If omitted, the `BGPSession` default (90s) applies. |
| `keepaliveTime` | `int32` | — | BGP keepalive interval for created sessions. If omitted, the `BGPSession` default (30s) applies. |

#### PeeringPolicyRRConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `reflectorSelector` | `LabelSelector` | required | Selects exactly one `BGPEndpoint` to act as the route reflector. If the selector matches more than one endpoint, an `InvalidConfig` condition is set and no sessions are created. |
| `clusterID` | `string` | required | BGP route reflector cluster ID in dotted-decimal IPv4 notation assigned to all client sessions. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `matchedEndpoints` | `int32` | Number of `BGPEndpoint` resources matching the selector. |
| `activeSessions` | `int32` | Number of `BGPSession` resources created by this policy. |
| `conditions` | `[]Condition` | Standard Kubernetes conditions. |

### Conditions

| Type | Meaning |
|------|---------|
| `InvalidConfig` | The policy spec is invalid. Typical causes: `route-reflector` mode with a missing or ambiguous `reflectorSelector`. |

### Verbs

`get`, `list`, `watch`

### Example — Full Mesh

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPPeeringPolicy
metadata:
  name: cluster-mesh
spec:
  selector:
    matchLabels:
      bgp.miloapis.com/role: node
      bgp.miloapis.com/cluster: cluster-a
  mode: mesh
  sessionTemplate:
    holdTime: 90
    keepaliveTime: 30
```

### Example — Route Reflector

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPPeeringPolicy
metadata:
  name: cluster-rr
spec:
  selector:
    matchLabels:
      bgp.miloapis.com/cluster: cluster-a
  mode: route-reflector
  routeReflectorConfig:
    reflectorSelector:
      matchLabels:
        bgp.miloapis.com/role: route-reflector
        bgp.miloapis.com/cluster: cluster-a
    clusterID: "1.0.0.1"
  sessionTemplate:
    holdTime: 90
    keepaliveTime: 30
```

---

## BGPAdvertisement

**Short name:** `bgpadvert`

Declares one or more IPv6 prefixes the local speaker should inject into its GoBGP RIB. Once in the RIB, GoBGP advertises them to established peers according to configured route policies.

The `AdvertisementReconciler` calls GoBGP's `AddPath` API when a `BGPAdvertisement` is created or updated, and `DeletePath` when it is deleted.

> Note: `BGPAdvertisement` is a Phase 2 resource. The `peerSelector`, `communities`, and `localPref` fields are defined in the schema and accepted by the API server, but peer-scoped advertisement targeting requires the advertisement reconciler to act on them.

### Spec Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `prefixes` | `[]string` | required | IPv6 CIDR prefixes to advertise. Minimum one prefix. |
| `peerSelector` | `LabelSelector` | — | Selects which peers this advertisement targets. If empty, prefixes are advertised to all peers. |
| `communities` | `[]string` | — | BGP community values to attach. Format: `"AS:value"` (e.g. `"65001:100"`). |
| `localPref` | `uint32` | — | `LOCAL_PREF` attribute. Only meaningful for iBGP. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `advertisedPrefixCount` | `int32` | Number of prefixes currently in the GoBGP RIB from this resource. |
| `conditions` | `[]Condition` | Standard Kubernetes conditions. |

### Verbs

`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`

### Example

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPAdvertisement
metadata:
  name: cluster-a-srv6-prefix
spec:
  prefixes:
    - "2001:db8:ff00::/40"
  communities:
    - "65001:100"
  localPref: 100
```

Peer-targeted advertisement:

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPAdvertisement
metadata:
  name: cluster-a-to-border-only
spec:
  prefixes:
    - "2001:db8:ff00::/40"
  peerSelector:
    matchLabels:
      bgp.miloapis.com/role: border
```

---

## BGPRoutePolicy

**Short name:** `bgprp`

Declares import or export filtering rules applied to BGP sessions. Statements are evaluated in order; the first matching statement wins. The primary use case is suppressing more-specific prefixes when an aggregate covers them.

> Note: `BGPRoutePolicy` is a Phase 2 resource.

### Spec Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `string` | required | Direction this policy applies to. One of: `Import`, `Export`. |
| `peerSelector` | `LabelSelector` | — | Selects which peers this policy applies to. If empty, the policy applies to all peers. |
| `statements` | `[]PolicyStatement` | required | Ordered list of policy statements. Minimum one statement. |

#### PolicyStatement

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `prefixSet` | `[]PrefixMatch` | — | Prefixes to match. If empty, the statement matches all routes. |
| `action` | `string` | required | What to do when the statement matches. One of: `Accept`, `Reject`. |

#### PrefixMatch

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cidr` | `string` | required | The prefix to match, e.g. `"2001:db8:ff00::/40"`. |
| `maskLengthMin` | `uint32` | — | Match only prefixes with mask length greater than or equal to this value. |
| `maskLengthMax` | `uint32` | — | Match only prefixes with mask length less than or equal to this value. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]Condition` | Standard Kubernetes conditions. |

### Verbs

`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`

### Example — Suppress More-Specific Prefixes

This policy suppresses individual /48s when a /40 aggregate is advertised. The aggregate (`/40`) is accepted; specifics within it (`/41` through `/48`) are rejected.

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPRoutePolicy
metadata:
  name: suppress-specifics
spec:
  type: Export
  statements:
    - prefixSet:
        - cidr: "2001:db8:ff00::/40"
          maskLengthMin: 41
          maskLengthMax: 48
      action: Reject
    - action: Accept
```
