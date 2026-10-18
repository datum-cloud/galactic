# Generating fabric sessions from endpoint records

This is the design of `FabricEndpoint` and `FabricTopology`: how
`fabric-router-controller --topology` generates the `BGPPeer`s of a cell's
fabric routers instead of an operator writing both ends of every session. It
covers the model, what the generator owns and what it never touches, how a
session spans cells, when a removed session is released, how the controller
behaves when it cannot see another cell, and what is still missing before an
addressing service can write the records. Operating it is in
[operations.md](operations.md#generating-peers-from-a-topology).

## What is implemented and what is not

| Piece                                                                             | State                                                                                                                                                                                                                  |
| --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FabricEndpoint` and `FabricTopology` CRDs                                        | Implemented, `config/crd`. Admission tested, including every CEL rule within the cost budget                                                                                                                           |
| Generator (`internal/fabric/routing/topology`)                                    | Implemented: mesh, reflection and external relationships; family rule; conflicts; drain before release; endpoint status                                                                                                |
| `--topology` and its RBAC (`config/fabric-router-controller/components/topology`) | Implemented, off by default. The envtests run the generator as the shipped ServiceAccount with only the shipped RBAC                                                                                                   |
| Compiler, revisions, rollout                                                      | Unchanged. Generated peers are ordinary `BGPPeer`s                                                                                                                                                                     |
| Lab fixtures (`deploy/containerlab/resources/fabric-topology`)                    | Implemented. `TestLabParity` proves they generate every lab session and compile to what the imported peers compile to. No deploy script applies them                                                                   |
| An authoritative writer of endpoint records                                       | **Not implemented, and not available anywhere.** Until one exists, infra has to write the records from the same hostvars it renders `frr.conf` from; it writes none yet. See [the addressing gap](#the-addressing-gap) |
| Distribution of records between cells                                             | **External.** Infra's per-cell bundles must carry every cell's records into every cell of the routing domain                                                                                                           |

## Why

Today every managed session is written twice. Infra's hostvars list each
node's `bgpNeighbors`, and the two ends of one session are authored
separately, in different files, often in different cells: a reflector in one
cell lists every client of every cell it serves, and each client lists the
reflector. Adding a node means editing every router that peers with it;
adding a cell means editing every reflector. Nothing checks that the two ends
agree.

The topology turns that into one record per router per transport network and
a description of which records peer with which. Each cell generates its own
side from the same records, so the two ends agree by construction and adding
a node or a cell is adding its records.

## Model

### FabricEndpoint: where one router is reached on one transport

| Field               | Meaning                                                                                                                                            |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `routingDomain`     | The fabric. A topology reads only its own domain's records                                                                                         |
| `cell`              | The cell that runs the router. The `BGPRouter` exists only there                                                                                   |
| `routerRef`         | The `BGPRouter`'s name in its own cell                                                                                                             |
| `transport`         | The network the addresses are on, such as `private-mesh` or `public`. Two records peer only over a transport they share                            |
| `asn`               | The router's ASN: the remote ASN of every session toward the record. Checked against the `BGPRouter` in the owning cell                            |
| `addresses.ipv4/v6` | At most one per family. A session runs only in a family both ends carry                                                                            |
| `interface`         | Required with a link-local IPv6 address. Reserved: the generator does not yet peer over an interface and reports the record `InterfaceUnsupported` |
| `failureDomain`     | Recorded on every peer toward the record. Unset in the owning cell, it is read from the router's Node label the topology names                     |
| `source`            | `Manual`, or `AddressClaim` with an `ipv4ClaimRef`/`ipv6ClaimRef` per address, the same shape as `EgressShard`'s `AddressClaimRef`                 |

Routing domain, cell, router and transport are immutable: a router moving to
another transport is a new record and the removal of the old one, so the old
one's sessions drain like any other removal. Addresses are mutable, because a
renumbering is a change to the same session (the generated peer keeps its
name and changes its address, and the compiler and a release carry the
change), not a new one.

A claim reference is provenance only, as on `EgressShard`: nothing resolves
it. The addressing service is an aggregated API in a project control plane,
with no claim object in the cell.

Status, written by each cell for its own copy of the record: `local` (a
topology here generates for the record's cell), `Ready` (`Local`, `Remote`,
`RouterNotFound`, `ASNMismatch`, `InterfaceUnsupported`, or the conflict's
reason) and `Conflict` (`DuplicateEndpoint`, `AddressInUse`). A remote record
cannot be checked against a router, so `Remote` is as far as a cell can vouch
for it.

### FabricTopology: one cell's relationships

| Field                  | Meaning                                                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `routingDomain`        | The records it reads. Immutable                                                                                                 |
| `cell`                 | The cell it generates for. Records of this cell belong to routers that run here; every other record is remote. Immutable        |
| `members`              | The fabric-class `BGPRouter`s it generates on: a label selector, names, or both                                                 |
| `mesh[]`               | Every selected record peers with every other on each listed transport                                                           |
| `reflection[]`         | Every reflector record peers with every client record on each listed transport. Reflectors do not peer with each other here     |
| `external[]`           | Members selected by `routers` peer with explicit external `peers` (address and ASN): providers and transits that have no record |
| `failureDomainLabel`   | The Node label giving a local record without `failureDomain` its domain. Default `topology.kubernetes.io/zone`                  |
| `maxSessionsPerRouter` | A topology that would generate more on any member changes nothing and reports `Accepted` False. Default 64                      |
| `drain`                | Routers of this cell and records of any cell whose retained sessions may be released                                            |

Each relationship names its `transports` and `families` (`ipv4`, `ipv6`, the
IP family a session runs over), an `updateSource` (`EndpointAddress`, the
local record's address in the session's family, or `None`, for directly
connected links where the route chooses), and session settings for each side
it generates: a `peerProfileRef`, `transport` overrides and per-family
`familySettings` (import and export policy, next-hop mode, FRR local weight,
prefix limits, allow-AS-in). A reflection relationship has separate
`reflector` and `client` settings, and marks every family of a reflector's
peer as a route-reflector client; admission refuses `routeReflectorClient` in
any settings, because the relationship decides it. Without a profile a peer
activates the unicast family of its session's IP family and takes only that
family's settings; with one it activates the profile's families.

Selectors match `FabricEndpoint` labels, not `BGPRouter` labels: a remote
router has no `BGPRouter` in this cell, so a role such as "reflector" has to
be a property of the record every cell can see.

Status: `members`, `generated`, `conflicting`, `missingEndpoints`, `retained`,
and conditions `Accepted`, `ResolvedRefs`, `Conflicts` and `Ready`, each with
`observedGeneration`.

## What the generator writes

For each relationship, each local record (one whose cell is the topology's and
whose router is a member) gets one peer per remote record it pairs with, per
family both carry, on a transport both are on. Nothing is generated for the
other end: that end's cell generates it from the same records.

| Peer field      | Value                                                                                                                                                                               |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| name            | `<local router>-<remote record>-<ipv4\|ipv6>`, or `<local router>-<relationship>-<address>` for external peers; over 253 characters it is cut and suffixed with a hash of the whole |
| `routerRef`     | The local member                                                                                                                                                                    |
| `peerASN`       | The remote record's `asn`, or the external peer's                                                                                                                                   |
| `address`       | The remote record's address in the family, canonical form                                                                                                                           |
| `updateSource`  | The local record's address in the family, with `EndpointAddress`                                                                                                                    |
| owner reference | The topology, as controller                                                                                                                                                         |
| labels          | `app.kubernetes.io/managed-by: fabric-topology`, `galactic.datumapis.com/fabric-topology`, `galactic.datumapis.com/peer-cell`, `galactic.datumapis.com/peer-failure-domain`         |
| annotations     | The relationship (`mesh/NAME`, `reflection/NAME`, `external/NAME`), local and remote record names, the remote record's UID, the remote router                                       |

Names come from the records, never from a counter or the order things were
seen in, so the same records always give the same peers; a resync compares
spec, labels and annotations and writes nothing when they match.

A generated peer is never described in FRR (no `description`), so a topology
can replace imported or hand-authored peers without changing a single
rendered line. The lab parity test depends on that.

If two relationships generate the same router and address, the first keeps it
(mesh before reflection before external, then list order) and `Conflicts`
names the other.

## Ownership boundaries

| Owner                               | Owns                                                                                | The topology                                                                                                                                          |
| ----------------------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| The topology                        | Peers it created: controller reference to it and its labels                         | Creates, updates and deletes only these                                                                                                               |
| Operators and infra                 | Hand-authored and imported peers, `FabricEndpoint`s, `FabricTopology`s              | Never changes or deletes them. A hand-authored peer on the same router and address, or holding a generated name, blocks that session with `Conflicts` |
| Revision compiler                   | `FabricRouterRevision`s                                                             | Unchanged. Generated peers reach it like any other peer                                                                                               |
| Rollout manager and node agents     | `FabricRouterDeployment`s, releases, FRR                                            | Reads deployments for retirement only. Nothing it writes changes a node until a release promotes it                                                   |
| `galactic-controller --role=fabric` | `NetworkFabricIdentity`: one integer per tenant network, for route targets and VRFs | Unrelated: the topology concerns underlay sessions between routers, not per-network identity, and allocates nothing                                   |
| NSO                                 | Network attachments and tenant-facing networking                                    | Unrelated: no NSO object names a fabric session                                                                                                       |
| The addressing service              | Allocations                                                                         | Records a claim as provenance; never calls it                                                                                                         |

The controller's own RBAC (`config/fabric-router-controller/rbac.yaml`) still
only reads peers. Write access to `BGPPeer`s comes with the topology
component's `fabric-router-controller-topology` ClusterRole, and the code, not
RBAC, keeps it off peers it did not create: RBAC cannot select by owner.

## Across cells

Each cell holds every record of the routing domain, its own and every other
cell's, delivered by infra's per-cell bundle along with the rest of its
intent. Each cell's
topology generates its local side toward every relevant record, local or
remote. Because both cells compute from the same records, both ends of a
cross-cell session agree: one cell's reflector generates a peer toward
another cell's client record, and the client's cell generates the peer toward
the reflector record.

While the records differ between cells, for example while a new record has
reached one cell and not yet the other, one end exists and the other does
not. The session stays down until both exist; nothing else is affected, and
each end's change still needs a release to reach a node.

Router names need only be unique within a cell: a record is identified by
cell, router and transport, and peers are named after records, whose names
are unique in the namespace that holds every cell's records.

## Drain before release

A generated peer is the local side of a running session. When the topology
stops generating it, deleting it at once would withdraw a session from a
router that may still be carrying traffic over it. So the topology keeps it
(`retained`) until there is evidence that one of its ends is out of service:

| The session's end                    | Released when                                                                                                                                                                                               |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The local router                     | its `BGPRouter` is deleted; or its `FabricRouterDeployment`, for the same router UID, has `spec.recovery.retired` and `status.appliedEpoch` at or above `spec.activationEpoch`; or `drain.routers` names it |
| Either record it uses                | `drain.endpoints` names it                                                                                                                                                                                  |
| A router of this cell at the far end | the same as the local router                                                                                                                                                                                |
| A record of another cell             | the record is deleted (or deleted and recreated: the peer carries the UID it was generated from)                                                                                                            |
| An external peer                     | the topology no longer lists that address in that relationship                                                                                                                                              |

Anything else keeps the session: a member that left the selector, a record of
this cell deleted while its router still runs, a remote record that stays but
stops matching a selector or drops a family, a profile edit. Those are
retained until one of the rows above holds, and `retained` counts them.

The retirement signal is the one the rollout already has. `release create
--retire` promotes a router's last revision with `recovery.retired`, and admission then
refuses any later promotion of it. `appliedEpoch` reaching that epoch means the
node agent committed that last revision, which usually withdraws everything,
so the sessions toward it carry nothing. A retirement that was promoted but
not committed keeps the sessions; a node that will never report (it is dead)
is drained with `drain.routers`.

A router of another cell has no deployment here, so its retirement cannot be
observed; the record's deletion is that cell's statement. The writer of the
records is responsible for deleting a router's records only after retiring
it.

Releasing a peer deletes the `BGPPeer`. That only produces a new candidate
revision: the session leaves a node's FRR when a release promotes that
revision, so the order in which the two ends leave is still the operator's.

Entries in `spec.drain` stay until an operator removes them. The topology
never clears one, since only an operator knows when a drained router or
record is gone for good; an entry naming something that no longer exists
does nothing.

### Deleting a topology

Deleting a topology drops no session. It carries the finalizer
`galactic.datumapis.com/fabric-topology`, added on its first reconcile, so
it stays until the controller has handed every peer it controls to manual
control: each peer, listed from the API server rather than the cache, keeps
its spec and loses the topology's controller reference and the
`app.kubernetes.io/managed-by` and `galactic.datumapis.com/fabric-topology`
labels, and gains the annotation
`galactic.datumapis.com/released-from-fabric-topology` naming the topology.
The other labels and annotations stay as provenance. The peers are then
ordinary hand-authored peers: the garbage collector has no owner to collect
them for, and every router keeps compiling the same sessions. The controller
then removes the finalizer.

A topology created again, even with the same name, does not adopt them: it
reports each as a conflict and generates nothing in its place. Adopting a
session is the same as the [migration from imported
peers](operations.md#moving-from-hand-authored-or-imported-peers): delete the
hand-authored peer, outside a release, and the topology generates its own.

Delete a topology with the default (background) cascade. `--cascade=foreground`
makes the garbage collector delete the topology's dependents while the
topology waits on its finalizers, racing the hand-off, and can delete peers
before the controller releases them.

## Partition

The controller acts only on API state in its own cell. Records of other cells
are local copies, so a cell that has lost contact with another still holds
that cell's records as they were and keeps generating toward them. Nothing in
the controller treats silence as removal.

Deletion is observable without a finalizer. A generated peer exists only
because a record existed when it was generated, and carries the record's
name and UID; if the peer exists and the record does not, or has another
UID, the record was deleted. A record that never reached the cell was never
generated toward, so it cannot be mistaken for a deleted one. The records
carry no finalizer: infra writes them through GitOps, and a finalizer held by
a controller that is off or partitioned would hang every prune, while the
peer already remembers everything its release needs.

## No readiness cycle

Generated peers do not wait for any router, deployment or session to be
ready. The chain is one way: topology and records → peers → compiler →
revisions → rollout → node agent. Agent health feeds the rollout (whether a
promotion commits) and, through retirement, the release of a retained
session, but never whether a peer is generated. A router whose agent is down
still has its peers generated and compiled; it just runs nothing new until a
release reaches it. So there is no cycle where a session waits on the health
of a router that needs that session to become healthy. The only input from
the rollout is a committed retirement, which can only remove sessions.

## Conflicts

| Conflict                                                          | Outcome                                                                                                                          |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Two records for one router on one transport                       | The older keeps it (creation time, then name); the newer is `Conflict` `DuplicateEndpoint`, `Ready` False, and generates nothing |
| Two records holding one address on one transport of a domain      | The older keeps it; the newer is `AddressInUse`                                                                                  |
| A peer the topology did not create on the same router and address | That session is not generated; `Conflicts` True names it; the peer is not touched                                                |
| A peer the topology did not create holding a generated name       | The same                                                                                                                         |
| A retained generated peer holding the address a new session wants | The new session waits until the retained one is released                                                                         |
| Two relationships generating one router and address               | The first keeps it                                                                                                               |
| A missing profile or policy                                       | `ResolvedRefs` False; the topology writes nothing until it exists                                                                |
| More than `maxSessionsPerRouter` on a member                      | `Accepted` False; the topology writes nothing                                                                                    |

Older wins, as for router IDs in the compiler, so a newcomer never takes a
session away from a record already in use. Where the topology writes nothing,
it also deletes nothing: the peers already generated stay as they are.

## Decisions and tradeoffs

- **Records, not allocations.** An endpoint states an address; it does not
  ask for one. That keeps the generator independent of whether a person or an
  addressing service wrote the record, and keeps addressing credentials out
  of every cell.
- **Transport per relationship, as a list.** Production has two shared
  transports (the private mesh within a cell, the public network between
  cells). The lab has a point-to-point link per pair of nodes, which is a
  transport per link; a relationship lists them, and two records peer only
  over a transport they share, so a hub peers only with the router on the
  other end of its own link.
- **Selectors on records.** Remote routers are only records, so roles live
  on records. A router's role therefore appears once per record, which the
  record writer keeps consistent.
- **The cell is on the topology, not a flag.** A cell's records and its
  topology are authored together; a flag would be one more per-cell value to
  get wrong. A namespace may hold topologies for more than one cell, and each
  generates only for its own.
- **No adoption.** A topology never takes over a peer it did not create, so
  moving from imported peers to generated ones is explicit: delete the
  imported peers, and the generated ones appear (see operations). The
  revision built in between is never promoted unless someone releases it.
- **Peers are not described.** A `description` would render a line and
  break parity with the configurations being replaced.
- **Release needs evidence.** Retaining on anything short of deletion,
  retirement or an explicit drain costs a stale session now and then; deleting
  on a selector mistake would withdraw a live one. The `retained` count makes
  the former visible.
- **No finalizers on records,** for the reason in [Partition](#partition).
- **Topology deletion hands peers to manual control.** Releasing them would
  need the drain rules applied to the whole set at once, and deleting them
  would withdraw every session on the next release. Keeping them as
  hand-authored peers changes nothing on any router, and makes adoption by a
  later topology an explicit, per-peer operator step rather than a silent one.
- **Drain entries belong to the operator.** The controller cannot tell a
  drained router that is gone for good from one coming back, so it never
  removes an entry.
- **Records are distributed by infra's per-cell bundles.** Each cell's bundle
  carries every record of the routing domain; no cluster component copies
  them between cells. A fleet controller doing so is possible later.
- **A bounded session count.** The plan rules out an unbounded fleet-wide
  full mesh; `maxSessionsPerRouter` makes a selector that matches too much a
  refusal rather than a fleet change.

## The addressing gap

What is missing is **an authoritative source of endpoint records**. Today:

- Router IDs, loopbacks, private mesh and transit addresses and peer ASNs
  live only in infra's hand-written hostvars, where `bgpNeighbors` are
  authored at both ends.
- NetBox holds the same inventory and is checked against the hostvars, but
  nothing reads it, and it is not consumable from inside a cell.
- `NetworkFabricIdentity` is a per-network integer for route targets and VRFs,
  allocated centrally by `galactic-controller --role=fabric`. It is not an
  address and must not be duplicated for routers.
- `EgressShard`'s `AddressClaimRef` is a write-once provenance record; nothing
  resolves it.
- `go.miloapis.com/ipam` is used only for per-network identity.

So the records, when infra starts writing them, come from its hostvars, with
`source.type: Manual`. This milestone adds no addressing client and no in-cluster stand-in
for one.

An addressing-backed writer would have to provide:

1. One allocation per router per transport, from the transport's pool, in
   each family the transport carries, named after the router and transport so
   a restarted writer finds its own claim rather than making a second.
2. The router's ASN, cell and failure domain, from inventory.
3. `source.type: AddressClaim` with the claim of each address, set in the
   same write as the address.
4. Uniqueness within each transport of a routing domain. The records'
   older-wins conflict rule is a backstop, not a substitute.
5. Delivery of every record to every cell of the routing domain, and deletion
   from every cell.
6. Release of an allocation only after the router's sessions are released:
   the record is deleted after the router's deployment committed its
   retirement, and the claim is released after every cell has deleted its
   copy of the record. Reusing an address before then would point another
   router's sessions at a router still running.
7. Credentials that stay off fabric nodes and out of cells that only consume
   records.

## The lab

`deploy/containerlab/resources/fabric-topology/<site>/` holds each lab
cluster's records and topology. Every lab session is managed at both ends
except the transit sessions:

- each edge node reflects for the compute node at the other end of its link,
  with `next-hop-self force` on its side and `allowas-in 1` on the compute
  node's;
- `iad-worker3` (the EVPN route reflector's node) is a client of
  `iad-worker2` like a compute node, with its own `set-src` import policy on
  IPv6, so it is a second reflection relationship;
- each edge node's transit router is an external peer.

`TestLabParity` imports every lab `frr.conf`, generates peers from the
fixtures, and checks that each router compiles to the same configuration with
the generated peers as with the imported ones. Every construct the lab uses
can be generated. The fixtures are not applied by any lab task: applying them
next to the imported peers reports every session as a conflict until the
imported peers are deleted, which is the migration in
[operations.md](operations.md#generating-peers-from-a-topology).

## Not yet done

- An addressing-backed record writer, and record distribution between cells
  (above).
- Sessions over an interface or a link-local address.
- Authentication on generated sessions: `familySettings` and profiles carry
  none, and a per-session secret has no place in a shared relationship yet.
- Records carrying more than sessions need, such as the router ID or
  loopback, so the same records could later describe other per-router
  facts. Not planned now.
- Fleet metrics and alerts for topologies (`retained` and `conflicting` are
  in status only).
- Failure-domain policy: domains are recorded on every peer, but no
  relationship yet requires, for example, reflectors in two domains per
  client.
