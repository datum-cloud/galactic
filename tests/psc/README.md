# Private Service Connect qualification

This Linux fixture runs the production service route controller and TC dataplane
against a real edge API. Two consumer VPCs use the same client address, source
port, and service frontend. A shared producer returns its destination identity
and the request payload over UDP and TCP. No DNS service is required.

Build after generating the eBPF objects:

```sh
task build:ebpf
go build -o bin/psc-fixture ./tests/psc/fixture
go test -race ./tests/psc/internal/traffic
```

Run in a disposable privileged Linux environment with IPv6, `ip`,
bpffs, and an edge kubeconfig. Supply two existing consumer VPCs and attachments,
a shared producer attachment, and the service endpoints and policies from the
[example manifest](example.yaml). Apply the Cloud and Network CRDs first.
Fill the policy variables before applying the example:

```sh
export CONSUMER_A_UID=$(kubectl get vpc consumer-a -n psc-test -o jsonpath='{.metadata.uid}')
export CONSUMER_B_UID=$(kubectl get vpc consumer-b -n psc-test -o jsonpath='{.metadata.uid}')
export AUTHORIZATION_VALID_UNTIL=$(date -u -d '+90 seconds' +%Y-%m-%dT%H:%M:%SZ)
envsubst < tests/psc/example.yaml | kubectl apply -f -
```

The kubeconfig must allow the fixture to read those objects, update attachment
status and policy status, and watch routing dependencies.

## Local delivery

Save a configuration file:

```json
{
  "role": "local",
  "kubeconfig": "/runtime/edge.kubeconfig",
  "namespace": "psc-test",
  "nodeName": "node-a",
  "state": "/runtime/psc-state.json",
  "cases": [
    {
      "project": "a",
      "vpcName": "consumer-a",
      "vpcIdentity": "consumer-a",
      "consumerAttachment": "client-a",
      "producerAttachment": "producer",
      "destination": "fd70:100::10"
    },
    {
      "project": "b",
      "vpcName": "consumer-b",
      "vpcIdentity": "consumer-b",
      "consumerAttachment": "client-b",
      "producerAttachment": "producer",
      "destination": "fd70:100::11"
    }
  ]
}
```

Start `bin/psc-fixture --config /runtime/psc.json`. The state file identifies
consumer namespaces. Query each namespace using its expected producer address:

```sh
ip netns exec CONSUMER_A "$(pwd)/bin/psc-fixture" query \
  --transport udp --expected fd70:100::10 --payload request-a
ip netns exec CONSUMER_B "$(pwd)/bin/psc-fixture" query \
  --transport tcp --expected fd70:100::11 --payload request-b
```

The same binary supplies the service relays and consumer queries.
Use `--timeout 15s` for delayed reply checks.

A successful result identifies the expected producer and the frontend
`fd70:ffff::10`. A denied or expired request exits with status 3. Repeat both
transports from both VPCs using the same source port to check isolation.

## Remote delivery

Run a consumer and producer fixture in separate containers on one IPv6 network.
Use role `consumer` on node A and role `producer` on node B. Add `nodeID`,
`locator`, `routerName`, `peerAddress`, and `peerMAC` to each configuration:

```json
{
  "role": "consumer",
  "nodeName": "node-a",
  "nodeID": 256,
  "locator": "fd00:123:456::/48",
  "routerName": "psc-node-a",
  "peerAddress": "PEER_IPV6_ADDRESS",
  "peerMAC": "PEER_ETHERNET_MAC"
}
```

Use node ID 257 for the producer and reverse the peer details. Give each container
its own state file. The fixture creates routing inputs and maps for the real
SRv6 request and return paths. Its kubeconfig also needs permission to manage
BGPRouter and BGPVRFInstance objects. Inspect `/status` on each node to compare
kernel map IDs and rows with the node programming reports in the API.

## Failure checks

The local HTTP endpoint at `127.0.0.1:18081` supports `GET /status` and
`POST /pause`, `/resume`, `/restart`, `/reconcile`, and `/delay`.

- Pause the manager, wait beyond the policy authorization deadline, and verify
  that new UDP/TCP requests fail while producer listeners remain available.
- Send a delayed request, let authorization expire, and verify that its reply
  does not return to the consumer. `/delay` accepts `{"seconds":10}` and
  `/status` includes timestamps for request receipt and the reply attempt.
- Renew authorization and verify recovery without restarting the controller.
- Create conflicting frontend policies in either order, remove one, and verify
  that the remaining policy recovers.
- Delete and recreate an endpoint or consumer VPC and verify that stale grants
  and node reports do not authorize the replacement.

The fixture assists attachment status, Linux interfaces, VRFs, and routing maps.
It does not qualify normal CNI lifecycle, BGP convergence, federation, or regional
deployment. Unit and kernel regression tests accompany the implementation PRs;
this fixture provides an explicit environment for combined qualification.
