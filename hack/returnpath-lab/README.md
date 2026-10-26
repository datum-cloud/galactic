# returnpath-lab

Phase 0 proof harness for
[docs/plans/855-return-path-ingress-decap.md](../../docs/plans/855-return-path-ingress-decap.md).

A lab tool, not a shipped binary. It performs by hand — and reverses — exactly
what that plan's Pieces 1–3 would automate, so the plan's derived-but-unproven
kernel assumptions can be tested before production code is written against
them. It calls the same packages the real implementation will
(`internal/plumbing/ebpf/usidmap`, `intf`, `uformat`, `egressroutemap`), so
what it proves is proven about the real code paths.

## Running it

Needs the host root netns, `hostPID`, `privileged` (setns wants
`CAP_SYS_ADMIN` on top of `NET_ADMIN`/`BPF`/`NET_RAW`), and the host's bpffs.
`galactic-system` enforces `privileged` pod security, so a pod there works:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/returnpath-lab ./hack/returnpath-lab
kubectl -n galactic-system apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: returnpath-lab, namespace: galactic-system}
spec:
  nodeName: NODE            # the node hosting the Envoy Gateway pod
  hostNetwork: true
  hostPID: true             # pod-netns discovery walks /proc
  restartPolicy: Never
  containers:
    - name: lab
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext: {privileged: true, runAsUser: 0}
      volumeMounts: [{name: bpf-fs, mountPath: /sys/fs/bpf}]
  volumes:
    - name: bpf-fs
      hostPath: {path: /sys/fs/bpf, type: Directory}
EOF
kubectl -n galactic-system cp /tmp/returnpath-lab returnpath-lab:/work/returnpath-lab
```

Invoke through `sh -c` — under a bare `kubectl exec ... -- binary sub -flags`
the flags do not reach the process:

```bash
kubectl -n galactic-system exec returnpath-lab -- sh -c "/work/returnpath-lab status $FLAGS"
```

## The facts it needs

| Flag | Where it comes from |
| ----------- | ------------------------------------------------------------------------------- |
| `-locator` | `kubectl -n galactic-system get bgprouter <node> -o jsonpath='{.spec.srv6Locator}'` |
| `-node-id` | the same object's `.spec.nodeID` |
| `-vpc` | the base62 VPC id — the first segment of an `EndpointSlice`'s `galactic.datum.net/tenant-id` |
| `-argument` | `.spec.vrfID` of `BGPVRFInstance` `<vpcHex>-<node>` |
| `-gw-addr` | the `/128` in the sidecar's own `BGPAdvertisement` (`<vpcHex>-<ingressHex>-<node>`) |

Note that `-argument` (the CRD's `VRFID`) is **not** the pod-netns Linux VRF
table id, and the two routinely differ. The advertised SID encodes the CRD
value, so that is what `vrf_table` must be keyed on.

## Subcommands

| | |
| -------------- | ---------------------------------------------------------------------------- |
| `status` | read-only: every piece of state the return path needs, and whether it exists |
| `up` | install it (needs `-yes`; without it, prints the plan only) |
| `down` | remove it (`-purge-locator` also removes the locator/function entries) |
| `probe` | open a VRF-bound TCP connection from inside the Envoy pod's netns, as #856 configures Envoy. **Refused counts as success** — a RST has to traverse the whole return path |
| `inject` | send a real SRv6-encapsulated packet at a node's return SID, isolating decap from whether any tenant workload replies |
| `egress-route` | look one `/128` up in `egress_route_table` — run on a *backend* node against the gateway address to see whether it imported the advertisement |
| `filters` | list an interface's tc filter chain in evaluation order |
| `verify-maps` | check that the bpffs-pinned maps are the same objects the attached program reads |

Always run `probe` before `up` for a baseline. `-purge-locator` on teardown is
not optional on a node that also runs `galactic-gateway`: the gateway's SRv6
address shares the node's Block and Node-ID with Function `0x0`, and
`usid_ingress` matches a locator entry on the top 64 bits alone, so a leftover
entry claims the gateway's address and drops its traffic as
`UNKNOWN_FUNCTION`.
