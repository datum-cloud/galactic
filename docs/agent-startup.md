# Router Startup Sequence

```mermaid
sequenceDiagram
    participant Router
    participant GoBGP
    participant Kubernetes

    Router->>Router: validate config (--node-name, --mode: transit/fabric/tenant, ...)
    Router->>Router: select RuntimeFactory: tenant→GoBGP, fabric→FRR stub, transit→error (unsupported)
    Router->>Kubernetes: build controller-runtime manager (metrics on :8080, no HTTP health)
    Router->>Router: start gRPC health server (:5000, SERVING immediately)
    Router->>Kubernetes: RBAC pre-flight — SelfSubjectAccessReview per watched resource (logs if watch denied)
    Router->>Kubernetes: register field indexes (BGPPeer×2, BGPPolicy, BGPAdvertisement, BGPVRFInstance, BGPRouter)
    Router->>Kubernetes: register controllers — BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance, BGPPolicy, Secret, Node, GC
    Router->>Kubernetes: start GC ticker goroutine (waits for cache sync, then runs on --gc-interval, default 5m)
    Router->>Kubernetes: start controller-runtime manager (watch BGPRouter/BGPPeer/BGPAdvertisement/BGPVRFInstance/BGPPolicy/Secret/Node)
    Note over Router: on each BGPRouter reconcile (not just the first)
    Router->>GoBGP: lazy-start embedded server (only for --mode=tenant; listenPort defaults to 179, or -1 for outbound-only deployments)
    Router->>GoBGP: StartBgp (ASN, RouterID from BGPRouter spec) — skipped if already started with the same values; Reconfigure (fresh BgpServer) if ASN/RouterID changed
    Router->>GoBGP: apply peers, VRFs (route targets + kernel VRF wiring), start RIB monitor, apply EVPN advertisements, apply policies
    Note over Router: on shutdown (SIGTERM/SIGINT): gRPC health server GracefulStop, manager exits when its signal context is cancelled. GoBGP has no explicit shutdown hook — it stops only because the process exits.
```

`--mode=fabric` uses an FRR runtime stub instead of GoBGP; `--mode=transit` is accepted by validation but returns an error at startup (not yet implemented). See [docs/router/configuration.md](router/configuration.md) for the full set of flags/environment variables.
