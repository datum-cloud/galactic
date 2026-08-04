# eBPF uSID Datapath Sequence Diagrams

Sequence diagrams for the eBPF/TC-BPF `uFMT 48+16` uSID datapath, covering the
`run` container's startup/load/attach path and the CNI ADD path's map
registration. This is the only forwarding path — there is no legacy
static-route fallback and no feature flag to disable it (removed in the
2026-08-02 direct cutover; see
[docs/cni/configuration.md](cni/configuration.md#ebpf-usid-datapath)).

See [docs/cni-cmd-sequence.md](cni-cmd-sequence.md) for the pre-existing
`cmdAdd`/`cmdDel` diagrams this one supplements, not replaces.

## `run` container startup — datapath load, attach, health, GC sweep

```mermaid
sequenceDiagram
    autonumber
    participant Main as cmd/galactic-cni (run)
    participant Installer as internal/installer.Run
    participant Attach as plumbing/ebpf/attach
    participant Preflight as plumbing/ebpf/preflight
    participant Kernel
    participant Metrics as plumbing/ebpf/metrics
    participant GC as internal/gc.SweepEBPFVRFTable
    participant K8s

    Main->>Installer: Run(ctx, grpcHealthPort, metricsPort)
    activate Installer
    Installer->>Installer: startEBPFDatapath(ctx, m)
    Installer->>Attach: SetHooks(m.Events.Hooks())
    Installer->>Attach: StartWatching(ctx, PinDir)
    activate Attach
    Attach->>Preflight: Check()
    activate Preflight
    Preflight->>Kernel: probe SCHED_CLS, HASH maps, BTF, fib_lookup+tbid
    Kernel-->>Preflight: capabilities present/absent
    Preflight-->>Attach: nil, or an actionable aggregated error
    deactivate Preflight
    alt preflight failed
        Attach-->>Installer: error
        Installer-->>Main: fatal error (container crashes, CrashLoopBackOff -- no fallback path exists)
    else preflight passed
        Attach->>Kernel: load compiled usid_ingress + pin maps under PinDir
        Attach->>Attach: ResolveInterfaces() (GALACTIC_CNI_EBPF_INTERFACES override or auto-detect default-route ifaces)
        Attach->>Kernel: Attach TC-BPF ingress filter to resolved interfaces
        Attach->>Attach: spawn Watch() goroutine (netlink link/route subscriptions)
        Attach-->>Installer: *prog.UsidObjects, ifaces, nil
    end
    deactivate Attach
    Installer->>Metrics: RegisterDatapathCollector(objs)
    Installer->>K8s: newK8sClientFn() (best-effort, for the GC sweep below)
    Installer->>Installer: loadHostConf(HostConflist) -> namespace, nodeName

    Installer->>Installer: serve /metrics (metricsPort), gRPC health (grpcHealthPort)
    Installer->>Installer: SetServingStatus("", SERVING) -- SetServingStatus("ebpf-datapath", SERVING)

    loop every ebpfHealthCheckInterval (10s)
        Installer->>Attach: Health(objs, ifaces)
        Attach->>Kernel: confirm TC filter still attached + program/maps still reachable
        Kernel-->>Attach: ok / error
        Attach-->>Installer: nil / error
        Installer->>Installer: SetServingStatus("ebpf-datapath", SERVING/NOT_SERVING)
    end

    loop every ebpfGCSweepInterval (5m)
        Installer->>GC: SweepEBPFVRFTable(ctx, k8sClient, namespace, nodeName, PinDir)
        activate GC
        GC->>Kernel: VRF.Generation() (cutoff, captured before listing CRDs)
        GC->>K8s: list BGPRouters (this node) + BGPVRFInstances
        GC->>GC: derive live (Block, Argument) set via uformat.Block + inst.Spec.VRFID directly
        GC->>Kernel: VRF.Reconcile(live, cutoff) -- deletes stale entries, keeps Generation>=cutoff
        GC-->>Installer: CleanupResult{EBPFVRFEntriesRemoved, Errors}
        deactivate GC
    end

    Note over Installer: ctx.Done() -> graceful shutdown -- deferred datapath.Close() releases this process's map/program fds (pinned maps persist for the next restart)
    deactivate Installer
```

## CNI ADD — eBPF `vrf_table` registration

```mermaid
sequenceDiagram
    autonumber
    participant Runtime
    participant CNI as internal/cni (cmdAdd)
    participant BGP as internal/cni/bgp.go
    participant USIDMap as plumbing/ebpf/usidmap
    participant PinnedMaps as pinned vrf_table/locator_table/function_table

    Runtime->>CNI: ADD
    activate CNI
    Note over CNI: VRF, veth/tap, IPAM as in docs/cni-cmd-sequence.md

    CNI->>BGP: publishBGPStateK8s(...)
    activate BGP
    BGP->>BGP: lookupBGPRouter() -> srv6Locator, nodeID
    BGP->>BGP: allocateArgument(ctx, k8s, namespace, routerName, vrfInstanceName) -> vrfID (12-bit Argument, local per-node allocation)
    BGP->>BGP: egressKindForInterfaceType(pluginConf.InterfaceType) -> EgressKindVeth | EgressKindTap
    BGP->>BGP: ComputeSID(srv6Locator, nodeID, vrfID, FunctionEndDT46) (for the router's independent BGP-advertised SID recomputation -- the CNI no longer installs a kernel route from it)

    BGP->>BGP: registerEBPFDatapath(bgp, vpc, vpcAttachment, ifaceType, vrfID, attach.PinDir)
    activate BGP
    alt BGPRouter not configured (no srv6Locator/nodeID)
        BGP-->>BGP: registered=false, nil (SRv6 intentionally not set up for this attachment)
    else configured
        BGP->>BGP: uformat.Block(netip.ParsePrefix(srv6Locator).Addr())
        BGP->>USIDMap: OpenPinnedRegistry(PinDir)
        USIDMap->>PinnedMaps: ebpf.LoadPinnedMap x3 (open, don't create)
        PinnedMaps-->>USIDMap: map handles
        USIDMap-->>BGP: Registry, closer
        BGP->>USIDMap: Locator.Register(block, nodeID)
        BGP->>USIDMap: Function.Register(block, FunctionEndDT46)
        BGP->>USIDMap: VRF.Register(block, vrfID, vrf.TableID(vpc, vpcAttachment), egressKind)
        USIDMap->>PinnedMaps: Put x3
        BGP->>USIDMap: closer.Close() (this process's own fd only -- pinned maps persist)
        BGP-->>BGP: registered=true, block, nil
    end
    deactivate BGP
    BGP->>BGP: on error, return it -- fatal to the ADD (no fallback path exists)
    Note over BGP: on registered=true, tracker.ebpfRegistered/ebpfBlock/ebpfArgument recorded for rollback (see below)
    deactivate BGP
    deactivate CNI
```

## Failed-ADD rollback — unregistering the eBPF entry

```mermaid
sequenceDiagram
    autonumber
    participant CNI as internal/cni (cmdAdd, failure path)
    participant Tracker as resourceTracker.cleanup
    participant BGP as internal/cni/bgp.go
    participant USIDMap as plumbing/ebpf/usidmap

    CNI->>Tracker: cleanup(ctx)
    activate Tracker
    Note over Tracker: reverse creation order
    alt tracker.ebpfRegistered
        Tracker->>BGP: unregisterEBPFDatapath(block, argument, attach.PinDir)
        BGP->>USIDMap: OpenPinnedRegistry(PinDir)
        BGP->>USIDMap: VRF.Unregister(block, argument)
        Note over BGP: idempotent -- not an error if already absent
    end
    Note over Tracker: veth/tap delete, VRF delete follow, as in docs/cni-cmd-sequence.md
    deactivate Tracker
```

Steady-state (non-failed-ADD) teardown of the `vrf_table` entry is
deliberately **not** part of `cmdDel` — matching this repo's existing
"DEL is intentionally minimal" design (`docs/agents/ARCHITECTURE.md`'s
Known Constraints) — it is instead the `run` container's periodic
`gc.SweepEBPFVRFTable` shown in the first diagram above.
