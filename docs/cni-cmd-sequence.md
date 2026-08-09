# CNI cmdAdd / cmdDel Sequence Diagrams

Per-binary sequence diagrams for the galactic CNI plugin chain's ADD and DEL
paths.

## Chain overview

The chain is one master plugin, plus up to two optional plugins invoked
after it in conflist order:

1. **Master** — `galactic-cni` (veth, for containers) or `galactic-tap-cni`
   (tap, for VM workloads: Kata, Firecracker, kraftlet/Unikraft). Creates
   the VRF and host-side interface, annotates the NAD, delegates IPAM (if
   an `"ipam"` block is present) and — for `galactic-cni` only —
   host-device (to move the guest veth into the container netns), then
   configures the host gateway address/route and prints the CNI result.
2. **`galactic-route`** (optional — present only when the attachment has
   `terminations`) — installs each termination as a route into the VRF
   table, then passes `prevResult` through unchanged.
3. **`galactic-bgp`** — publishes BGP/SRv6/eBPF state: `BGPVRFInstance`,
   `BGPAdvertisement`, and (when this node's `BGPRouter` has SRv6
   configured) the eBPF uSID datapath's `vrf_table` registration. Learns
   everything it needs (interface kind, allocated addresses) from
   `prevResult` alone — it never touches a kernel interface. Passes
   `prevResult` through unchanged as the final CNI result.

Every binary's own `cmdDel` is a no-op beyond binary-local, per-container
cleanup (IPAM deallocation, guest netns flush, host-device DEL — all
`galactic-cni`/`galactic-tap-cni` only). Shared node-level state (VRF,
host interface, routes, SRv6/eBPF registration, `BGPVRFInstance`,
`BGPAdvertisement`) is kept because it may still be in use by another
pod/VM on the same `(vpc, vpcAttachment)`; `galactic-router`'s GC
controller reclaims it once nothing references it anymore.

## cmdAdd — veth (galactic-cni → galactic-route → galactic-bgp)

```mermaid
sequenceDiagram
    autonumber
    Runtime->>CNI: ADD (stdin config, netns, IfName)
    activate CNI

    CNI->>CNI: parseConf()
    CNI->>CNI: resourceTracker{vpc, attachment}

    CNI->>VRF: Add(vpc, attachment)
    activate VRF
    VRF->>VRF: create VRF interface, assign table ID
    VRF-->>CNI: ok
    deactivate VRF

    CNI->>Veth: Add(vpc, attachment, mtu)
    activate Veth
    Veth->>Veth: create veth pair (host + guest)
    Veth->>Veth: enslave host to VRF
    Veth->>Veth: iptables FORWARD rules
    Veth->>Veth: LinkSetUp + sysctls
    Veth-->>CNI: ok
    deactivate Veth

    CNI->>K8s: newK8sClient()
    CNI->>K8s: AnnotateNAD(name, podNamespace, hostName)

    Note over CNI: host-device delegation
    CNI->>HostDevice: ADD (move guest veth to container netns)
    activate HostDevice
    HostDevice-->>CNI: ok
    deactivate HostDevice

    opt "ipam" block present
        CNI->>IPAM: ExecAdd(ipam.type, stdin)
        activate IPAM
        IPAM->>IPAM: allocate subnet/address (pool or static)
        IPAM-->>CNI: CNI IPAM result
        deactivate IPAM
        CNI->>NetNS: configureInterfaceInNetns(guest, subnet, gw)
        activate NetNS
        NetNS->>NetNS: AddrAdd(subnet), LinkSetUp, RouteAdd(default via gw)
        NetNS-->>CNI: ok
        deactivate NetNS
    end

    CNI->>CNI: readGuestInterface(MAC, MTU)
    CNI->>HostGW: ConfigureHostGateway(vpc, attachment, ipamResult, guestMAC)
    activate HostGW
    HostGW->>HostGW: AddrAdd(gateway) on host veth
    HostGW->>HostGW: RouteAdd(pod subnet) in VRF table
    HostGW->>HostGW: NeighSet(pod IP -> guest MAC), permanent
    HostGW-->>CNI: ok
    deactivate HostGW

    CNI->>CNI: buildResult() + PrintResult()
    CNI-->>Runtime: CNI result (JSON) — becomes next plugin's prevResult
    deactivate CNI

    opt attachment has terminations
        Runtime->>Route: ADD (stdin config, prevResult)
        activate Route
        Route->>Route: parseConf(); require prevResult
        loop terminations
            Route->>Route: route.Add(vpc, attachment, network, via, dev)
        end
        Route-->>Runtime: prevResult, unchanged
        deactivate Route
    end

    Runtime->>BGP: ADD (stdin config, prevResult)
    activate BGP
    BGP->>BGP: parseConf(); inferFromPrevResult(prevResult)
    Note over BGP: interface kind + IPAM result inferred from<br/>prevResult shape alone — no kernel access
    BGP->>K8s: newK8sClient()

    BGP->>BGP: publishBGPState() (retry loop)
    activate BGP
    BGP->>K8s: lookupBGPRouter(node)
    BGP->>K8s: allocateArgument() -> VRFID
    BGP->>K8s: CreateOrUpdate BGPVRFInstance
    BGP->>K8s: checkArgumentCollision()
    opt router has srv6Locator + nodeID
        BGP->>eBPF: registerEBPFDatapath(block, argument, vrfTableID, egressKind)
        activate eBPF
        eBPF->>eBPF: locator_table / function_table / vrf_table entries
        eBPF-->>BGP: ok
        deactivate eBPF
    end
    BGP->>K8s: CreateOrUpdate BGPAdvertisement(prefixes, annotations)
    deactivate BGP

    BGP-->>Runtime: prevResult, unchanged
    deactivate BGP

    Runtime-->>Runtime: CNI result (JSON)
```

## cmdAdd — tap (galactic-tap-cni → galactic-route → galactic-bgp)

```mermaid
sequenceDiagram
    autonumber
    Runtime->>CNI: ADD (stdin config, netns, IfName)
    activate CNI

    CNI->>CNI: parseConf()
    CNI->>CNI: resourceTracker{vpc, attachment}

    CNI->>VRF: Add(vpc, attachment)
    activate VRF
    VRF->>VRF: create VRF interface, assign table ID
    VRF-->>CNI: ok
    deactivate VRF

    CNI->>Tap: Add(vpc, attachment, mtu)
    activate Tap
    Tap->>Tap: create TAP interface
    Tap->>Tap: enslave to VRF
    Tap->>Tap: iptables FORWARD rules (IPv4 + IPv6)
    Tap->>Tap: LinkSetUp + tap sysctls
    Tap-->>CNI: ok
    deactivate Tap

    CNI->>K8s: newK8sClient()
    CNI->>K8s: AnnotateNAD(name, podNamespace, hostName)

    Note over CNI: tap branch — no host-device, no guest netns

    opt "ipam" block present
        CNI->>IPAM: ExecAdd(ipam.type, stdin)
        activate IPAM
        IPAM->>IPAM: allocate subnet/address (pool or static)
        IPAM-->>CNI: CNI IPAM result
        deactivate IPAM
    end

    CNI->>HostGW: ConfigureHostGateway(vpc, attachment, ipamResult, nil)
    activate HostGW
    HostGW->>HostGW: AddrAdd(gateway, /25 + NOPREFIXROUTE) on host tap
    HostGW->>HostGW: RouteAdd(pod subnet) in VRF table
    Note over HostGW: no guest MAC in tap mode — no neighbor entry installed
    HostGW-->>CNI: ok
    deactivate HostGW

    CNI->>CNI: buildTapResult(ipamResult) + PrintResult()
    CNI-->>Runtime: CNI result (JSON) — becomes next plugin's prevResult
    deactivate CNI

    opt attachment has terminations
        Runtime->>Route: ADD (stdin config, prevResult)
        activate Route
        Route->>Route: parseConf(); require prevResult
        loop terminations
            Route->>Route: route.Add(vpc, attachment, network, via, dev)
        end
        Route-->>Runtime: prevResult, unchanged
        deactivate Route
    end

    Runtime->>BGP: ADD (stdin config, prevResult)
    activate BGP
    BGP->>BGP: parseConf(); inferFromPrevResult(prevResult)
    Note over BGP: single interface, empty sandbox -> ifaceType = tap
    BGP->>K8s: newK8sClient()

    BGP->>BGP: publishBGPState() (retry loop)
    activate BGP
    BGP->>K8s: lookupBGPRouter(node)
    BGP->>K8s: allocateArgument() -> VRFID
    BGP->>K8s: CreateOrUpdate BGPVRFInstance
    BGP->>K8s: checkArgumentCollision()
    opt router has srv6Locator + nodeID
        BGP->>eBPF: registerEBPFDatapath(block, argument, vrfTableID, egressKind)
        activate eBPF
        eBPF->>eBPF: locator_table / function_table / vrf_table entries
        eBPF-->>BGP: ok
        deactivate eBPF
    end
    BGP->>K8s: CreateOrUpdate BGPAdvertisement(prefixes, annotations)
    deactivate BGP

    BGP-->>Runtime: prevResult, unchanged
    deactivate BGP

    Runtime-->>Runtime: CNI result (JSON)
```

## cmdDel — every binary in the chain

Per the CNI spec, DEL is idempotent — missing resources are never errors.
The runtime calls DEL on every chain entry that had a successful ADD, in
reverse order; every one of those calls is independently idempotent, so
the order doesn't matter for correctness.

```mermaid
sequenceDiagram
    autonumber
    Runtime->>CNI: DEL (stdin config, containerID)
    activate CNI

    CNI->>CNI: parseConf()
    alt parse fails
        CNI->>CNI: slog.Error, print empty result
        CNI-->>Runtime: nil
        deactivate CNI
    else parse succeeds
        alt "ipam" block present (galactic-cni/galactic-tap-cni only)
            CNI->>IPAM: ExecDel(ipam.type, stdin)
            activate IPAM
            IPAM->>IPAM: look up this containerID's own marker file, delete it
            IPAM-->>CNI: ok
            deactivate IPAM
        end

        Note over CNI: galactic-cni only: flush the guest netns'<br/>address/route, then forward DEL to host-device

        Note over CNI,BGP: Shared resources (VRF, host interface, routes,<br/>eBPF vrf_table entry, BGPAdvertisement, BGPVRFInstance) are<br/>NOT deleted by any binary's DEL — they may be in use by<br/>another pod/VM on the same (vpc, attachment).<br/>galactic-router's GC controller collects orphans periodically.

        CNI->>CNI: slog.Info("DEL: skipping shared resource cleanup (handled by GC)")
        CNI->>CNI: print empty result

        CNI-->>Runtime: nil
        deactivate CNI
    end
```
