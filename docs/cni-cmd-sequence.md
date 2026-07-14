# CNI cmdAdd / cmdDel Sequence Diagrams

Per-interface-type sequence diagrams for the galactic-cni ADD and DEL paths.

## cmdAdd — veth

```mermaid
sequenceDiagram
    autonumber
    Runtime->>CNI: ADD (stdin config, netns, IfName)
    activate CNI

    CNI->>CNI: parseConf()
    CNI->>CNI: resourceTracker{vpc, attachment, veth}

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

    loop terminations
        CNI->>Route: Add(vpc, attachment, network, via, dev)
        activate Route
        Route->>Route: netlink.RouteAdd in VRF table
        Route-->>CNI: ok
        deactivate Route
    end

    CNI->>CNI: buildVethResult()
    activate CNI

    Note over CNI: host-device delegation
    CNI->>HostDevice: ADD (move guest veth to container netns)
    activate HostDevice
    HostDevice-->>CNI: ok
    deactivate HostDevice

    CNI->>CNI: configureIPAM()
    CNI->>CNI: allocateIPAM() -> subnet + gateway
    CNI->>NetNS: configureInterfaceInNetns(guest, subnet, gw)
    activate NetNS
    NetNS->>NetNS: AddrAdd(subnet), LinkSetUp, RouteAdd(default via gw)
    NetNS-->>CNI: ok
    deactivate NetNS

    CNI->>CNI: readGuestInterface(MAC, MTU)
    CNI->>CNI: buildResult() + PrintResult()
    deactivate CNI

    CNI->>CNI: publishBGPState()
    activate CNI

    CNI->>CNI: configureHostGateway(vpc, attachment, ipamResult)
    CNI->>CNI: AddrAdd(gateway/128) on host veth
    CNI->>CNI: RouteAdd(subnet to host veth) in VRF table

    CNI->>CNI: decode VPC hex + VRFID
    CNI->>K8s: newK8sClient()

    CNI->>CNI: publishBGPStateK8s() (retry loop)
    activate CNI
    CNI->>K8s: lookupBGPRouter(node)
    CNI->>CNI: resolveSRv6SID(locator, nodeID, vrfID)
    CNI->>SRv6: RouteIngressAdd(sid, vpc, attachment)
    activate SRv6
    SRv6->>SRv6: seg6local End.DT46 route
    SRv6-->>CNI: ok
    deactivate SRv6
    CNI->>K8s: CreateOrUpdate BGPVRFInstance
    CNI->>K8s: CreateOrUpdate BGPAdvertisement(prefix, annotations)
    CNI-->>Runtime: ok
    deactivate CNI

    Runtime-->>Runtime: CNI result (JSON)
    deactivate CNI
```

## cmdAdd — tap

```mermaid
sequenceDiagram
    autonumber
    Runtime->>CNI: ADD (stdin config, netns, IfName)
    activate CNI

    CNI->>CNI: parseConf()
    CNI->>CNI: resourceTracker{vpc, attachment, tap}

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

    loop terminations
        CNI->>Route: Add(vpc, attachment, network, via, dev)
        activate Route
        Route->>Route: netlink.RouteAdd in VRF table
        Route-->>CNI: ok
        deactivate Route
    end

    Note over CNI: tap branch - no host-device, no guest netns

    CNI->>CNI: allocateIPAM() -> subnet + gateway
    CNI->>CNI: configureHostGateway(vpc, attachment, ipamResult)
    CNI->>CNI: AddrAdd(gateway/128) on host tap
    CNI->>CNI: RouteAdd(subnet to host tap) in VRF table

    CNI->>CNI: buildTapResult(ipamResult) + PrintResult()

    CNI->>CNI: decode VPC hex + VRFID
    CNI->>K8s: newK8sClient()

    CNI->>CNI: publishBGPStateK8s() (retry loop)
    activate CNI
    CNI->>K8s: lookupBGPRouter(node)
    CNI->>CNI: resolveSRv6SID(locator, nodeID, vrfID)
    CNI->>SRv6: RouteIngressAdd(sid, vpc, attachment)
    activate SRv6
    SRv6->>SRv6: seg6local End.DT46 route
    SRv6-->>CNI: ok
    deactivate SRv6
    CNI->>K8s: CreateOrUpdate BGPVRFInstance
    CNI->>K8s: CreateOrUpdate BGPAdvertisement(prefix, annotations)
    CNI-->>Runtime: ok
    deactivate CNI

    Runtime-->>Runtime: CNI result (JSON)
    deactivate CNI
```

## cmdDel — veth / tap (shared)

Both interface types share the same DEL path. Per the CNI spec, DEL is
idempotent — missing resources are never errors.

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
        alt hasIPAM
            CNI->>K8s: newK8sClient()
            alt k8s client OK
                CNI->>CNI: deallocateIPAM()
                CNI->>K8s: Get BGPAdvertisement -> read subnet annotation
                CNI->>IPAM: PoolAllocator.Deallocate(subnet)
            end
        end

        Note over CNI: Shared resources (VRF, interface, routes, SRv6,<br/>BGPAdvertisement, BGPVRFInstance) are NOT deleted here.<br/>They may be in use by another pod on the same (vpc, attachment).<br/>The GC controller collects orphans periodically.

        CNI->>CNI: slog.Info("DEL: skipping shared resource cleanup (handled by GC)")
        CNI->>CNI: print empty result

        CNI-->>Runtime: nil
        deactivate CNI
    end
```
