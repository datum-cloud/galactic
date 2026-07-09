# CNI Plugin Sequence

```mermaid
sequenceDiagram
    participant Multus as Kubernetes / Multus
    participant CNI as galactic-cni
    participant VRF as vrf
    participant IfacePkg as veth/tap
    participant Route as route
    participant HD as host-device CNI
    participant K8s as Kubernetes API
    participant Kernel as Kernel (SRv6)
    participant Router as galactic-router

    rect rgb(220, 240, 220)
        note over Multus,Router: cmdAdd — Container Attach
        Multus->>CNI: ADD (vpc, vpcattachment, srv6_sid, interface_type, namespace, ipam, terminations)
        CNI->>CNI: parseConf() — NODE_NAME already validated at process startup
        CNI->>VRF: Add(vpc, vpcAttachment)
        CNI->>IfacePkg: veth.Add or tap.Add(vpc, vpcAttachment, MTU) — depends on interface_type
        CNI->>CNI: read host-side interface MAC/MTU (netlink.LinkByName)
        loop for each termination
            CNI->>Route: Add(vpc, vpcAttachment, network, via, host-side dev)
        end
        alt interface_type = tap
            CNI->>Multus: PrintResult (single host interface, no ips/routes)
            note over CNI: tap mode returns here — no IPAM, no BGP; the guest VM manages its own networking
        else interface_type = veth (default)
            CNI->>HD: ADD — move guest veth into pod netns (skipped if already moved by a prior attempt)
            CNI->>CNI: configureIPAM (built-in pool/static allocator, if ipam configured or --enable-local-ipam)
            CNI->>CNI: read guest veth MAC/MTU inside container netns
            CNI->>Multus: PrintResult (interfaces[0]=host veth, interfaces[1]=guest veth, ips[0].interface=1)
            note over CNI,Multus: result is returned to Multus here — before SRv6/BGP setup below
            CNI->>CNI: configureHostVethGateway — /128 gateway addr on host veth + explicit pod-subnet route in VRF table
            CNI->>CNI: Base62ToHex(vpc) → vpcHex (vpcAttachment is not hex-converted)
            CNI->>Kernel: RouteIngressAdd(srv6_sid, vpc, vpcAttachment) — skipped if srv6_sid is empty
            loop retry with backoff on transient k8s errors
                CNI->>K8s: List BGPRouters in namespace — match by targetRef.name == node name
                CNI->>CNI: compute RT = "ASN:<low 32 bits of vpcHex>"
                CNI->>K8s: CreateOrUpdate BGPVRFInstance (routerRef, RouteDistinguisher=RT, importRT=[RT], exportRT=[RT])
                CNI->>K8s: CreateOrUpdate BGPAdvertisement (routerRef, l2vpn/evpn, prefixes=[pod subnet], communities=[RT], annotations: allocated-subnet by containerID, srv6-sid for the EVPN gateway IP)
            end
            K8s-->>Router: BGPVRFInstance / BGPAdvertisement created or updated
            note over Router: reconciles into GoBGP asynchronously
        end
    end

    rect rgb(240, 220, 220)
        note over Multus,Router: cmdDel — Container Detach (idempotent; always returns success)
        Multus->>CNI: DEL
        CNI->>CNI: parseConf() — on parse failure, skip cleanup and return an empty result immediately
        alt interface_type = veth and IPAM was configured
            CNI->>K8s: best-effort client (ignored on error)
            CNI->>CNI: deallocateIPAM — look up the allocated subnet from the BGPAdvertisement annotation (keyed by containerID) and release it from the in-memory pool
        end
        note over CNI: shared resources (VRF, veth/tap, routes, SRv6 ingress route,<br/>BGPAdvertisement, BGPVRFInstance) are intentionally left in place —<br/>they're keyed by (vpc, vpcAttachment) and may be reused by another pod;<br/>deleting them here would race with a concurrent ADD during pod restarts
        CNI->>Multus: PrintResult (empty result)
        note over Router: galactic-router's GC controller reclaims orphaned<br/>BGPAdvertisement/BGPVRFInstance CRDs and stale kernel VRFs<br/>asynchronously (ticker-driven, default every 5m) — not part of cmdDel
    end
```
