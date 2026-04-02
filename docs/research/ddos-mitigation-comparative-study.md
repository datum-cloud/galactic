# DDoS Detection and Mitigation: Traditional vs. SRv6 Comparative Study

**Date**: March 2026
**Purpose**: Landscape assessment before architectural decisions
**Scope**: Full spectrum from battle-tested traditional approaches through emerging SRv6-based methods

---

## Part 1: Traditional DDoS Mitigation — The Baseline

These are not legacy techniques. They are the production baseline with twenty years of operational learning behind them. Any new approach needs to beat or complement what's here.

### 1.1 The Defense Layers

A well-run DDoS mitigation operation in 2026 stacks multiple layers:

**Layer 1 — Ingress filtering and anti-spoofing.** Source address validation ([BCP38/RFC 2827](https://www.rfc-editor.org/rfc/rfc2827), [BCP84/RFC 3704](https://www.rfc-editor.org/rfc/rfc3704)) and [uRPF](https://www.rfc-editor.org/rfc/rfc8704) prevent spoofed-source attacks at their origin. The problem: despite 25 years of advocacy, the [CAIDA Spoofer Project](https://spoofer.caida.org/) still shows ~25-30% of ASes allow spoofed packets out. [MANRS](https://manrs.org/) has ~1,000 operator participants — growing, but a fraction of the internet's ~75,000 ASes. Spoofed-source amplification attacks persist because deployment remains incomplete.

**Layer 2 — RTBH (black hole routing).** The fastest response when an attack threatens to saturate your links. A trigger router injects a /32 route to Null0, propagated via iBGP to all edges. Destination-based RTBH sacrifices the target to save the network ("sacrificing the hostage to save the building"). Source-based RTBH ([RFC 5635](https://www.rfc-editor.org/rfc/rfc5635)) preserves the target but only works when attack sources are enumerable and stable. Inter-domain signaling uses the [RFC 7999](https://www.rfc-editor.org/rfc/rfc7999) BLACKHOLE community (`65535:666`), widely supported by transit providers and IXPs. [Team Cymru's UTRS](https://www.team-cymru.com/ddos-mitigation-utrs-services) extends this across hundreds of participating networks. Automation via tools like [ExaBGP](https://github.com/Exa-Networks/exabgp), [GoBGP](https://github.com/osrg/gobgp), or [BIRD](https://bird.network.cz/) is critical.

**Layer 3 — FlowSpec.** [BGP FlowSpec](https://www.rfc-editor.org/rfc/rfc8955) distributes surgical filtering rules (match on src/dst, protocol, port, packet size, etc.) via BGP to all edge routers. More granular than RTBH — you can rate-limit or drop specific attack traffic without blackholing the target entirely. The constraint is TCAM: most platforms support 10K-50K FlowSpec rules before exhaustion. At 400G+ line rates, you can't enumerate every source of a large DDoS in hardware ACLs, which is why scrubbing exists.

**Layer 4 — Scrubbing.** Attack traffic is diverted (via BGP re-route) to a scrubbing center that separates bad from good through a multi-stage pipeline: volumetric filtering, protocol validation, behavioral analysis, and application-layer inspection. The industry best practice in 2026 is **hybrid scrubbing**: on-premise appliances ([Arbor/NETSCOUT](https://www.netscout.com/arbor-ddos), [Corero](https://www.corero.com/smartwall/), [A10](https://www.a10networks.com/products/thunder-tps/)) handle routine attacks up to their capacity, with cloud scrubbing ([Cloudflare Magic Transit](https://www.cloudflare.com/network-services/products/magic-transit/), [Akamai Prolexic](https://www.akamai.com/products/prolexic-solutions), [AWS Shield](https://aws.amazon.com/shield/)) activated for overflow. Clean traffic returns via GRE tunnel or direct interconnect, with well-known challenges around MTU (GRE adds 24-48 bytes overhead) and asymmetric routing.

**Layer 5 — Anycast distribution.** Same prefix announced from multiple PoPs; attack volume distributed geographically. Highly effective for volumetric attacks. All root DNS servers, Cloudflare (1,300+ cities), and major CDNs rely on this. Less effective against application-layer attacks, which just distribute the processing problem.

**Layer 6 — Application protection.** WAF, bot management, rate limiting, challenge-response (JS challenges, CAPTCHAs), and TLS fingerprinting (JA3/JA4). This is where flash crowd vs. DDoS discrimination is hardest — HTTP-layer false positive rates run 5-20% even in well-tuned deployments.

### 1.2 Detection in Practice

Detection uses sampled flow telemetry from routers and switches. The two dominant protocols are sFlow (packet-based sampling, stateless on device, dominant on switches and at IXPs) and NetFlow/IPFIX (flow-based with on-device cache, dominant on routers from Cisco/Juniper/Nokia). Sampling rates typically range from 1:1000 at peering points to 1:8192 on high-speed backbone links.

**Real-world detection latency:**
- sFlow-based: **5-30 seconds** end-to-end
- NetFlow-based: **1-5 minutes** (flow cache timeouts dominate)
- Hyperscaler custom pipelines: **seconds**

The major detection platforms: [Arbor/NETSCOUT Sightline](https://www.netscout.com/arbor-ddos) (de facto standard at Tier 1 ISPs), [FastNetMon](https://github.com/pavel-odintsov/fastnetmon) (popular open-source option for small-medium ISPs), [sFlow-RT](https://sflow-rt.com/) (real-time analytics, popular at IXPs), [Kentik](https://www.kentik.com/product/protect/) (SaaS-based, strong BGP correlation), and custom pipelines using [pmacct](https://github.com/pmacct/pmacct) into Kafka (used by [OVHcloud](https://blog.ovhcloud.com/the-rise-of-packet-rate-attacks-when-core-routers-turn-evil/) and others).

**The key insight: detection speed is rarely the bottleneck.** Mitigation deployment is. BGP-based traffic diversion to scrubbing takes 30-90 seconds to converge across a network. Shaving detection from 5 seconds to 1 second is marginal when mitigation activation dominates. This was [NANOG](https://www.nanog.org/events/archive/) consensus across multiple presentations in 2023-2024. The industry trend is toward full automation: detection-to-mitigation in under 60 seconds for known volumetric attack patterns.

### 1.3 Economics

| Item | Cost Range |
|---|---|
| On-prem scrubbing appliance | $50K-$500K+ per appliance, plus 15-20% annual maintenance |
| Full on-prem deployment (100 Gbps capacity) | $500K-$2M initial, $200K-$400K/year ongoing |
| Cloud scrubbing (clean pipe pricing) | $5-$15/Mbps/month at 1 Gbps+ commits |
| [Cloudflare Magic Transit](https://www.cloudflare.com/network-services/products/magic-transit/) | ~$5K/month base, $3-$8/Mbps at scale |
| [Akamai Prolexic](https://www.akamai.com/products/prolexic-solutions) | $15K-$40K/month for 10 Gbps clean commit |
| Running a scrubbing center (modest) | $3M-$8M/year |
| Running a scrubbing center (Tier 1 grade) | $10M-$30M/year |

Most operators buy rather than build. The economics of scrubbing heavily favor scale.

### 1.4 The Threat Landscape in 2026

Attacks are multi-vector (volumetric + protocol + application simultaneously), often short-duration (<15 min "pulse" attacks), and regularly exceed 1 Tbps volumetric / 100M+ RPS application-layer. IoT botnets (Mirai variants) remain the primary source. DDoS-for-hire is available for <$20/month. Key recent evolutions: **carpet bombing** (emerged ~2019, distributes low-volume traffic across an entire /24 to evade per-IP detection), [HTTP/2 Rapid Reset](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/) (CVE-2023-44487, 398M RPS), and browser-based botnets generating traffic indistinguishable from real users.

Cross-AS coordination remains largely manual. [DOTS](https://www.rfc-editor.org/rfc/rfc9132) (standardized signaling) adoption is limited. BGP FlowSpec is rarely accepted across AS boundaries. In practice, operators protect their own networks and coordinate with contracted scrubbing providers.

---

## Part 2: SRv6-Based DDoS Mitigation — Where Things Actually Stand

### 2.1 The Honest Answer: Almost Nobody Is Doing This

Almost nobody is running SRv6 *specifically for DDoS mitigation* in production at scale. Chinese operators (China Telecom, China Mobile, China Unicom) lead SRv6 deployment broadly — primarily for L3VPN, traffic engineering, and network slicing. SoftBank (Japan), Bell Canada, and Iliad/Free (France) have SRv6 backbones focused on TE and VPN. The closest DDoS-adjacent use case: Chinese operators have demonstrated steering traffic through scrubbing middleboxes using SRv6 service function chaining, presented at [MPLS+SDN+NFV World Congress](https://www.uppersideconferences.com/mpls-sdn-nfv/) 2022-2023 by Huawei/ZTE. But even there, it's "SRv6 steering to existing scrubbers" rather than a fundamentally new DDoS architecture.

### 2.2 What SRv6 Actually Changes (and Doesn't)

**SRv6 does not replace scrubbing intelligence. It replaces traffic steering.** The comparison is really: GRE tunnels to scrubbers (traditional) vs. SRv6 service chains to scrubbers (new). The scrubbing logic, detection systems, and mitigation intelligence are all unchanged.

Three architecture patterns exist, in decreasing order of reality:

**Pattern A (closest to production):** Traditional detection (NetFlow/sFlow) signals FlowSpec or RTBH. A controller translates this into SRv6 TE policy at the headend, steering traffic to a scrubbing center. The scrubber itself doesn't need to be SRv6-aware. This is the pragmatic approach and replaces GRE/MPLS-based redirect with SRv6 policy steering.

**Pattern B (lab/PoC):** Full SRv6 service function chaining through a pipeline of network functions (classifier -> DPI -> scrubber -> firewall -> destination), using [SRv6 service programming](https://datatracker.ietf.org/doc/draft-ietf-spring-sr-service-programming/) proxy behaviors (END.AD/END.AM/END.AS). Demonstrated by Huawei and Cisco in labs. Not in production for DDoS.

**Pattern C (research only):** P4 switches with INT detect anomalies at line rate, insert SRv6 encap to steer to the nearest scrubber. Paper-only.

### 2.3 The Ecosystem Gap

**Vendor support is uneven.** Huawei has the strongest FlowSpec-to-SRv6 integration (production in Chinese operator networks). Cisco supports SRv6 TE policies well (especially on the 8000 series/Silicon One) with partial FlowSpec bridging. Nokia's FlowSpec-to-SRv6 bridging is emerging. Juniper historically lagged on SRv6, preferring SR-MPLS. The [draft bridging FlowSpec with SRv6](https://datatracker.ietf.org/doc/draft-ietf-idr-ts-flowspec-srv6-policy/) is primarily Huawei-driven and remains a working group draft, not yet RFC.

**The detection ecosystem hasn't caught up.** No major detection platform — not [Arbor/NETSCOUT](https://www.netscout.com/arbor-ddos), not [Kentik](https://www.kentik.com/product/protect/), not [FastNetMon](https://github.com/pavel-odintsov/fastnetmon), not [Cloudflare](https://www.cloudflare.com/network-services/products/magic-transit/) — natively signals SRv6 policies. Only Huawei's AntiDDoS product does, within the Huawei ecosystem. In practice, deployments use a **translation layer**: the detector signals FlowSpec or RTBH, and a custom controller translates to SRv6 TE policy.

**P4 hardware is contracting.** Intel discontinued Tofino and wound down the ASIC division. Many academic P4 programs for SRv6/DDoS were written for Tofino — the platform's sunset is a significant blow to this research direction. Nokia's FP5 and Broadcom's Jericho2+ cover most practical use cases with built-in capabilities but aren't P4-programmable.

**Standards are immature.** [IOAM](https://datatracker.ietf.org/wg/ioam/about/) is winning over INT for production SRv6 telemetry (IETF-standardized, native SRv6 integration). No multi-vendor interop testing has been publicly shared for FlowSpec-to-SRv6 DDoS scenarios. SRv6 SID format interop (Cisco's uSID vs. standard SIDs) still creates friction.

**Open source is research-grade.** [VPP/fd.io](https://fd.io/) ([SRv6 docs](https://wiki.fd.io/view/VPP/Segment_Routing_for_IPv6)) is the most viable open-source platform for SRv6 scrubbing/proxy (DPDK-based, 10-100 Gbps, full service programming support). [FRR](https://frrouting.org/) has SRv6 control plane support but no FlowSpec-to-SRv6 integration. [SONiC](https://github.com/sonic-net/SONiC) has basic SRv6 but no FlowSpec, no service chaining, and no IOAM. The Linux kernel lacks the END.AD/END.AM proxy behaviors needed for service chaining to scrubbers.

---

## Part 3: Detection Deep Dive

### 3.1 ML/AI for DDoS — Marketing vs. Reality

Most "ML/AI-based DDoS detection" in production is really adaptive thresholding (learning traffic baselines over time), attack classification (identifying attack type once an anomaly is detected), and automated countermeasure selection. Fully ML-driven detection — where the model itself decides "this is an attack" without threshold pre-filtering — is rare because false positive cost is too high, simple thresholds catch 90%+ of volumetric attacks, and operators need explainability.

Cloudflare's multi-stage pipeline (per-server XDP heuristics -> edge anomaly detection -> global transformer-based models) is arguably the most sophisticated in production. Most vendors ([Arbor](https://www.netscout.com/arbor-ddos), [Kentik](https://www.kentik.com/product/protect/), [Radware](https://www.radware.com/products/defensepro/), [A10](https://www.a10networks.com/products/thunder-tps/)) use ML primarily for classification and adaptive rate limiting, not initial detection.

### 3.2 eBPF/XDP — Transformative, But Only for Some

eBPF/XDP-based DDoS mitigation is production-proven at hyperscalers. Cloudflare processes packets at line rate on every server via XDP programs ([architecture blog post](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/)), achieving <1ms mitigation for known patterns and ~200 attacks/hour mitigated. [Meta's Katran](https://github.com/facebookincubator/katran) handles >10M pps per core.

The catch: **XDP requires Linux-based forwarding planes.** Service providers running Cisco/Juniper/Nokia routers can't use it on their core infrastructure. It's applicable at scrubbing centers, peering routers built on Linux, and cloud/CDN edges. For traditional router-centric ISP networks, XDP is a scrubbing-center technique, not a network-wide one.

### 3.3 Does Faster Detection Actually Help?

UDP amplification attacks ramp to full volume in 1-2 seconds. Botnet HTTP floods ramp over minutes. Carpet bombing spreads over minutes per /24. For operators using BGP-based mitigation (where diversion takes 30-90 seconds), detecting 4 seconds faster is meaningless. For operators using inline mitigation ([Corero](https://www.corero.com/smartwall/), [Radware](https://www.radware.com/products/defensepro/), XDP), faster detection directly translates to faster mitigation. [CableLabs Transparent Security](https://github.com/cablelabs/transparent-security) demonstrated 1-second detection with P4/INT in lab, but cable operators haven't deployed it — existing flow-based detection is "good enough" for the economics.

---

## Part 4: Head-to-Head Comparison

### 4.1 Where Traditional Wins

| Dimension | Traditional Advantage |
|---|---|
| **Operational maturity** | 20+ years of production learning, playbooks, and tooling. Failures are well-understood. |
| **Staff availability** | FlowSpec: 60-80% of DDoS-focused engineers know it. Ramp-up: 1-2 weeks. |
| **Tooling** | Mature dashboards, forensics, REST APIs, Ansible/Terraform modules. |
| **Cross-AS coordination** | [RFC 7999](https://www.rfc-editor.org/rfc/rfc7999) BLACKHOLE community widely supported. No SRv6 equivalent. |
| **Multi-tenant isolation** | VRF + per-VRF FlowSpec is production-proven with hundreds of tenants. |
| **Economics** | Lower TCO today. Standard staffing costs. Proven vendor pricing models. |
| **Failure modes** | Worst case (FlowSpec misconfiguration) is well-known with robust safeguards. |

### 4.2 Where SRv6 Has Genuine Advantages

| Dimension | SRv6 Advantage |
|---|---|
| **Headend-only steering** | No per-hop tunnel state. Changing the scrubbing path = changing one segment list at the headend. No GRE tunnel mesh to manage. |
| **Steering granularity** | Route different traffic classes through different scrubbing chains with a single policy change. Doing this with FlowSpec + GRE requires multiple rules and tunnel configurations. |
| **Scaling** | SRv6 chains are stateless at transit — scales to thousands of policies at the headend. GRE tunnels are per-endpoint state that gets problematic at scale. |
| **Unified transport** | DDoS steering uses the same infrastructure as VPN and TE. Operational simplification at scale, long-term. |
| **Elastic scrubbing** | SRv6 + VNF-based scrubbing enables scaling capacity up/down, potentially reducing over-provisioning by 20-40%. |

### 4.3 Where the Difference Doesn't Matter

**Signaling speed.** FlowSpec propagates in 3-12 seconds. SRv6 headend changes take 1-6 seconds. The difference is swamped by detection latency (30+ seconds for flow-based) and is irrelevant to outcomes.

**MTU overhead.** GRE adds 24-48 bytes. SRv6 SRH adds 64-96 bytes (more than GRE, except with uSID compression). Both require careful MTU management. Neither is clearly better.

**Detection.** Detection systems are infrastructure-agnostic — the same Arbor/Kentik/FastNetMon works whether you steer traffic via GRE or SRv6. No gap here.

### 4.4 Operational Maturity Gap

This is the most important comparison and it's not close:

| Dimension | Traditional | SRv6-Based |
|---|---|---|
| **Hiring pool** | Thousands of candidates globally | Scarce; 20-40% salary premium; SRv6+DDoS intersection essentially doesn't exist |
| **Ramp-up time** | 1-2 weeks for FlowSpec | 6-12 months for SRv6 service chaining |
| **Mitigation tooling** | 10-20 years of refinement | **5-8 years behind** — no SRv6 forensics product category, debugging 2-5x slower |
| **Failure playbooks** | Comprehensive, community-validated | Sparse; novel failures take significantly longer at 3 AM |
| **Worst failure mode** | FlowSpec blackhole (well-known safeguards) | SID collision leaking traffic between tenants (no established safeguards) |

---

## Part 5: The Honest Assessment

### Is SRv6-Native DDoS Mitigation Ready? (2026)

**No. Unambiguously no.** The reasons:

1. **Tooling is 5-8 years behind** traditional mitigation
2. **Staff expertise barely exists** — you'll train people, not hire them
3. **SRv6 only replaces steering**, not detection or scrubbing intelligence
4. **No production-validated reference architecture** outside Huawei ecosystem in China
5. **VNF scrubbing unproven** at 100+ Gbps vs. purpose-built hardware

### Where SRv6 Is Heading

SRv6 is a superior traffic steering architecture in theory. The protocol is well-defined. The problem is everything around it: tooling, expertise, vendor interop, and operational validation. These gaps will close, but they're real today.

### Pragmatic Migration Path

**Phase 1: Now (2026) — Build on proven foundations.** Flow-based detection + FlowSpec + hybrid scrubbing (on-prem + cloud overflow). Begin SR-MPLS if not already deployed. Invest in API-driven orchestration that abstracts the steering mechanism — this lets you swap GRE for SRv6 later without rewriting automation. Cost: $500K-$3M initial + $300K-$1M/year.

**Phase 2: 2-3 years (2028) — Introduce SRv6 for TE, not DDoS.** Deploy SRv6 for traffic engineering and VPN alongside MPLS. Build operational expertise on non-critical workloads. Pilot service chaining with non-DDoS VNFs. Keep production DDoS on the traditional stack.

**Phase 3: 3-5 years (2029-2031) — Hybrid.** SRv6 steering for lower-risk traffic. Traditional FlowSpec + GRE for premium/critical customers. Tooling and VNF performance should have matured by then.

**Phase 4: 5-10 years (2031-2036) — SRv6-primary.** SRv6 service chains as primary steering. FlowSpec retained for edge filtering (complementary, not replaced). Per-tenant SRv6 slicing with per-slice DDoS policies.

### What's Portable

Detection and scrubbing intelligence are fully portable across steering mechanisms. [Arbor](https://www.netscout.com/arbor-ddos), [Kentik](https://www.kentik.com/product/protect/), [FastNetMon](https://github.com/pavel-odintsov/fastnetmon) work the same regardless of whether steering is GRE or SRv6. Scrubbing logic is unchanged — only encap/decap changes. If you build API-driven orchestration with proper abstraction, the steering mechanism becomes a swappable layer. **There is no wasted investment in building traditional mitigation today.**

---

## Maturity Matrix

| Capability | Maturity | Production Timeline |
|---|---|---|
| Traditional FlowSpec + RTBH + GRE scrubbing | **Battle-tested** | Now |
| sFlow/NetFlow detection at scale | **Battle-tested** | Now |
| eBPF/XDP inline mitigation | **Production** (hyperscalers) | Now (if you have Linux forwarding planes) |
| ML-assisted detection/classification | **Production** (augments thresholds) | Now |
| SRv6 TE for steering to scrubbers | **Early production** (China) / **PoC** (elsewhere) | Now (Huawei) / 1-2 years (multi-vendor) |
| FlowSpec->SRv6 Policy (standards) | **Draft** | 1-3 years to RFC + interop |
| SRv6 service function chaining for DDoS | **Lab/PoC** | 2-3 years |
| IOAM-based detection in SRv6 networks | **Early research** | 3-5 years |
| P4+SRv6 DDoS (Tofino-based) | **Declining** (hardware sunset) | May never reach production |
| Open source SRv6 DDoS stack | **Research/PoC** | [VPP](https://fd.io/)-based approaches viable in 1-2 years |
| SRv6 slicing for multi-tenant DDoS | **Theoretical** | 3-5 years (early adopters) |

---

## Key References

### RFCs and Standards
- [RFC 2827](https://www.rfc-editor.org/rfc/rfc2827) / BCP38: Network Ingress Filtering
- [RFC 3704](https://www.rfc-editor.org/rfc/rfc3704) / BCP84: Ingress Filtering for Multihomed Networks
- [RFC 5635](https://www.rfc-editor.org/rfc/rfc5635): Remote Triggered Black Hole Filtering with uRPF
- [RFC 7999](https://www.rfc-editor.org/rfc/rfc7999): BLACKHOLE Community
- [RFC 8704](https://www.rfc-editor.org/rfc/rfc8704): Enhanced Feasible-Path uRPF
- [RFC 8955](https://www.rfc-editor.org/rfc/rfc8955) / [RFC 8956](https://www.rfc-editor.org/rfc/rfc8956): Flow Specification Rules (FlowSpec)
- [RFC 9132](https://www.rfc-editor.org/rfc/rfc9132): DDoS Open Threat Signaling (DOTS)
- [RFC 9197](https://www.rfc-editor.org/rfc/rfc9197) / [RFC 9326](https://www.rfc-editor.org/rfc/rfc9326): IOAM Data Fields and Direct Exporting
- [RFC 9252](https://www.rfc-editor.org/rfc/rfc9252): BGP Overlay Services Based on SRv6
- [RFC 9259](https://www.rfc-editor.org/rfc/rfc9259): SRv6 OAM
- [RFC 3176](https://www.rfc-editor.org/rfc/rfc3176) / [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011): sFlow / IPFIX

### IETF Drafts
- [draft-ietf-idr-ts-flowspec-srv6-policy](https://datatracker.ietf.org/doc/draft-ietf-idr-ts-flowspec-srv6-policy/) — FlowSpec + SRv6 steering
- [draft-ietf-spring-sr-service-programming](https://datatracker.ietf.org/doc/draft-ietf-spring-sr-service-programming/) — SRv6 service function chaining
- [draft-ietf-teas-ietf-network-slices](https://datatracker.ietf.org/doc/draft-ietf-teas-ietf-network-slices/) — Network slicing
- [IOAM Working Group](https://datatracker.ietf.org/wg/ioam/about/) — In-situ OAM standards

### Community and Conferences
- [NANOG archives](https://www.nanog.org/events/archive/) | [RIPE NCC](https://www.ripe.net/) | [APRICOT](https://www.apricot.net/) | [MPLS+SDN+NFV World Congress](https://www.uppersideconferences.com/mpls-sdn-nfv/)
- [MANRS](https://manrs.org/) — BCP38 deployment tracking
- [CAIDA Spoofer Project](https://spoofer.caida.org/) — Spoofing measurement data
- [Team Cymru UTRS](https://www.team-cymru.com/ddos-mitigation-utrs-services) — Community blackholing service
- [Segment Routing](https://www.segment-routing.net/) — SR community information

### Vendor Products and Reports
- [NETSCOUT Threat Intelligence Report](https://www.netscout.com/threatreport) | [Cloudflare DDoS Threat Report](https://radar.cloudflare.com/reports)
- Cloudflare engineering: [L4Drop/XDP mitigation](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/), [Unimog load balancer](https://blog.cloudflare.com/unimog-cloudflares-edge-load-balancer/), [HTTP/2 Rapid Reset](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)
- [OVHcloud DDoS architecture](https://blog.ovhcloud.com/the-rise-of-packet-rate-attacks-when-core-routers-turn-evil/)
- SRv6 docs: [Cisco 8000 Series](https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/srv6/b-srv6-configuration-guide/m-segment-routing-over-ipv6.html) | [Nokia SR](https://documentation.nokia.com/sr/23-3-1/books/7x50-shared/segment-routing-pce-user/segment-rout-with-ipv6-data-plane-srv6.html)
- Cloud DDoS: [AWS Shield](https://aws.amazon.com/shield/) | [Azure DDoS Protection](https://learn.microsoft.com/en-us/azure/ddos-protection/) | [Google Cloud Armor](https://cloud.google.com/security/products/armor)

### Open Source
- [VPP / fd.io](https://fd.io/) ([SRv6 docs](https://wiki.fd.io/view/VPP/Segment_Routing_for_IPv6)) — Best open-source SRv6 implementation
- [FRRouting](https://frrouting.org/) — SRv6 control plane | [BIRD](https://bird.network.cz/) — Routing daemon | [SONiC](https://github.com/sonic-net/SONiC) — Open NOS
- [FastNetMon](https://github.com/pavel-odintsov/fastnetmon) — DDoS detection | [sFlow-RT](https://sflow-rt.com/) — sFlow analytics | [pmacct](https://github.com/pmacct/pmacct) — Telemetry collection
- [ExaBGP](https://github.com/Exa-Networks/exabgp) / [GoBGP](https://github.com/osrg/gobgp) — Programmatic BGP for RTBH/FlowSpec
- [Meta Katran](https://github.com/facebookincubator/katran) — XDP L4 load balancer
- [CableLabs Transparent Security](https://github.com/cablelabs/transparent-security) — P4/INT DDoS PoC
- [ROSE project](https://github.com/netgroup/rose-srv6-control-plane) — Academic SRv6 experimentation
