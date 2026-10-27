# Galactic Edge

Galactic Edge gives providers authorized attachments to tenant VPCs and controls which provider may forward each prefix. The provider owns its protocol and client sessions; Galactic owns attachment isolation, policy, route lifetime and forwarding ownership.

- [Provider contract](provider-contract.md): resources, writers, lifecycle, timing assumptions and required failure evidence.
- [Troubleshooting](troubleshooting.md): conditions, Events, metrics and locating the current prefix holder.
- [CONNECT-IP interoperability](connectip-interop.md): HTTP/3 and HTTP/2 protocol proof with an independent client, selections and remaining HTTP/2 listener work.
- [Foundation metrics](../observability/edge.md): lifecycle and forwarding-gate measurements.
- [Design record](../designs/galactic-edge.md): motivation and design alternatives.
- [Generated API](../api/galactic.md): exact resource fields and validation.

Implemented code and a conformance harness are not proof of production qualification. Review the contract's open items and the evidence for the candidate release before relying on capacity or timing targets.
