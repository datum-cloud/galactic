# Galactic Edge

Galactic Edge gives providers authorized attachments to tenant VPCs and controls which provider may forward each prefix. The provider owns its protocol and client sessions; Galactic owns attachment isolation, policy, route lifetime and forwarding ownership.

- [Provider contract](provider-contract.md): resources, writers, lifecycle, timing assumptions and required failure evidence.
- [Troubleshooting](troubleshooting.md): conditions, Events, metrics and locating the current prefix holder.
- [MASQUE connector service](masque-service.md): the `masque-provider` command and image, its configuration, limits, readiness and shutdown.
- [MASQUE provider adapter](masque-provider.md): setup, readiness, drain and cleanup of the CONNECT-IP provider's attachments and routes.
- [MASQUE grant authority](masque-authority.md): connector credentials, allocation ledgers, EdgeService issue, refresh and revocation, and the operator commands.
- [MASQUE capacity](masque-capacity.md): the CONNECT-IP load harness, its loopback results and what still needs edge nodes.
- [CONNECT-IP interoperability](connectip-interop.md): HTTP/3 and HTTP/2 protocol proof with an independent client, and the stacks selected for it.
- [Foundation metrics](../observability/edge.md): lifecycle and forwarding-gate measurements.
- [Design record](../designs/galactic-edge.md): motivation and design alternatives.
- [Generated API](../api/galactic.md): exact resource fields and validation.

Implemented code and a conformance harness are not proof of production qualification. Review the contract's open items and the evidence for the candidate release before relying on capacity or timing targets.
