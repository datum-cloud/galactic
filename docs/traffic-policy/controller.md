# galactic-controller

`galactic-controller --role=cell` runs once per edge cell and owns the API
side of interface traffic policy. It does not program any node: the per-node
datapath state belongs to `galactic-router`, which reads the bindings this
controller resolves (see [Traffic policy on the node](node.md)). The design is in
[the traffic policy proposal](../enhancements/networking/interface-traffic-policy/README.md);
the API reference is [docs/api/galactic.md](../api/galactic.md).

## What it does

- **Validating webhook** for TrafficPolicy, failing closed. It rejects an
  explicit `null` at any optional match field, which the schema cannot see;
  re-parses and canonicalizes every address and prefix; refuses a policy that
  would compile past the datapath's entry limit; and warns about rules that
  can never match or are never reached. Only the controller may create or
  change a policy named `default-deny-all`, and only it may delete its own
  one, except while the namespace is being deleted. DELETE reaches the
  webhook only for that name, so an outage cannot stall namespace teardown.
- **Default policy.** In every namespace that holds a VPCAttachment it
  creates `default-deny-all`, one rule denying everything, labeled
  `galactic.datumapis.com/managed-by: galactic-controller`, so it can be
  referenced by name. An existing object of that name that it does not own is
  never adopted or overwritten: it gets an `Accepted=False` condition with
  reason `ReservedNameConflict` and a `ProvisioningConflict` event, and
  explicit references to it resolve to nothing. Its owner clears the
  conflict by deleting it, after which the controller provisions its own;
  until then they can still edit it, but not label it as the controller's.
- **Policy status.** Every TrafficPolicy gets an `Accepted` condition: true
  with the compiled entry count and any unreachable or shadowed rules, or
  false with the validation errors.
- **Binding status.** Every TrafficPolicyBinding gets `status.ingress` and
  `status.egress`: the resolved policy identity and a `Resolved` condition,
  with reason `Default` (no reference, the built-in default), `Resolved`,
  `NotFound`, `PolicyInvalid` or `PolicyReservedNameConflict`. It applies
  only those fields with server-side apply, so the per-node entries under
  `status.nodes` stay with the nodes that write them.

## Flags

| Flag                          | Default                                                 | Meaning                                                    |
| ----------------------------- | ------------------------------------------------------- | ---------------------------------------------------------- |
| `--role`                      | none (required)                                         | `cell`, the only role so far                               |
| `--namespace`                 | `POD_NAMESPACE`, else `galactic-system`                 | Namespace of the pod and its leader election lease         |
| `--metrics-bind-address`      | `:9184`                                                 | controller-runtime metrics                                 |
| `--health-probe-bind-address` | `:8081`                                                 | `/healthz`, and `/readyz` once the webhook is serving      |
| `--webhook-port`              | `9443`                                                  | Admission webhook port                                     |
| `--webhook-cert-dir`          | `/tmp/k8s-webhook-server/serving-certs`                 | Holds `tls.crt` and `tls.key`                              |
| `--leader-elect`              | `true`                                                  | One replica reconciles; every replica serves the webhook   |
| `--controller-username`       | `system:serviceaccount:<namespace>:galactic-controller` | The only user allowed to write the reserved default policy |

## Installing

Apply, in order:

1. the `galactic.datumapis.com` CRDs, `kubectl apply -k config/crd`, including the `VPCAttachment` CRD; the controller watches it and
   does not become ready without it;
2. cert-manager, if the cell does not have it;
3. the ServiceAccount and RBAC, `kubectl apply -k config/galactic-controller`;
4. the controller, `kubectl apply -k config/galactic-controller/base`, which
   includes the self-signed serving certificate and the
   ValidatingWebhookConfiguration and pod MutatingWebhookConfiguration.

The webhook fails closed, so install it only with the Deployment it points
at. With no replica serving, every TrafficPolicy write is refused; the
Deployment runs two replicas with a PodDisruptionBudget for that reason.
Nothing here is in the root `config/kustomization.yaml`, and installing it
changes no packet until the datapath enforces policy.
