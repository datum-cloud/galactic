# API references

These references describe the Kubernetes resources served as
`galactic.datumapis.com/v1alpha1`. The source packages separate ownership and
implementation; they do not create separate API groups.

| Reference                                  | Resources                                                                                      | Source package          |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------- | ----------------------- |
| [Cloud](cloud.md)                          | VPC, VPCAttachment, NetworkFabricIdentity                                                      | `api/cloud/v1alpha1`    |
| [Routing](network-bgp.md)                  | BGP configuration, prefix lists, fabric topology, revisions, deployments and release controls  | `api/network/v1alpha1`  |
| [Gateway and services](network-gateway.md) | NetworkGateway, NetworkService, NetworkEgressPolicy, EgressShard and private-service resources | `api/network/v1alpha1`  |
| [Policy and Edge](galactic.md)             | TrafficPolicy, TrafficPolicyBinding and Galactic Edge resources                                | `api/v1alpha1`          |

The [FabricQuery reference](../fabric-api/api.md) is a maintained explanation
of diagnostic requests and results. Its source is `internal/fabric/api/v1alpha1`;
it is separate from these generated references.

For operating procedures, begin at the [documentation index](../README.md).
An API field's presence does not imply that its controller is deployed or that
its feature is enabled. Follow the corresponding component's deployment and
rollout guide.

## Updating the generated references

Edit the Go API comments and validation markers. When assigning a new resource
to a reference, update the corresponding `.crd-ref-docs*.yaml` filter. The BGP
and gateway references partition the network resources; shared field types may
appear in both, but each resource must appear in exactly one resource index.
Filters match qualified Go type names. Exclude collection wrappers explicitly:
`BGPPrefixList` is a resource, while `BGPPrefixListList` is its collection.

From the repository root, with Go and Task installed:

```sh
task generate:api-docs
task docs:check-generated
```

The generator version is pinned in `hack/docs/generate_api.py`. It adds the
source banner and quotes array-pattern validations so regular expressions do
not render as Markdown links. Do not edit generated Markdown by hand. The
check regenerates into a temporary directory and fails on a difference without
modifying tracked files.

## Checking documentation

The link checker uses a pinned CommonMark parser. Install its dependencies in
a virtual environment, then run the local gate:

```sh
python3 -m venv /tmp/galactic-docs-venv
. /tmp/galactic-docs-venv/bin/activate
python3 -m pip install -r hack/docs/requirements.txt
task docs:check
```

The gate checks local files, images, reference links, heading fragments and
explicit HTML anchors in `docs/`, the root README and agent instructions. It
also checks links into `docs/` from other tracked Markdown files. Code blocks,
code spans and HTML comments are parsed as examples, not links. It checks each
resource struct against the generated resource indexes, including resources
whose names end in `List`.

External URLs and executable deployment examples are outside this gate. The
separate Documentation workflow runs this gate and the generated-reference
check on every pull request, including pull requests targeting another branch
in a stack.
