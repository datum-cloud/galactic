# Local E2E Testing on macOS with Colima

> Last verified: 2026-03-12 against branch `consolidate-monorepo`

This guide walks through setting up a local environment to run the Galactic VPC end-to-end test suite on macOS using Colima and VS Code devcontainers.

The E2E tests spin up a 4-node kind cluster inside the Colima VM, deploy the full Galactic stack, and verify that VPC overlays provide working cross-region IPv4 and IPv6 connectivity. The full suite takes approximately 15–20 minutes on first run (image builds included) and around 8–10 minutes on subsequent runs.

---

## Prerequisites

Install the following on your Mac before proceeding:

| Tool | Installation |
|------|-------------|
| [Colima](https://github.com/abiosoft/colima) | `brew install colima` |
| Docker CLI | `brew install docker` |
| VS Code | [code.visualstudio.com](https://code.visualstudio.com) |
| VS Code Dev Containers extension | Install `ms-vscode-remote.remote-containers` in VS Code |

You do not need Docker Desktop. Colima provides the Docker daemon; the Docker CLI talks to it.

---

## 1. Create the Colima VM

The E2E cluster is 4 kind nodes (1 control-plane + 3 workers). Each node runs as a Docker container inside the Colima VM. The VM also needs to hold all pulled container images.

Create the VM with enough resources and a routable network address:

```bash
colima start \
  --cpu 4 \
  --memory 8 \
  --disk 100 \
  --network-address \
  --arch aarch64   # omit on Intel Macs
```

The `--network-address` flag assigns the VM a static IP on your Mac's local network. This is required because the devcontainer needs to reach kind container IPs directly — the `cluster-create` task patches the kubeconfig to use these IPs rather than `127.0.0.1`.

**Resource guidance:**

- 4 CPUs and 8 GB RAM are the minimum. 6 CPUs / 12 GB is more comfortable.
- 100 GB disk is recommended. The 4-node kind cluster, Cilium, and all Galactic images consume roughly 20 GB on first load. Docker's layer cache grows over time.

Verify Docker is reachable:

```bash
docker info
```

---

## 2. Install the VRF kernel module

This is the most important non-obvious step. Skip it and the E2E tests will fail with network interface errors when the CNI plugin tries to create VRF interfaces.

**Why this is needed:** The Galactic CNI plugin creates VRF (Virtual Routing and Forwarding) network interfaces using Linux `netlink`. VRF requires the `vrf` kernel module (`CONFIG_NET_VRF=m`). Kind cluster nodes share the host kernel — the Colima VM's kernel — so the module must be present in the VM. The default Colima VM image ships without `linux-modules-extra`, which means `vrf.ko` is absent by default.

SSH into the VM and install the modules:

```bash
colima ssh
```

Inside the VM:

```bash
# Install linux-modules-extra for the running kernel
sudo apt-get update
sudo apt-get install -y linux-modules-extra-$(uname -r)

# Load the vrf module immediately
sudo modprobe vrf

# Verify it loaded
lsmod | grep vrf
```

Expected output from `lsmod`:

```
vrf                    28672  0
```

---

## 3. Make VRF persistent across VM reboots

The module load from `modprobe` does not survive a VM restart. Add it to `/etc/modules` so it loads automatically:

```bash
# Still inside the Colima VM
echo "vrf" | sudo tee -a /etc/modules
```

Exit the VM:

```bash
exit
```

---

## 4. Open the devcontainer

Clone the repository if you have not already, then open it in VS Code:

```bash
code /path/to/galactic
```

When VS Code detects the `.devcontainer/devcontainer.json`, it will prompt you to reopen in a container. Click **Reopen in Container**, or use the Command Palette (`Cmd+Shift+P`) and run **Dev Containers: Reopen in Container**.

Alternatively, use the CLI:

```bash
devcontainer open /path/to/galactic
```

The first build takes several minutes. The `post-create.sh` script installs all development tools: Go, kind, kubectl, helm, task, chainsaw, and the Galactic-specific toolchain.

**How the devcontainer connects to Docker:** The devcontainer mounts `/var/run/docker.sock` from the Colima VM (Docker-outside-of-Docker). This means `docker`, `kind`, and all task commands in the devcontainer operate on the Colima VM's Docker daemon, not a daemon inside the container.

When the container starts, `post-create.sh` detects the Docker socket's GID, creates a `docker-host` group with that GID, and adds the `vscode` user to it. This is why docker commands work without `sudo`.

---

## 5. Run the E2E tests

Open a terminal inside the devcontainer and navigate to the E2E directory:

```bash
cd /workspaces/galactic/test/e2e
```

Run the full suite:

```bash
task default
```

This runs the following sequence:

1. `cluster-create` — Creates a kind cluster named `galactic-e2e` with 1 control-plane node and 3 worker nodes (region1, region2, region3), dual-stack IPv4+IPv6, no default CNI. Patches the kubeconfig server URL to the control-plane container IP and connects the devcontainer to the kind Docker network.
2. `images-load` — Loads `ghcr.io/datum-cloud/galactic:e2e-local` and `ghcr.io/datum-cloud/galactic-router:e2e-local` into the cluster. These images must already exist locally; build them first with `task images-build` if needed (see [Running individual steps](#6-running-individual-steps)).
3. `deploy` — Deploys all components in order: CRDs, Cilium, FluxCD, cert-manager, Multus, MQTT, node-setup, cni-installer, operator, router, agent.
4. `test` — Runs the three Chainsaw test suites.
5. `cluster-delete` — Deletes the kind cluster.

**Expected output from `task test`:**

Chainsaw runs three suites under `test/e2e/tests/`:

| Suite | What it checks |
|-------|---------------|
| `system-readiness` | The operator, router, agent, and MQTT deployments are Available/Ready |
| `vpc-lifecycle` | A VPC and three VPCAttachments reach Ready state |
| `vpc-connectivity` | Cross-region IPv4 and IPv6 ping succeeds between pods in region1, region2, and region3 |

A successful run ends with output like:

```
Tests Summary...
Passed  3
Failed  0
Skipped 0
```

---

## 6. Running individual steps

During development you typically do not want to recreate the cluster on every iteration.

**Build images after code changes:**

```bash
cd /workspaces/galactic/test/e2e
task images-build
task images-load
```

**Redeploy a single component after changing its manifest:**

```bash
# Example: redeploy the operator after changing config/components/operator
KUBECONFIG=/workspaces/galactic/test/e2e/.kubeconfig \
  kubectl apply -k /workspaces/galactic/config/components/operator
```

**Run tests without setup/teardown:**

```bash
cd /workspaces/galactic/test/e2e
task test
```

**Run a single test suite:**

```bash
cd /workspaces/galactic/test/e2e
KUBECONFIG=/workspaces/galactic/test/e2e/.kubeconfig \
  chainsaw test \
    --test-dir tests/vpc-connectivity \
    --config chainsaw-config.yaml
```

**Recreate only the cluster (keep images):**

```bash
cd /workspaces/galactic/test/e2e
task cluster-delete
task cluster-create
task images-load
task deploy
```

---

## 7. Troubleshooting

### Docker permission denied

**Symptom:** `docker: permission denied while trying to connect to the Docker daemon socket`

**Cause:** The `vscode` user's group membership is updated during container creation. A terminal opened before the group was applied does not have it in its session.

**Fix:** Open a new terminal in VS Code, which picks up the updated group. If a new terminal does not help, prefix the failing command with `sg docker-host`:

```bash
sg docker-host -- docker ps
sg docker-host -- task cluster-create
```

The Taskfile internally handles the group correctly; this issue typically only appears when running commands directly from a shell that predates the group setup.

---

### `uname -r` expands on Mac instead of inside the VM

**Symptom:** The `apt-get install linux-modules-extra-$(uname -r)` command installs the wrong package (a macOS kernel version string).

**Cause:** You ran the command on your Mac before SSHing into the VM, or your shell expanded the substitution locally.

**Fix:** SSH into the VM first, then run the command. If you need to run it as a one-liner from outside, use:

```bash
colima ssh -- bash -c 'sudo apt-get install -y linux-modules-extra-$(uname -r)'
```

---

### `vrf` module not found after VM restart

**Symptom:** After restarting the Colima VM, the CNI plugin fails again with netlink errors.

**Diagnosis:**

```bash
colima ssh
lsmod | grep vrf
cat /etc/modules
```

If `/etc/modules` does not contain `vrf`, the persistence step was missed.

**Fix:**

```bash
colima ssh
echo "vrf" | sudo tee -a /etc/modules
sudo modprobe vrf
```

---

### kind cluster unreachable from devcontainer

**Symptom:** `kubectl` commands time out or return "connection refused to 127.0.0.1:XXXXX".

**Cause:** The default kubeconfig written by kind uses `127.0.0.1` with the mapped host port, which resolves to the Mac's localhost from inside the devcontainer — not the Colima VM where the cluster actually runs.

**How it is handled automatically:** The `cluster-create` task patches the kubeconfig server URL to the control-plane container's IP on the kind Docker bridge network, and connects the devcontainer container to that network with `docker network connect kind <container-id>`. Both steps are idempotent and run automatically.

**If you see this after a manual kubeconfig reset:**

```bash
cd /workspaces/galactic/test/e2e
CP_IP=$(docker inspect galactic-e2e-control-plane \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' | head -1)
KUBECONFIG=.kubeconfig kubectl config set-cluster kind-galactic-e2e \
  --server=https://${CP_IP}:6443
```

---

### Disk full

**Symptom:** `kind load docker-image` or `docker pull` fails with "no space left on device".

**Diagnosis:**

```bash
colima ssh -- df -h /
```

**Fix:** Stop Colima and resize the disk. Note that disk resize only works to increase size, not decrease.

```bash
colima stop
colima start --disk 150  # or whatever size you need
```

Alternatively, prune unused images and stopped containers to reclaim space without resizing:

```bash
docker system prune -a
```

---

### Chainsaw timeouts

**Symptom:** A test step fails with "timeout exceeded" rather than an assertion error.

The global Chainsaw timeouts are defined in `test/e2e/chainsaw-config.yaml`:

```yaml
timeouts:
  apply: 2m
  assert: 5m
  delete: 2m
  exec: 2m
```

If your VM is underpowered, component startup — especially Cilium on 4 nodes — can exceed these limits. The `deploy` task uses its own `kubectl wait` calls with explicit timeouts; those are the first place to check for which component is slow.

**Fix:** Allocate more CPUs and memory to the Colima VM:

```bash
colima stop
colima start --cpu 6 --memory 12 --disk 100 --network-address
```
