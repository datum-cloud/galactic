// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/hostconf"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/radv"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ebpfHealthCheckInterval controls how often Run polls attach.Health once the
// eBPF datapath is running. A var, not a const, so tests can shrink it.
var ebpfHealthCheckInterval = 10 * time.Second

// ebpfGCSweepInterval controls how often Run runs the eBPF map GC sweeps once
// the datapath is running. Matches galactic-router's own GC controller
// period.
var ebpfGCSweepInterval = 5 * time.Minute

// radvReconcileInterval controls how often Run diffs the recorded tap
// attachments against the running radv.RunActor goroutines, starting one for
// each new attachment and canceling one for each that has gone. Kept short,
// unlike the RFC-sized intervals the actors themselves use, because it only
// gates how fast a new attachment starts being served, and a guest's boot time
// dwarfs a few seconds.
var radvReconcileInterval = 2 * time.Second

// tapNeighReconcileInterval paces hostgw.EnsureTapGuestNeighbors. Far slower
// than radv's ticker: the kernel refreshes a resolved neighbor from the guest's
// own advertisements, so a pass only has to notice one that aged out or a guest
// that just booted, and each pass costs a solicit per unresolved guest.
var tapNeighReconcileInterval = 30 * time.Second

// sidecarReturnReconcileInterval paces ensureSidecarReturnPath. Slower than
// radv's ticker because each pass walks this node's network namespaces, and
// faster than the credential refresh because what it installs points at a pod:
// an Envoy restart changes the host-side veth and MAC the return route names,
// and the sidecar creates the VRF holding the gateway address some time after
// the pod is scheduled.
var sidecarReturnReconcileInterval = 30 * time.Second

// egressRouteRefreshInterval paces the egress_route_table re-resolution sweep.
// Each entry's outgoing link and L2 addresses are resolved once by whoever
// wrote it and never again, and the writer for a tenant VRF's route toward an
// egress shard is a CNI plugin process that exited long ago. Fast enough that a
// node attaching pods before BGP converges heals in well under a minute,
// slow enough that a converged node re-resolves a handful of entries twice a
// minute and no more.
var egressRouteRefreshInterval = 30 * time.Second

// ebpfHealthServiceName is the gRPC health service name reporting the eBPF
// uSID datapath's status, kept separate from the overall ("") always-serving
// status so a datapath degradation is neither conflated with nor masked by this
// container's unrelated responsibilities.
const ebpfHealthServiceName = "ebpf-datapath"

var (
	// Host paths, configurable for testing
	HostBinDir             = "/host/opt/cni/bin"
	HostConflist           = "/host/etc/cni/net.d/10-galactic.conflist"
	HostEtcDir             = "/host/var/lib/galactic"
	SADir                  = "/var/run/secrets/kubernetes.io/serviceaccount"
	SourceVethBinary       = "/galactic-veth"
	SourceTapBinary        = "/galactic-tap"
	SourceIPAMBinary       = "/galactic-ipam"
	SourceBGPBinary        = "/galactic-bgp"
	SourceRouteBinary      = "/galactic-route"
	SourceHostDeviceBinary = "/host-device"
)

// atomicWriteFile writes data to destPath atomically.
func atomicWriteFile(destPath string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(destPath)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write to temp file: %w", err)
	}
	if err := tmpFile.Chmod(mode); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, destPath); err != nil {
		return fmt.Errorf("rename temp file to %q: %w", destPath, err)
	}
	return nil
}

// atomicCopyFile streams the file at srcPath to destPath atomically, creating
// it with mode. It streams rather than buffering the whole source, since the
// binaries copied here run to tens of megabytes and the installer has a tight
// memory limit.
func atomicCopyFile(srcPath, destPath string, mode os.FileMode) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", srcPath, err)
	}
	defer func() {
		_ = src.Close()
	}()

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(destPath)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := io.Copy(tmpFile, src); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("copy to temp file: %w", err)
	}
	if err := tmpFile.Chmod(mode); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, destPath); err != nil {
		return fmt.Errorf("rename temp file to %q: %w", destPath, err)
	}
	return nil
}

var scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	// Registered for the BGPRouter and BGPVRFInstance lists the eBPF map
	// sweeps make. The client is shared with Bootstrap's plain Node lookup,
	// which does not need it, but must know every kind either caller lists.
	_ = bgpv1alpha1.AddToScheme(scheme)
}

var newK8sClientFn = func() (client.Client, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %w", err)
	}
	return client.New(restConfig, client.Options{Scheme: scheme})
}

// addrListFn can be overridden in tests to mock netlink interface addresses.
var addrListFn = func(family int) ([]netlink.Addr, error) {
	return netlink.AddrList(nil, family)
}

// ebpfStartFn loads, pins, and attaches the eBPF uSID datapath, then keeps its
// resolved interface set re-evaluated against netlink link and route events for
// the life of ctx. pinDir is the bpffs directory to pin into.
//
// It is a package-level override point so tests can exercise Run's wiring
// without root, a kernel BPF stack, or a live interface. The returned io.Closer
// is the loaded objects; Run holds it for the process lifetime and closes it on
// shutdown, which does not disrupt already-attached forwarding. Canceling ctx
// stops the watch loop but does not close the object.
//
// The returned *attach.Watcher is Run's handle on that watch loop, so a failed
// health check can nudge an out-of-band reconcile and a watch loop that has
// died is itself reported unhealthy.
var ebpfStartFn = func(ctx context.Context, pinDir string) (io.Closer, []string, *attach.Watcher, error) {
	return attach.StartWatching(ctx, pinDir)
}

// resolveLogLevel reads GALACTIC_CNI_LOG_LEVEL and returns a validated level
// string. Unrecognized values fall back to config.DefaultLogLevel ("info").
func resolveLogLevel() string {
	return config.NormalizeLogLevel(os.Getenv(config.EnvLogLevel))
}

// resolveEgressShardSIDs reads the fabric-wide egress shard membership list
// from the environment. An unset or empty value means no shard is configured
// yet and is written into the conflist verbatim, with no default substituted.
func resolveEgressShardSIDs() string {
	return os.Getenv(config.EnvCNIEgressShardSIDs)
}

// resolveNAT64Prefix reads the fabric-wide NAT64 prefix from the environment.
// Empty means this fabric has no NAT64, and is written through verbatim for the
// same reason the shard list is.
func resolveNAT64Prefix() string {
	return os.Getenv(config.EnvCNINAT64Prefix)
}

// resolveEBPFInterfaces resolves the eBPF datapath's interface list, from the
// environment override if set and auto-detected from the default IPv6 route
// otherwise, and joins it for storage in the static conflist. Resolving it here,
// in this container's real pod environment, saves every per-pod CNI invocation
// from repeating an auto-detection that is less reliable there.
//
// A resolution failure, such as no default IPv6 route and no override, is not
// fatal: it writes an empty string, the same "not yet known, fall back to your
// own detection" state the field already has, and self-heals the next time this
// container runs with a converged route.
func resolveEBPFInterfaces() string {
	names, err := attach.ResolveInterfaces()
	if err != nil {
		slog.Warn("Could not resolve eBPF datapath interface(s) for the static conflist; "+
			"CNI plugin invocations will fall back to their own auto-detection until this succeeds",
			"err", err)
		return ""
	}
	return strings.Join(names, ",")
}

// Bootstrap runs the CNI installation init container tasks: it copies the
// binaries to the host, performs a one-shot dual-stack node identity check, and
// templates the static conflist and initial kubeconfig.
func Bootstrap(ctx context.Context, nodeName string) error {
	if nodeName == "" {
		return errors.New("node name is required (or set GALACTIC_CNI_NODE_NAME)")
	}

	slog.Info("Starting CNI installer bootstrap", "nodeName", nodeName)

	// Copy the CNI plugin chain's binaries to the host. Every binary in the
	// chain ships in this image and is staged by this one init container,
	// whichever master plugin a node's workloads use.
	if err := os.MkdirAll(HostBinDir, 0755); err != nil {
		return fmt.Errorf("create host CNI bin dir: %w", err)
	}
	if err := atomicCopyFile(SourceVethBinary, filepath.Join(HostBinDir, "galactic-veth"), 0755); err != nil {
		return fmt.Errorf("copy galactic-veth binary: %w", err)
	}
	if err := atomicCopyFile(SourceTapBinary, filepath.Join(HostBinDir, "galactic-tap"), 0755); err != nil {
		return fmt.Errorf("copy galactic-tap binary: %w", err)
	}
	if err := atomicCopyFile(SourceIPAMBinary, filepath.Join(HostBinDir, "galactic-ipam"), 0755); err != nil {
		return fmt.Errorf("copy galactic-ipam binary: %w", err)
	}
	if err := atomicCopyFile(SourceBGPBinary, filepath.Join(HostBinDir, "galactic-bgp"), 0755); err != nil {
		return fmt.Errorf("copy galactic-bgp binary: %w", err)
	}
	if err := atomicCopyFile(SourceRouteBinary, filepath.Join(HostBinDir, "galactic-route"), 0755); err != nil {
		return fmt.Errorf("copy galactic-route binary: %w", err)
	}
	if err := atomicCopyFile(SourceHostDeviceBinary, filepath.Join(HostBinDir, "host-device"), 0755); err != nil {
		return fmt.Errorf("copy host-device binary: %w", err)
	}
	slog.Info("Binaries copied successfully to host")

	// 2. Perform one-shot dual-stack node identity check
	k8sClient, err := newK8sClientFn()
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}

	var node corev1.Node
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: nodeName}, &node); err != nil {
		return fmt.Errorf("get Node %q from API server: %w", nodeName, err)
	}

	// Fetch all local interface IP addresses (both IPv4 and IPv6)
	addrsV4, err := addrListFn(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list local IPv4 addresses: %w", err)
	}
	addrsV6, err := addrListFn(netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("list local IPv6 addresses: %w", err)
	}

	var matched bool
	var matchedLocalIP string
	for _, addr := range append(addrsV4, addrsV6...) {
		localIP := addr.IP
		for _, nodeAddr := range node.Status.Addresses {
			if nodeAddr.Type == corev1.NodeInternalIP {
				nodeIP := net.ParseIP(nodeAddr.Address)
				if nodeIP != nil && localIP.Equal(nodeIP) {
					matched = true
					matchedLocalIP = localIP.String()
					break
				}
			}
		}
		if matched {
			break
		}
	}
	if !matched {
		var nodeIPs []string
		for _, nodeAddr := range node.Status.Addresses {
			if nodeAddr.Type == corev1.NodeInternalIP {
				nodeIPs = append(nodeIPs, nodeAddr.Address)
			}
		}
		return fmt.Errorf(
			"node identity check failed: none of the local interface addresses match the Node's InternalIP addresses %v",
			nodeIPs,
		)
	}
	slog.Info("Node identity validation passed", "matchedIP", matchedLocalIP)

	// 3. Write ca.crt and initial kubeconfig under persistent host storage /var/lib/galactic
	if err := os.MkdirAll(HostEtcDir, 0755); err != nil {
		return fmt.Errorf("create host CNI credentials dir: %w", err)
	}
	caSrc := filepath.Join(SADir, "ca.crt")
	if _, err := os.Stat(caSrc); err == nil {
		if err := atomicCopyFile(caSrc, filepath.Join(HostEtcDir, "ca.crt"), 0644); err != nil {
			return fmt.Errorf("copy ca.crt: %w", err)
		}
	}

	if err := writeKubeconfig(); err != nil {
		return fmt.Errorf("write initial kubeconfig: %w", err)
	}

	// 4. Write static conflist to /host/etc/cni/net.d/10-galactic.conflist
	logLevel := resolveLogLevel()
	egressShardSIDs := resolveEgressShardSIDs()
	nat64Prefix := resolveNAT64Prefix()
	ebpfInterfaces := resolveEBPFInterfaces()
	danDir := os.Getenv(config.EnvCNIDANDir)
	conflistContent := fmt.Sprintf(`{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "plugins": [
    {
      "type": "galactic-cni",
      "node_name": %q,
      "kubeconfig": %q,
      "namespace": %q,
      "log_file": %q,
      "log_level": %q,
      "egress_shard_sids": %q,
      "nat64_prefix": %q,
      "ebpf_interfaces": %q,
      "dan_dir": %q
    }
  ]
}
`, nodeName, config.DefaultKubeconfig, config.DefaultNamespace, config.DefaultLogFile, logLevel,
		egressShardSIDs, nat64Prefix, ebpfInterfaces, danDir)

	if err := atomicWriteFile(HostConflist, []byte(conflistContent), 0644); err != nil {
		return fmt.Errorf("write conflist file: %w", err)
	}
	slog.Info("Static CNI conflist written successfully")

	return nil
}

// writeKubeconfig writes the kubeconfig file using the ServiceAccount token.
func writeKubeconfig() error {
	tokenBytes, err := os.ReadFile(filepath.Join(SADir, "token"))
	if err != nil {
		return fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	apiHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	if strings.Contains(apiHost, ":") {
		apiHost = "[" + apiHost + "]"
	}
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")

	kubeconfigTemplate := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
  - name: galactic
    cluster:
      server: https://%s:%s
      certificate-authority: /var/lib/galactic/ca.crt
contexts:
  - name: galactic
    context:
      cluster: galactic
      user: galactic-cni
current-context: galactic
users:
  - name: galactic-cni
    user:
      token: %s
`, apiHost, apiPort, token)

	kubeconfigPath := filepath.Join(HostEtcDir, "kubeconfig")
	return atomicWriteFile(kubeconfigPath, []byte(kubeconfigTemplate), 0600)
}

// ebpfDatapathState bundles what startEBPFDatapath resolves for Run to use
// afterward: health polling, metrics, and the GC sweeps.
type ebpfDatapathState struct {
	objs      *prog.UsidObjects
	ifaces    []string
	watcher   *attach.Watcher
	k8sClient client.Client
	namespace string
	nodeName  string

	// egressShardSIDs is the configured egress shard list, in preference
	// order, from the same host conflist CNI ADD reads it from. The egress
	// route sweep uses it to keep each VRF on the first reachable shard.
	egressShardSIDs []net.IP
}

// startEBPFDatapath loads and attaches the eBPF datapath and returns the state
// Run needs to poll and sweep it, plus the closer Run holds for the process
// lifetime. Split out of Run to keep it within the gocyclo budget.
//
// A failure, including a failed kernel preflight check, is fatal. This is the
// only forwarding path, so there is no partial or legacy state to fall back
// to.
func startEBPFDatapath(ctx context.Context, m *metrics.Metrics) (ebpfDatapathState, io.Closer, error) {
	attach.SetHooks(m.Events.Hooks())

	datapath, ifaces, watcher, err := ebpfStartFn(ctx, attach.PinDir)
	if err != nil {
		return ebpfDatapathState{}, nil, fmt.Errorf("start eBPF uSID datapath: %w", err)
	}
	slog.Info("eBPF uSID datapath loaded, pinned, and attached", "interfaces", ifaces, "pinDir", attach.PinDir)

	state := ebpfDatapathState{ifaces: ifaces, watcher: watcher}

	// The closer is the loaded objects in production. A test fake stands in a
	// plain mock closer, which correctly leaves the metrics, health, and GC
	// wiring below inert.
	if objs, ok := datapath.(*prog.UsidObjects); ok {
		state.objs = objs
		if err := m.RegisterDatapathCollector(objs); err != nil {
			slog.Warn("Failed to register eBPF datapath metrics collector", "err", err)
		}
	}

	// Best-effort setup for the eBPF map GC sweeps. Unlike the datapath start
	// above, a failure is not fatal: GC is background maintenance, not a
	// requirement for forwarding, so the sweep ticker just stays inert until
	// the next restart.
	hostConf, err := hostconf.Load(HostConflist, hostconf.PluginType)
	if err != nil {
		slog.Warn("eBPF vrf_table GC sweep and egress shard re-selection disabled: failed to load host conf",
			"err", err)
		return state, datapath, nil
	}
	state.egressShardSIDs = loadEgressShardSIDs(hostConf.EgressShardSIDs)
	if k8sClient, err := newK8sClientFn(); err != nil {
		slog.Warn("eBPF vrf_table GC sweep disabled: failed to create k8s client", "err", err)
	} else {
		state.k8sClient, state.namespace, state.nodeName = k8sClient, hostConf.Namespace, hostConf.NodeName
	}

	return state, datapath, nil
}

// loadEgressShardSIDs parses the host conflist's egress shard list for the
// egress route sweep. A list that fails to parse also fails every ADD on this
// node, which is where it gets reported; the sweep just keeps each entry's
// shard as ADD wrote it.
func loadEgressShardSIDs(raw string) []net.IP {
	sids, err := config.ParseEgressShardSIDs(raw)
	if err != nil {
		slog.Warn("Egress shard re-selection disabled: failed to parse egress shard list", "err", err)
		return nil
	}
	return sids
}

// cleanupOldBinaryWrapper removes the stale .bin wrapper file. Split out of
// Run's select to keep it within the gocyclo budget.
func cleanupOldBinaryWrapper() {
	oldBinPath := filepath.Join(HostBinDir, "galactic-cni.bin")
	if _, err := os.Stat(oldBinPath); err == nil {
		if err := os.Remove(oldBinPath); err != nil {
			slog.Warn("Failed to clean up old CNI binary wrapper", "path", oldBinPath, "err", err)
		} else {
			slog.Info("Stale CNI binary wrapper cleaned up successfully", "path", oldBinPath)
		}
	}
}

// startTapNeighborSweep runs one hostgw.EnsureTapGuestNeighbors pass off Run's
// goroutine, so a slow pass cannot hold the select loop.
//
// sem is a size-1 semaphore: a tick arriving while a pass is still in flight is
// dropped rather than queued, so freshness suffers instead of a backlog
// building.
func startTapNeighborSweep(sem chan struct{}) {
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			if resolved, pending := hostgw.EnsureTapGuestNeighbors(); pending > 0 {
				slog.Info("Tap guest neighbor resolution incomplete; will retry",
					"resolved", resolved, "pending", pending)
			}
		}()
	default:
	}
}

// startSidecarReturnSweep runs one ensureSidecarReturnPath pass off Run's
// goroutine. A pass enters every network namespace on this node, so on a node
// running a large Envoy fleet it would otherwise starve the credential refresh,
// GC sweeps, and health check.
//
// sem is a size-1 semaphore, dropping a tick rather than queueing it when the
// previous pass is still running.
func startSidecarReturnSweep(ctx context.Context, sem chan struct{}, st ebpfDatapathState) {
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			reconcileSidecarReturnPath(ctx, st)
		}()
	default:
	}
}

// startEgressRouteRefreshSweep runs one egress_route_table re-resolution pass,
// which also moves each VRF onto the first reachable of shardSIDs, off Run's
// goroutine, for the same reason the two sweeps above run off it: an
// entry whose next hop has no neighbor costs a solicit plus a poll, so a node
// that has lost its fabric uplink would hold the select loop past the next tick
// and starve the credential refresh, GC sweeps, and health check with it.
//
// sem is a size-1 semaphore, dropping a tick rather than queueing it when the
// previous pass is still running.
//
// A missing pinned map is not an error worth logging on every tick: it means
// the datapath is not loaded on this node, and the sweep has nothing to do.
//
// The ingress sidecar shares these pinned maps from inside a pod network
// namespace, so the sweep first reads back which VRF routing tables that writer
// owns and passes them to Refresh to be left alone. Failing to read that set
// skips the whole sweep: a sweep that cannot tell the two writers apart
// rewrites the sidecar's entries to host interfaces the pod does not have, and
// a stale next hop is recoverable where that is not.
func startEgressRouteRefreshSweep(sem chan struct{}, shardSIDs []net.IP) {
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(attach.PinDir)
			if err != nil {
				return
			}
			defer func() { _ = closer.Close() }()

			registry, registryCloser, err := usidmap.OpenPinnedRegistry(attach.PinDir)
			if err != nil {
				return
			}
			defer func() { _ = registryCloser.Close() }()

			foreignTableIDs, err := egressroutemap.SidecarOwnedTableIDs(registry.VRF)
			if err != nil {
				slog.Error("egress_route_table refresh sweep skipped: could not resolve entry ownership", "err", err)
				return
			}

			result, err := table.Refresh(foreignTableIDs, shardSIDs)
			if err != nil {
				slog.Error("egress_route_table refresh sweep failed", "err", err,
					"scanned", result.Scanned, "refreshed", result.Refreshed)
				return
			}
			if result.Refreshed > 0 || result.Unresolved > 0 {
				slog.Info("egress_route_table refresh sweep complete",
					"scanned", result.Scanned, "refreshed", result.Refreshed, "reselected", result.Reselected,
					"unresolved", result.Unresolved, "skipped", result.Skipped)
			}
		}()
	default:
	}
}

// radvActorSet tracks the running radv.RunActor goroutines, keyed by host
// interface name, plus the retry state of attachments not currently served. It
// is Run's local state, reconciled against the recorded attachments on every
// tick. The zero value is ready to use.
//
// cancel and pending are touched only from Run's own goroutine and are
// deliberately unguarded, since single ownership is simpler than synchronizing
// with the actor goroutines. Those goroutines report a failed startup on failed
// instead, which Run's select drains on its own turn.
type radvActorSet struct {
	cancel  map[string]context.CancelFunc
	pending map[string]*radvPending
	failed  chan radvActorFailure
	wg      sync.WaitGroup
}

// radvPending is the retry state of one recorded attachment that has no running
// actor, or whose host interface has gone missing.
type radvPending struct {
	// failures counts consecutive failed starts, and retryAt is the earliest
	// time the next one may run. Both reset whenever the interface loses
	// carrier, so a guest that restarts gets a fresh, fast retry cycle.
	failures int
	retryAt  time.Time
	// noCarrier records that the last reconcile found the interface without
	// carrier, so the wait is logged once rather than on every tick.
	noCarrier bool
	// missingSince is when a reconcile first found the interface absent, zero
	// while it exists.
	missingSince time.Time
}

// radvActorFailure is an actor goroutine's report that radv.RunActor could not
// start.
type radvActorFailure struct {
	iface string
	err   error
}

// radvStaleRecordGrace is how long a recorded attachment's host interface must
// stay missing before its record is removed. DEL removes the record before the
// tap, and ADD creates the tap before the record, so a missing interface with a
// record is always stale; the grace only keeps the removal from racing a DEL
// that is still running.
var radvStaleRecordGrace = 30 * time.Second

// radvMaxRetryBackoff caps the delay between failed starts on an interface that
// has carrier. Failures double the delay from radvReconcileInterval upward.
var radvMaxRetryBackoff = 5 * time.Minute

// radvWarnAfterFailures is the consecutive failed start that is logged as a
// warning. Earlier failures are routine, since a freshly attached guest's
// link-local address is still completing duplicate address detection, and later
// ones would repeat the same warning for as long as the failure lasts.
const radvWarnAfterFailures = 3

// radvNow is the clock reconcileRadvActors reads. A var so tests can move it.
var radvNow = time.Now

// radvLinkState reports whether iface exists and whether it has carrier. A tap
// has carrier only while a VMM holds it open, and until then the kernel never
// assigns it a link-local address, so an actor started on it cannot open its
// NDP connection. A var so tests can fake the kernel.
var radvLinkState = func(iface string) (exists, carrier bool, err error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return false, false, nil
		}
		return false, false, err
	}
	return true, link.Attrs().RawFlags&unix.IFF_LOWER_UP != 0, nil
}

// reconcileRadvActors starts one radv.RunActor per recorded tap attachment that
// is ready to be served and cancels one for each attachment that has
// disappeared. It is also called once before Run's loop starts, so attachments
// already recorded when this daemon starts are served immediately.
//
// An attachment is ready once its host interface has carrier and any backoff
// from earlier failed starts has elapsed. A tap without carrier belongs to a
// guest whose VMM has not opened it, whether because it is still booting or
// because it never will, so it is waited on quietly rather than retried. A
// record whose host interface stays missing past radvStaleRecordGrace is
// removed, since nothing else would ever remove it once its DEL has been missed.
//
// A listing failure is never fatal. Resending and soliciting is best-effort
// maintenance for already-attached guests, so running actors are left alone
// until a tick succeeds. An actor that fails during startup reports itself on
// actors.failed rather than leaving its map entry stuck as running.
func reconcileRadvActors(ctx context.Context, actors *radvActorSet) {
	records, err := radv.ListAttachments(radv.DefaultStateDir)
	if err != nil {
		slog.Warn("Failed to list router advertisement attachments", "err", err)
		return
	}

	if actors.cancel == nil {
		actors.cancel = make(map[string]context.CancelFunc)
		actors.pending = make(map[string]*radvPending)
		// Buffered well past any realistic node's attachment count, so a run
		// of startup failures cannot block an actor goroutine on this send.
		// The goroutine sends non-blocking anyway, so a full channel only
		// delays a retry.
		actors.failed = make(chan radvActorFailure, 256)
	}

	now := radvNow()
	seen := make(map[string]struct{}, len(records))
	for _, r := range records {
		exists, carrier, err := radvLinkState(r.HostInterface)
		if err != nil {
			// Unknown, so leave the attachment as it is until a tick can tell.
			slog.Debug("Failed to look up router advertisement interface",
				"err", err, "hostInterface", r.HostInterface)
			seen[r.HostInterface] = struct{}{}
			continue
		}
		p := radvPendingFor(actors, r.HostInterface)
		if !exists {
			if !removeStaleRadvRecord(p, r.HostInterface, now) {
				seen[r.HostInterface] = struct{}{}
			}
			continue
		}
		p.missingSince = time.Time{}
		seen[r.HostInterface] = struct{}{}

		if _, running := actors.cancel[r.HostInterface]; running {
			continue
		}
		if !radvReadyToStart(p, r.HostInterface, carrier, now) {
			continue
		}

		actorCtx, cancel := context.WithCancel(ctx)
		actors.cancel[r.HostInterface] = cancel
		actors.wg.Add(1)
		go func(iface string, mtu int) {
			defer actors.wg.Done()
			if err := radv.RunActor(actorCtx, iface, mtu); err != nil {
				select {
				case actors.failed <- radvActorFailure{iface: iface, err: err}:
				default:
					slog.Warn("Router advertisement failed-actor channel full, retry may be delayed",
						"err", err, "hostInterface", iface)
				}
			}
		}(r.HostInterface, r.MTU)
	}

	for iface, cancel := range actors.cancel {
		if _, ok := seen[iface]; ok {
			continue
		}
		cancel()
		delete(actors.cancel, iface)
	}
	for iface := range actors.pending {
		if _, ok := seen[iface]; !ok {
			delete(actors.pending, iface)
		}
	}
}

// removeStaleRadvRecord handles a record whose host interface is missing. It
// notes when the interface was first found missing, and once it has stayed
// missing past radvStaleRecordGrace removes the record, reporting true.
func removeStaleRadvRecord(p *radvPending, iface string, now time.Time) bool {
	if p.missingSince.IsZero() {
		p.missingSince = now
		return false
	}
	if now.Sub(p.missingSince) < radvStaleRecordGrace {
		return false
	}
	// Only a record written before the interface was first found missing is
	// stale. A newer one comes from an ADD that is creating the interface again.
	removed, err := radv.RemoveStaleAttachment(radv.DefaultStateDir, iface, p.missingSince)
	if err != nil {
		slog.Warn("Failed to remove router advertisement record for missing interface",
			"err", err, "hostInterface", iface)
		return false
	}
	if !removed {
		p.missingSince = time.Time{}
		return false
	}
	slog.Info("Removed router advertisement record for missing interface",
		"hostInterface", iface, "missingFor", now.Sub(p.missingSince).Round(time.Second))
	return true
}

// radvReadyToStart reports whether an actor should be started on an existing
// interface now: it has carrier and any backoff from earlier failures has
// elapsed. Losing carrier resets the backoff, so a guest that restarts is
// served as soon as its VMM opens the tap again.
func radvReadyToStart(p *radvPending, iface string, carrier bool, now time.Time) bool {
	if !carrier {
		if !p.noCarrier {
			slog.Debug("Router advertisement interface has no carrier, waiting for its guest",
				"hostInterface", iface)
		}
		p.noCarrier = true
		p.failures = 0
		p.retryAt = time.Time{}
		return false
	}
	p.noCarrier = false

	return !now.Before(p.retryAt)
}

// radvPendingFor returns iface's retry state, creating it on first use.
func radvPendingFor(actors *radvActorSet, iface string) *radvPending {
	p, ok := actors.pending[iface]
	if !ok {
		p = &radvPending{}
		actors.pending[iface] = p
	}
	return p
}

// radvActorFailed clears the map entry for an actor that could not start, so a
// later reconcile sees the attachment as unserved and retries it once its
// backoff has elapsed. Without it, reconcileRadvActors would stay convinced the
// actor is running. A report for an attachment that is already gone is a safe
// no-op.
//
// Each attempt derives its context from one that lives as long as the process.
// Only cancelling detaches the derived context. Deleting the entry alone leaves
// it attached, so a retry loop grows this daemon's memory without bound.
func radvActorFailed(actors *radvActorSet, failure radvActorFailure) {
	cancel, ok := actors.cancel[failure.iface]
	if !ok {
		return
	}
	cancel()
	delete(actors.cancel, failure.iface)

	p := radvPendingFor(actors, failure.iface)
	p.failures++
	backoff := radvReconcileInterval << min(p.failures-1, 16)
	if backoff <= 0 || backoff > radvMaxRetryBackoff {
		backoff = radvMaxRetryBackoff
	}
	p.retryAt = radvNow().Add(backoff)

	if p.failures == radvWarnAfterFailures {
		slog.Warn("Router advertisement actor keeps failing to start, backing off",
			"err", failure.err, "hostInterface", failure.iface, "failures", p.failures, "maxBackoff", radvMaxRetryBackoff)
		return
	}
	slog.Debug("Router advertisement actor failed to start, will retry",
		"err", failure.err, "hostInterface", failure.iface, "failures", p.failures, "retryIn", backoff)
}

// Run executes the CNI installer main container tasks:
//  1. Loads, pins, and attaches the eBPF uSID datapath and keeps its attachment
//     set re-evaluated against netlink events for the life of ctx. This is the
//     only forwarding path, so a failure here, including a failed kernel
//     preflight check, is fatal. Once running, the re-attachment loop logs and
//     retries its own failures instead of propagating them back into Run.
//     Load, attach, and detach events are counted, and live map state is
//     exposed on the same metrics endpoint.
//  2. Serves Prometheus metrics on metricsPort.
//  3. Rotates logs periodically.
//  4. Refreshes the ServiceAccount token on a ticker.
//  5. Cleans up the stale .bin wrapper file.
//  6. Serves gRPC health on grpcHealthPort. The overall ("") service always
//     reports SERVING once the process is up, since credential refresh and log
//     rotation have no meaningful unhealthy state; a separate
//     ebpfHealthServiceName service reports the polled result of attach.Health.
//  7. Sweeps stale vrf_table entries and reconciles nptv6_table entries on a
//     ticker. Both run here rather than in galactic-router's GC controller
//     because the pinned maps exist only inside this container.
//  8. Runs one radv.RunActor per recorded tap attachment, reconciled on a short
//     ticker. Each actor resends Router Advertisements on a jittered schedule
//     and replies to that guest's solicitations. This runs here, not from
//     galactic-tap's cmdAdd, because a guest's boot outlives that short-lived
//     process. It is independent of the eBPF datapath and runs regardless.
func Run(ctx context.Context, grpcHealthPort, metricsPort int) error {
	slog.Info("Starting CNI installer run daemon", "grpcHealthPort", grpcHealthPort, "metricsPort", metricsPort)

	m := metrics.New()

	ebpfState, datapath, err := startEBPFDatapath(ctx, m)
	if err != nil {
		return err
	}
	if datapath != nil {
		defer func() {
			if err := datapath.Close(); err != nil {
				slog.Warn("Failed to close eBPF uSID datapath objects", "err", err)
			}
		}()
	}

	// This node's uSID locator must be locally resolvable before any same-node
	// SRv6 egress route can be registered. Non-fatal and retried below, since
	// the BGPRouter carrying the locator may not exist yet.
	reconcileLocatorLocalRoute(ctx, ebpfState)

	// Serve Prometheus metrics at the conventional /metrics scrape path.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", m.Handler())
	metricsSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", metricsPort),
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Metrics server exited with error", "err", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("Failed to gracefully shut down metrics server", "err", err)
		}
	}()

	// Start gRPC health check server
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", grpcHealthPort))
	if err != nil {
		return fmt.Errorf("listen on gRPC health port %d: %w", grpcHealthPort, err)
	}
	grpcSrv := grpc.NewServer()
	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	if ebpfState.objs != nil {
		healthSrv.SetServingStatus(ebpfHealthServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	}

	go func() {
		if err := grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			slog.Error("gRPC health server exited with error", "err", err)
		}
	}()

	defer func() {
		grpcSrv.GracefulStop()
	}()

	// Tickers
	refreshTicker := time.NewTicker(300 * time.Second)
	defer refreshTicker.Stop()

	// Deferred old binary cleanup after 2 minutes
	cleanupTimer := time.NewTimer(2 * time.Minute)
	defer cleanupTimer.Stop()

	// Health poll, meaningful only once the datapath is running; otherwise it
	// fires harmlessly and does nothing.
	ebpfHealthTicker := time.NewTicker(ebpfHealthCheckInterval)
	defer ebpfHealthTicker.Stop()
	var ebpfLastHealthy = true // matches the initial SetServingStatus(SERVING) above

	// eBPF map GC sweep, meaningful only once the Kubernetes client is set;
	// otherwise it fires harmlessly, like the health poll above.
	ebpfGCSweepTicker := time.NewTicker(ebpfGCSweepInterval)
	defer ebpfGCSweepTicker.Stop()

	// Router Advertisement serving for tap-attached guests, independent of the
	// eBPF datapath. One actor per recorded attachment handles both the
	// periodic resend and solicitation replies. Reconciled once here as well
	// as on the ticker, so attachments already recorded at startup do not wait
	// out the first tick.
	radvActors := &radvActorSet{}
	reconcileRadvActors(ctx, radvActors)
	defer radvActors.wg.Wait()

	radvReconcileTicker := time.NewTicker(radvReconcileInterval)
	defer radvReconcileTicker.Stop()

	tapNeighTicker := time.NewTicker(tapNeighReconcileInterval)
	defer tapNeighTicker.Stop()

	sidecarReturnTicker := time.NewTicker(sidecarReturnReconcileInterval)
	defer sidecarReturnTicker.Stop()
	// Size-1 semaphore, so at most one sweep runs at a time and a tick
	// arriving during one is dropped instead of piling up behind it.
	tapNeighSem := make(chan struct{}, 1)
	sidecarReturnSem := make(chan struct{}, 1)

	egressRouteRefreshTicker := time.NewTicker(egressRouteRefreshInterval)
	defer egressRouteRefreshTicker.Stop()
	egressRouteRefreshSem := make(chan struct{}, 1)

	for {
		select {
		case <-ctx.Done():
			slog.Info("CNI installer run daemon shutting down")
			return nil

		case <-cleanupTimer.C:
			cleanupOldBinaryWrapper()

		case <-refreshTicker.C:
			// Refresh kubeconfig ServiceAccount token
			slog.Info("Refreshing host kubeconfig credentials")
			if err := writeKubeconfig(); err != nil {
				slog.Error("Failed to refresh host kubeconfig credentials", "err", err)
			}

			// Log rotation check
			logFileHostPath := getLogFileHostPath()
			if logFileHostPath != "" {
				rotateLogFile(logFileHostPath)
			}

			// Re-assert the locator local route: this picks up a BGPRouter
			// created after startup and restores the route if it was
			// flushed.
			reconcileLocatorLocalRoute(ctx, ebpfState)

		case <-ebpfHealthTicker.C:
			reportEBPFHealth(ebpfState, healthSrv, &ebpfLastHealthy)

		case <-ebpfGCSweepTicker.C:
			if ebpfState.k8sClient == nil {
				continue
			}
			result := gc.SweepEBPFVRFTable(ctx, ebpfState.k8sClient, ebpfState.namespace, ebpfState.nodeName, attach.PinDir)
			logEBPFVRFSweepResult(result)

			// nptv6_table's sweep is its map's only writer, so it registers
			// every live mapping as well as reaping stale ones.
			nptv6Result := gc.SweepEBPFNPTv6Table(
				ctx, ebpfState.k8sClient, ebpfState.namespace, ebpfState.nodeName, attach.PinDir)
			if nptv6Result.EBPFNPTv6EntriesRemoved > 0 || nptv6Result.Errors > 0 {
				slog.Info("eBPF nptv6_table GC sweep complete",
					"removed", nptv6Result.EBPFNPTv6EntriesRemoved, "errors", nptv6Result.Errors)
			}

		case <-radvReconcileTicker.C:
			reconcileRadvActors(ctx, radvActors)

		case <-tapNeighTicker.C:
			// Resolve each tap guest's neighbor entry, without which the
			// datapath's FIB lookup drops every decapsulated packet bound for
			// it. Periodic rather than once at CNI ADD, for the same reason
			// the radv actors run here: a guest's boot outlives the
			// short-lived plugin process, so there is nothing to solicit yet
			// at ADD time.
			//
			// Off this goroutine and on its own slower ticker. Each
			// unresolved guest costs a solicit plus polling, so a node whose
			// guests are down would hold the select loop past the next tick
			// and starve the credential refresh, GC sweeps, and health check
			// with it.
			startTapNeighborSweep(tapNeighSem)

		case <-sidecarReturnTicker.C:
			// Install and re-assert the host side of the ingress sidecar's
			// return path: the routes, neighbors, and uSID map entries a
			// reply encapsulated toward this node's SID needs to reach an
			// Envoy pod's per-VPC sidecar VRF.
			startSidecarReturnSweep(ctx, sidecarReturnSem, ebpfState)

		case <-egressRouteRefreshTicker.C:
			// Re-resolve every egress route's outgoing link and L2 addresses.
			// They are resolved once, when the entry is written, and the
			// writer of a tenant VRF's route toward an egress shard is a CNI
			// plugin process that has since exited -- so an entry resolved
			// before the fabric advertised that shard's SID would otherwise
			// stay wrong for the life of the node. The same pass moves each
			// VRF onto the first reachable shard in the configured order,
			// since the one ADD picked may just have been the first whose
			// route happened to arrive.
			startEgressRouteRefreshSweep(egressRouteRefreshSem, ebpfState.egressShardSIDs)

		case failure := <-radvActors.failed:
			radvActorFailed(radvActors, failure)
		}
	}
}

// reportEBPFHealth polls the datapath's health and republishes it on the gRPC
// health service, logging only on a transition so a persistently healthy or
// persistently broken node does not repeat itself every tick. lastHealthy is
// read and updated in place, being the only state that has to survive between
// ticks. Split out of Run's select to keep it within the gocyclo budget, as
// logEBPFVRFSweepResult below is.
//
// A nil objs means no datapath is loaded on this node, so there is nothing to
// poll and the service keeps whatever status it was given at startup.
func reportEBPFHealth(st ebpfDatapathState, healthSrv *health.Server, lastHealthy *bool) {
	if st.objs == nil {
		return
	}
	h := attach.Handle{Objs: st.objs, Watcher: st.watcher}
	healthErr := h.Healthy()
	healthy := healthErr == nil
	if healthy != *lastHealthy {
		if healthy {
			slog.Info("eBPF uSID datapath health check recovered")
		} else {
			slog.Error("eBPF uSID datapath health check failed", "err", healthErr)
		}
		*lastHealthy = healthy
	}
	status := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if healthy {
		status = grpc_health_v1.HealthCheckResponse_SERVING
	}
	healthSrv.SetServingStatus(ebpfHealthServiceName, status)
}

// logEBPFVRFSweepResult logs one vrf_table sweep result when there is anything
// worth logging. Split out of Run's select to keep it within the gocyclo
// budget.
func logEBPFVRFSweepResult(result gc.CleanupResult) {
	if result.EBPFVRFEntriesRemoved > 0 || result.EBPFVRFEntriesRegistered > 0 || result.Errors > 0 {
		slog.Info("eBPF vrf_table GC sweep complete",
			"removed", result.EBPFVRFEntriesRemoved, "registered", result.EBPFVRFEntriesRegistered,
			"errors", result.Errors)
	}
}

// getLogFileHostPath resolves the CNI log file path from HostConflist
// and prefixes it with "/host" since the container views host filesystem via /host mount.
func getLogFileHostPath() string {
	hostConf, err := hostconf.Load(HostConflist, hostconf.PluginType)
	if err != nil || hostConf.LogFile == "" {
		return filepath.Join("/host", config.DefaultLogFile)
	}
	return filepath.Join("/host", hostConf.LogFile)
}

// rotateLogFile rotates the log file if it exceeds 10MB in size.
func rotateLogFile(hostLogPath string) {
	info, err := os.Stat(hostLogPath)
	if err != nil {
		return // file doesn't exist yet, nothing to do
	}
	if info.Size() > 10*1024*1024 { // 10MB
		rotatedPath := hostLogPath + ".1"
		if err := os.Rename(hostLogPath, rotatedPath); err != nil {
			slog.Warn("Failed to rotate log file", "from", hostLogPath, "to", rotatedPath, "err", err)
		} else {
			slog.Info("Rotated log file successfully", "path", hostLogPath)
		}
	}
}
