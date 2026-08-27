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
	"time"

	"github.com/vishvananda/netlink"
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
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/radv"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ebpfHealthCheckInterval controls how often Run polls
// internal/plumbing/ebpf/attach.Health once the eBPF datapath is running.
// A package-level var (not a const) so tests can shrink it, the same
// override pattern internal/plumbing/ebpf/attach/watch.go's
// debounceInterval already uses.
var ebpfHealthCheckInterval = 10 * time.Second

// ebpfGCSweepInterval controls how often Run calls gc.SweepEBPFVRFTable
// once the eBPF datapath is running. A package-level var, same override
// pattern as ebpfHealthCheckInterval above -- matches galactic-router's
// own GC controller's documented default period (docs/agents/
// ARCHITECTURE-ROUTER.md: "ticker-driven, default every 5m").
var ebpfGCSweepInterval = 5 * time.Minute

// radvNextIntervalFn resolves the delay before Run's next Router
// Advertisement resend pass (internal/plumbing/radv.NextInterval — a
// jittered value in [MinRtrAdvInterval, MaxRtrAdvInterval), per RFC 4861
// §6.2.4). A package-level func var, same override pattern as ebpfStartFn/
// addrListFn/newK8sClientFn above, so tests can substitute a short fixed
// delay instead of waiting out a real RFC-sized interval.
var radvNextIntervalFn = radv.NextInterval

// ebpfHealthServiceName is the gRPC health service name (see
// grpc_health_v1.HealthServer) reporting the live status of the eBPF uSID
// datapath specifically, separate from the overall (""), always-serving
// status the credential-refresh/log-rotation loop reports -- so a BPF
// datapath degradation (e.g. something external detaches the tc filter)
// doesn't get conflated with, or masked by, the rest of this container's
// unrelated responsibilities.
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

// atomicCopyFile streams a file from srcPath to destPath atomically. It
// copies via io.Copy rather than reading the whole source into memory
// first, since binaries copied here (e.g. galactic-veth itself) run tens of
// megabytes and the installer runs under a tight memory limit.
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
	// bgpv1alpha1 registration is required for gc.SweepEBPFVRFTable's
	// BGPRouter/BGPVRFInstance List calls (Milestone 7.3) -- newK8sClientFn
	// below is shared with Bootstrap's plain Node lookup, which doesn't
	// need it, but the client itself must know about every kind either
	// caller lists.
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

// ebpfStartFn loads, pins, and attaches the eBPF/TC-BPF uSID datapath, then
// keeps its resolved interface set re-evaluated against netlink link/route
// change events for the life of ctx (design plan
// .local/plan-ebpf-xdp-usid-datapath.md §4.1, §4.4, §5.4; Milestones 3.1
// and 3.2 of .local/implementation-plan-ebpf-xdp-usid-datapath.md). It is a
// package-level override point -- like addrListFn and newK8sClientFn above
// -- so tests can exercise Run's wiring without needing root, a real kernel
// BPF stack, or a live network interface. The returned io.Closer is
// internal/plumbing/ebpf/attach.StartWatching's *prog.UsidObjects in
// production; Run keeps it open for the process lifetime and Closes it on
// shutdown (see the attach package doc comment for why that does not
// disrupt already-attached forwarding). Canceling ctx stops the background
// netlink watch loop but does not, by itself, close the returned object.
//
// The returned *attach.Watcher is Run's handle onto that background watch
// loop -- wired into the ebpfHealthTicker case below so a failed health
// check can nudge an out-of-band reconcile, and a watch loop that has
// died is itself reported as unhealthy (ecv's review of #283).
var ebpfStartFn = func(ctx context.Context, pinDir string) (io.Closer, []string, *attach.Watcher, error) {
	return attach.StartWatching(ctx, pinDir)
}

// resolveLogLevel reads GALACTIC_CNI_LOG_LEVEL and returns a validated level
// string. Unrecognized values fall back to config.DefaultLogLevel ("info").
func resolveLogLevel() string {
	return config.NormalizeLogLevel(os.Getenv(config.EnvLogLevel))
}

// resolveNAT66ShardSIDs reads GALACTIC_CNI_NAT66_SHARD_SIDS, the fabric-wide
// NAT66 shard membership list -- see that env var's own doc comment. Unlike
// resolveLogLevel's fallback, an unset/empty value has no default to
// normalize to: it means no shard is configured yet, and is written into
// the conflist verbatim (empty), not substituted for anything.
func resolveNAT66ShardSIDs() string {
	return os.Getenv(config.EnvCNINAT66ShardSIDs)
}

// resolveEBPFInterfaces resolves the eBPF datapath's own interface list
// (attach.ResolveInterfaces -- env override if GALACTIC_CNI_EBPF_INTERFACES
// is set, auto-detected from the default IPv6 route otherwise) and joins
// it for storage in the static conflist (HostConf.EBPFInterfaces), the
// same "resolve once, in this init container's own real pod env, so a
// per-pod CNI plugin invocation never has to" pattern
// resolveNAT66ShardSIDs's own doc comment describes -- see that field's
// doc comment in internal/hostconf for why a CNI plugin's own
// auto-detection is unreliable in a way this container's isn't.
//
// A resolution failure here (e.g. no default IPv6 route yet and no env
// override) is not fatal to Bootstrap: it writes an empty string, the
// same "not yet known, caller falls back to its own auto-detection"
// state the conflist field already has before this function existed at
// all -- no worse than today, and self-heals whenever install-cni next
// runs (a Bootstrap re-run, e.g. this DaemonSet pod restarting) with a
// converged default route.
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

// Bootstrap runs the CNI installation init container tasks:
// 1. Copies binaries to the host.
// 2. Performs a one-shot dual-stack node identity check.
// 3. Templates the static conflist and initial kubeconfig.
func Bootstrap(ctx context.Context, nodeName string) error {
	if nodeName == "" {
		return errors.New("node name is required (or set GALACTIC_CNI_NODE_NAME)")
	}

	slog.Info("Starting CNI installer bootstrap", "nodeName", nodeName)

	// 1. Copy the CNI plugin chain's binaries to the host. Every binary in
	// the chain ships in this same image and is staged here by this one
	// init container, regardless of which master plugin(s) a given node's
	// workloads actually use.
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
	nat66ShardSIDs := resolveNAT66ShardSIDs()
	ebpfInterfaces := resolveEBPFInterfaces()
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
      "nat66_shard_sids": %q,
      "ebpf_interfaces": %q
    }
  ]
}
`, nodeName, config.DefaultKubeconfig, config.DefaultNamespace, config.DefaultLogFile, logLevel,
		nat66ShardSIDs, ebpfInterfaces)

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
// afterward (health polling, metrics, the GC sweep) -- a named type purely
// to avoid a many-value return signature.
type ebpfDatapathState struct {
	objs      *prog.UsidObjects
	ifaces    []string
	watcher   *attach.Watcher
	k8sClient client.Client
	namespace string
	nodeName  string
}

// startEBPFDatapath is Run's eBPF-datapath startup path, split out solely
// to keep Run's own cyclomatic complexity within golangci-lint's gocyclo
// budget -- behaviorally this is inlined exactly where it used to live. A
// failure here (including a failed kernel preflight check, design plan §6)
// is fatal: Run returns an error rather than falling back to a partial or
// unsafe datapath state -- this is the only forwarding path, there is no
// legacy path to fall back to.
func startEBPFDatapath(ctx context.Context, m *metrics.Metrics) (ebpfDatapathState, io.Closer, error) {
	attach.SetHooks(m.Events.Hooks())

	datapath, ifaces, watcher, err := ebpfStartFn(ctx, attach.PinDir)
	if err != nil {
		return ebpfDatapathState{}, nil, fmt.Errorf("start eBPF uSID datapath: %w", err)
	}
	slog.Info("eBPF uSID datapath loaded, pinned, and attached", "interfaces", ifaces, "pinDir", attach.PinDir)

	state := ebpfDatapathState{ifaces: ifaces, watcher: watcher}

	// ebpfStartFn's io.Closer is *prog.UsidObjects in production (test
	// fakes stand in a plain mock closer, which correctly leaves
	// metrics/health/GC wiring inert below -- see installer_test.go's
	// fakeDatapathCloser).
	if objs, ok := datapath.(*prog.UsidObjects); ok {
		state.objs = objs
		if err := m.RegisterDatapathCollector(objs); err != nil {
			slog.Warn("Failed to register eBPF datapath metrics collector", "err", err)
		}
	}

	// Best-effort setup for the eBPF vrf_table GC sweep (Milestone 7.3).
	// A failure here is not fatal to Run -- unlike the datapath start
	// above, GC is a background maintenance task, not a hard requirement
	// for the datapath to forward traffic -- it just means this node's
	// sweep ticker stays inert until the next restart.
	if hostConf, err := hostconf.Load(HostConflist, hostconf.PluginType); err != nil {
		slog.Warn("eBPF vrf_table GC sweep disabled: failed to load host conf", "err", err)
	} else if k8sClient, err := newK8sClientFn(); err != nil {
		slog.Warn("eBPF vrf_table GC sweep disabled: failed to create k8s client", "err", err)
	} else {
		state.k8sClient, state.namespace, state.nodeName = k8sClient, hostConf.Namespace, hostConf.NodeName
	}

	return state, datapath, nil
}

// cleanupOldBinaryWrapper is Run's cleanupTimer case body, split out solely
// to keep Run's own cyclomatic complexity within golangci-lint's gocyclo
// budget -- same reasoning as startEBPFDatapath above; behaviorally this is
// inlined exactly where it used to live.
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

// resendRouterAdvertisements is Run's radvTicker case body, split out
// solely to keep Run's own cyclomatic complexity within golangci-lint's
// gocyclo budget -- same reasoning as startEBPFDatapath above; behaviorally
// this is inlined exactly where it used to live. A failure here is never
// fatal to Run: resending is best-effort maintenance for already-attached
// VM guests, not a requirement for anything else this process does.
func resendRouterAdvertisements() {
	records, err := radv.ListAttachments(radv.DefaultStateDir)
	if err != nil {
		slog.Warn("Failed to list router advertisement attachments", "err", err)
		return
	}
	for _, r := range records {
		if err := radv.SendRouterAdvertisement(r.HostInterface, r.MTU); err != nil {
			slog.Warn("Failed to resend router advertisement", "err", err, "hostInterface", r.HostInterface)
		}
	}
}

// Run executes the CNI installer main container tasks:
//  1. Loads/pins/attaches the eBPF/TC-BPF uSID datapath and keeps its
//     attachment set re-evaluated against netlink link/route change events
//     for the life of ctx (design plan §4.1, §4.4, §5.4; Milestones 3.1
//     and 3.2 of .local/implementation-plan-ebpf-xdp-usid-datapath.md) --
//     the only forwarding path. A failure here (including a failed kernel
//     preflight check, design plan §6) is fatal: Run returns an error
//     rather than falling back to a partial or unsafe datapath state.
//     Once running, the netlink-driven re-attachment loop logs and retries
//     its own failures rather than propagating them back into Run -- see
//     internal/plumbing/ebpf/attach.Watch's doc comment. Datapath
//     load/attach/detach events are counted via
//     internal/plumbing/ebpf/metrics's EventCounters (Milestone 4), and
//     live vrf_table/locator_table/drop_reasons state is exposed through
//     the same metrics endpoint.
//  2. Serves Prometheus metrics on metricsPort.
//  3. Sets up log rotation periodically.
//  4. Starts a simple ServiceAccount token refresh ticker.
//  5. Deferred cleanup of stale .bin wrapper file.
//  6. Starts the gRPC health check server -- the overall ("") service
//     always reports SERVING once the process is up (credential
//     refresh/log rotation have no meaningful "unhealthy" state of their
//     own); a separate ebpfHealthServiceName ("ebpf-datapath") service is
//     polled on a ticker and reports the live result of
//     internal/plumbing/ebpf/attach.Health -- exit criterion "health check
//     fails correctly when the program is unloaded".
//  7. Periodically sweeps stale vrf_table entries via gc.SweepEBPFVRFTable
//     (design plan §5.3; Milestone 7.3), and registers/reconciles
//     nptv6_table entries via gc.SweepEBPFNPTv6Table. Both run from here,
//     not from galactic-router's existing GC controller
//     (internal/controller/gc_controller.go), because the pinned maps
//     only exist inside this container -- see gc.SweepEBPFVRFTable's own
//     doc comment for the full reasoning.
//  8. Periodically resends an IPv6 Router Advertisement (internal/plumbing/
//     radv) for every tap attachment galactic-tap has recorded
//     (radv.ListAttachments) since the last tick. This runs from here, not
//     from galactic-tap's own cmdAdd, because a VM guest's boot almost
//     always outlives that short-lived process -- see radv's own doc
//     comment for the full reasoning. Unrelated to, and runs regardless of,
//     the eBPF datapath above.
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

	// eBPF datapath health poll -- only meaningful once datapathObjs is
	// set (eBPF datapath enabled and actually running); otherwise this
	// fires harmlessly and does nothing every tick.
	ebpfHealthTicker := time.NewTicker(ebpfHealthCheckInterval)
	defer ebpfHealthTicker.Stop()
	var ebpfLastHealthy = true // matches the initial SetServingStatus(SERVING) above

	// eBPF vrf_table GC sweep (Milestone 7.3) -- only meaningful once
	// gcK8sClient is set (eBPF datapath enabled and host conf/k8s client
	// setup above succeeded); otherwise this fires harmlessly and does
	// nothing every tick, same as the health poll above.
	ebpfGCSweepTicker := time.NewTicker(ebpfGCSweepInterval)
	defer ebpfGCSweepTicker.Stop()

	// Router Advertisement resend for tap-attached VM guests (see
	// internal/plumbing/radv's own doc comment) -- runs regardless of
	// whether the eBPF datapath is enabled, since it has nothing to do with
	// it; harmless no-op ticks whenever no tap attachment currently needs
	// one (internal/plumbing/radv.ListAttachments returns empty). A Timer,
	// not a Ticker: RFC 4861 §6.2.4 requires each send to be spaced by a
	// freshly-jittered interval (radvNextIntervalFn, reset after every
	// fire below) rather than a fixed period, so routers on the same link
	// don't synchronize their RAs into bursts.
	radvTimer := time.NewTimer(radvNextIntervalFn())
	defer radvTimer.Stop()

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

		case <-ebpfHealthTicker.C:
			if ebpfState.objs == nil {
				continue
			}
			h := attach.Handle{Objs: ebpfState.objs, Watcher: ebpfState.watcher}
			healthErr := h.Healthy()
			healthy := healthErr == nil
			if healthy != ebpfLastHealthy {
				if healthy {
					slog.Info("eBPF uSID datapath health check recovered")
				} else {
					slog.Error("eBPF uSID datapath health check failed", "err", healthErr)
				}
				ebpfLastHealthy = healthy
			}
			status := grpc_health_v1.HealthCheckResponse_NOT_SERVING
			if healthy {
				status = grpc_health_v1.HealthCheckResponse_SERVING
			}
			healthSrv.SetServingStatus(ebpfHealthServiceName, status)

		case <-ebpfGCSweepTicker.C:
			if ebpfState.k8sClient == nil {
				continue
			}
			result := gc.SweepEBPFVRFTable(ctx, ebpfState.k8sClient, ebpfState.namespace, ebpfState.nodeName, attach.PinDir)
			if result.EBPFVRFEntriesRemoved > 0 || result.Errors > 0 {
				slog.Info("eBPF vrf_table GC sweep complete",
					"removed", result.EBPFVRFEntriesRemoved, "errors", result.Errors)
			}

			// nptv6_table's own sweep: unlike vrf_table above, this is the
			// map's *only* writer (see gc.SweepEBPFNPTv6Table's own doc
			// comment) -- it both registers every currently-live NPTv6
			// mapping and reconciles stale ones away on every tick.
			nptv6Result := gc.SweepEBPFNPTv6Table(
				ctx, ebpfState.k8sClient, ebpfState.namespace, ebpfState.nodeName, attach.PinDir)
			if nptv6Result.EBPFNPTv6EntriesRemoved > 0 || nptv6Result.Errors > 0 {
				slog.Info("eBPF nptv6_table GC sweep complete",
					"removed", nptv6Result.EBPFNPTv6EntriesRemoved, "errors", nptv6Result.Errors)
			}

		case <-radvTimer.C:
			resendRouterAdvertisements()
			radvTimer.Reset(radvNextIntervalFn())
		}
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
