// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/hostconf"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/radv"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN/CAP_SYS_ADMIN) to load/attach a real BPF " +
			"program; re-run via sudo")
	}
}

func TestResolveLogLevel(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{"empty defaults to info", "", config.DefaultLogLevel},
		{"info", config.DefaultLogLevel, config.DefaultLogLevel},
		{"debug", config.LogLevelDebug, config.LogLevelDebug},
		{"warn", config.LogLevelWarn, config.LogLevelWarn},
		{"warning normalizes to warn", config.LogLevelWarning, config.LogLevelWarn},
		{"error", config.LogLevelError, config.LogLevelError},
		{"case insensitive DEBUG", "DEBUG", config.LogLevelDebug},
		{"case insensitive Warn", "Warn", config.LogLevelWarn},
		{"whitespace trimmed", "  debug  ", config.LogLevelDebug},
		{"unrecognized falls back to info", "trace", config.DefaultLogLevel},
		{"unrecognized falls back to info (empty-looking)", "foo", config.DefaultLogLevel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("GALACTIC_CNI_LOG_LEVEL", tc.env)
			}
			got := resolveLogLevel()
			if got != tc.want {
				t.Errorf("resolveLogLevel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveEgressShardSIDs(t *testing.T) {
	// Unset: no default to normalize to, unlike resolveLogLevel -- empty
	// means "no shard configured yet," written into the conflist verbatim.
	if got := resolveEgressShardSIDs(); got != "" {
		t.Errorf("resolveEgressShardSIDs() = %q, want empty when unset", got)
	}

	const want = "2001:db8:ff01:1:e001::,2001:db8:ff03:1:e001::"
	t.Setenv(config.EnvCNIEgressShardSIDs, want)
	if got := resolveEgressShardSIDs(); got != want {
		t.Errorf("resolveEgressShardSIDs() = %q, want %q", got, want)
	}
}

// TestResolveEBPFInterfaces covers the env-override path only (the
// auto-detected fallback -- attach.ResolveInterfaces' own default IPv6
// route heuristic -- depends on this test host's own routing table, so
// asserting an exact interface name there would be environment-dependent
// rather than a property of this function itself). GALACTIC_CNI_EBPF_INTERFACES
// set here is exactly what internal/cnibgp's own config.go bridges back
// into a downstream CNI plugin process's raw env, per hostconf.HostConf.
// EBPFInterfaces' own doc comment -- this test is what makes that value
// deterministic and correct in the first place, resolved once from this
// init container's own real pod env.
func TestResolveEBPFInterfaces(t *testing.T) {
	const want = "eth1,eth2"
	t.Setenv(config.EnvCNIEBPFInterfaces, want)
	if got := resolveEBPFInterfaces(); got != want {
		t.Errorf("resolveEBPFInterfaces() = %q, want %q", got, want)
	}
}

// assertBinaryCopied verifies that the binary at path exists and contains
// wantContent, factored out of TestBootstrap to keep its own cyclomatic
// complexity within golangci-lint's gocyclo budget.
func assertBinaryCopied(t *testing.T, path, wantContent string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != wantContent {
		t.Fatalf("binary copy verification failed for %q: err=%v content=%q", path, err, got)
	}
}

// writeSourceBinary writes content to path, failing the test on error.
// Factored out alongside assertBinaryCopied for the same reason — each
// binary this test seeds would otherwise add its own branch to
// TestBootstrap's own cyclomatic complexity.
func writeSourceBinary(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write source binary %q: %v", path, err)
	}
}

func TestBootstrap(t *testing.T) {
	// Set up temporary directories for testing overrides
	tmpDir := t.TempDir()
	HostBinDir = filepath.Join(tmpDir, "host", "opt", "cni", "bin")
	HostConflist = filepath.Join(tmpDir, "host", "etc", "cni", "net.d", "10-galactic.conflist")
	HostEtcDir = filepath.Join(tmpDir, "host", "var", "lib", "galactic")
	SADir = filepath.Join(tmpDir, "serviceaccount")

	// Create service account files and source binary files
	if err := os.MkdirAll(SADir, 0755); err != nil {
		t.Fatalf("os.MkdirAll SADir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(SADir, "ca.crt"), []byte("dummy-ca"), 0644); err != nil {
		t.Fatalf("os.WriteFile ca.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(SADir, "token"), []byte("dummy-token"), 0644); err != nil {
		t.Fatalf("os.WriteFile token: %v", err)
	}

	// Create mock CNI source binary files
	SourceVethBinary = filepath.Join(tmpDir, "source-galactic-veth")
	SourceTapBinary = filepath.Join(tmpDir, "source-galactic-tap")
	SourceIPAMBinary = filepath.Join(tmpDir, "source-galactic-ipam")
	SourceBGPBinary = filepath.Join(tmpDir, "source-galactic-bgp")
	SourceRouteBinary = filepath.Join(tmpDir, "source-galactic-route")
	SourceHostDeviceBinary = filepath.Join(tmpDir, "source-host-device")
	writeSourceBinary(t, SourceVethBinary, "cni-content")
	writeSourceBinary(t, SourceTapBinary, "tap-cni-content")
	writeSourceBinary(t, SourceIPAMBinary, "ipam-content")
	writeSourceBinary(t, SourceBGPBinary, "bgp-content")
	writeSourceBinary(t, SourceRouteBinary, "route-content")
	writeSourceBinary(t, SourceHostDeviceBinary, "host-device-content")

	// Mock node object
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: "192.168.1.10",
				},
				{
					Type:    corev1.NodeInternalIP,
					Address: "fd00:1234::10",
				},
			},
		},
	}

	// Override client builder and netlink functions
	originalClientFn := newK8sClientFn
	originalAddrListFn := addrListFn
	defer func() {
		newK8sClientFn = originalClientFn
		addrListFn = originalAddrListFn
	}()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()
	newK8sClientFn = func() (client.Client, error) {
		return fakeClient, nil
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")

	t.Run("matching IPv4 address succeeds", func(t *testing.T) {
		addrListFn = func(family int) ([]netlink.Addr, error) {
			if family == netlink.FAMILY_V4 {
				return []netlink.Addr{
					{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}},
				}, nil
			}
			return nil, nil
		}
		const wantShardSIDs = "2001:db8:ff01:1:e001::,2001:db8:ff03:1:e001::"
		t.Setenv(config.EnvCNIEgressShardSIDs, wantShardSIDs)
		const wantEBPFIfaces = "eth1"
		t.Setenv(config.EnvCNIEBPFInterfaces, wantEBPFIfaces)

		err := Bootstrap(context.Background(), "test-node")
		if err != nil {
			t.Fatalf("Bootstrap failed unexpectedly: %v", err)
		}

		// Verify binaries copied
		assertBinaryCopied(t, filepath.Join(HostBinDir, "galactic-veth"), "cni-content")
		assertBinaryCopied(t, filepath.Join(HostBinDir, "galactic-tap"), "tap-cni-content")
		assertBinaryCopied(t, filepath.Join(HostBinDir, "galactic-ipam"), "ipam-content")
		assertBinaryCopied(t, filepath.Join(HostBinDir, "galactic-bgp"), "bgp-content")
		assertBinaryCopied(t, filepath.Join(HostBinDir, "galactic-route"), "route-content")

		// Verify conflist written
		conflist, err := hostconf.Load(HostConflist, hostconf.PluginType)
		if err != nil {
			t.Fatalf("failed to read conflist: %v", err)
		}
		if conflist.NodeName != "test-node" {
			t.Errorf("expected node_name test-node, got %s", conflist.NodeName)
		}
		if conflist.Kubeconfig != "/var/lib/galactic/kubeconfig" {
			t.Errorf("expected kubeconfig /var/lib/galactic/kubeconfig, got %s", conflist.Kubeconfig)
		}
		if conflist.Namespace != "galactic-system" {
			t.Errorf("expected namespace galactic-system, got %s", conflist.Namespace)
		}
		if conflist.LogFile != "/var/log/galactic/galactic-cni.log" {
			t.Errorf("expected log_file /var/log/galactic/galactic-cni.log, got %s", conflist.LogFile)
		}
		if conflist.LogLevel != config.DefaultLogLevel {
			t.Errorf("expected log_level %s, got %s", config.DefaultLogLevel, conflist.LogLevel)
		}
		if conflist.EgressShardSIDs != wantShardSIDs {
			t.Errorf("expected nat66_shard_sids %s, got %s", wantShardSIDs, conflist.EgressShardSIDs)
		}
		if conflist.EBPFInterfaces != wantEBPFIfaces {
			t.Errorf("expected ebpf_interfaces %s, got %s", wantEBPFIfaces, conflist.EBPFInterfaces)
		}

		// Verify kubeconfig written
		kubeconfig, err := os.ReadFile(filepath.Join(HostEtcDir, "kubeconfig"))
		if err != nil {
			t.Fatalf("failed to read kubeconfig: %v", err)
		}
		if !strings.Contains(string(kubeconfig), "dummy-token") {
			t.Fatalf("kubeconfig does not contain token")
		}
	})

	t.Run("matching IPv6 address succeeds", func(t *testing.T) {
		addrListFn = func(family int) ([]netlink.Addr, error) {
			if family == netlink.FAMILY_V6 {
				return []netlink.Addr{
					{IPNet: &net.IPNet{IP: net.ParseIP("fd00:1234::10"), Mask: net.CIDRMask(64, 128)}},
				}, nil
			}
			return nil, nil
		}

		err := Bootstrap(context.Background(), "test-node")
		if err != nil {
			t.Fatalf("Bootstrap failed unexpectedly: %v", err)
		}
	})

	t.Run("address mismatch fails", func(t *testing.T) {
		addrListFn = func(family int) ([]netlink.Addr, error) {
			return []netlink.Addr{
				{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}},
			}, nil
		}

		err := Bootstrap(context.Background(), "test-node")
		if err == nil {
			t.Fatal("expected Bootstrap to fail due to address mismatch, got nil")
		}
		if !strings.Contains(err.Error(), "node identity check failed") {
			t.Fatalf("expected node identity check failure, got: %v", err)
		}
	})

	t.Run("GALACTIC_CNI_LOG_LEVEL propagates to conflist", func(t *testing.T) {
		t.Setenv("GALACTIC_CNI_LOG_LEVEL", config.LogLevelDebug)

		addrListFn = func(family int) ([]netlink.Addr, error) {
			if family == netlink.FAMILY_V4 {
				return []netlink.Addr{
					{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}},
				}, nil
			}
			return nil, nil
		}

		err := Bootstrap(context.Background(), "test-node")
		if err != nil {
			t.Fatalf("Bootstrap failed unexpectedly: %v", err)
		}

		conflist, err := hostconf.Load(HostConflist, hostconf.PluginType)
		if err != nil {
			t.Fatalf("failed to read conflist: %v", err)
		}
		if conflist.LogLevel != config.LogLevelDebug {
			t.Errorf("expected log_level %s, got %s", config.LogLevelDebug, conflist.LogLevel)
		}
	})

	t.Run("GALACTIC_CNI_LOG_LEVEL warning normalizes to warn", func(t *testing.T) {
		t.Setenv("GALACTIC_CNI_LOG_LEVEL", config.LogLevelWarning)

		addrListFn = func(family int) ([]netlink.Addr, error) {
			if family == netlink.FAMILY_V4 {
				return []netlink.Addr{
					{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}},
				}, nil
			}
			return nil, nil
		}

		err := Bootstrap(context.Background(), "test-node")
		if err != nil {
			t.Fatalf("Bootstrap failed unexpectedly: %v", err)
		}

		conflist, err := hostconf.Load(HostConflist, hostconf.PluginType)
		if err != nil {
			t.Fatalf("failed to read conflist: %v", err)
		}
		if conflist.LogLevel != config.LogLevelWarn {
			t.Errorf("expected log_level %s (normalized from %s), got %s",
				config.LogLevelWarn, config.LogLevelWarning, conflist.LogLevel)
		}
	})
}

func TestRun(t *testing.T) {
	// This test exercises Run's general daemon behavior (health server,
	// log rotation, shutdown) -- not the eBPF datapath itself (covered by
	// the TestRun_EBPFDatapathEnabled_* tests below), so stand in a fake
	// ebpfStartFn rather than requiring root/a real kernel BPF stack here.
	origEBPFStartFn := ebpfStartFn
	t.Cleanup(func() { ebpfStartFn = origEBPFStartFn })
	ebpfStartFn = func(_ context.Context, _ string) (io.Closer, []string, *attach.Watcher, error) {
		return &fakeDatapathCloser{}, []string{"eth0"}, nil, nil
	}

	// Exercise the radv reconciler too: a short, fixed override (rather
	// than waiting out a real multi-minute reconcile interval) so it ticks
	// several times during this test's lifetime, against an empty,
	// test-local state dir (radv.RunActor is never started with no
	// attachments recorded, so this needs no root/real interface -- just
	// confirms the reconcile/shutdown wiring in Run doesn't panic or block
	// shutdown).
	origRadvReconcileInterval := radvReconcileInterval
	t.Cleanup(func() { radvReconcileInterval = origRadvReconcileInterval })
	radvReconcileInterval = 20 * time.Millisecond

	origRadvStateDir := radv.DefaultStateDir
	t.Cleanup(func() { radv.DefaultStateDir = origRadvStateDir })
	radv.DefaultStateDir = filepath.Join(t.TempDir(), "galactic-radv")

	// Set up directories
	tmpDir := t.TempDir()
	HostBinDir = filepath.Join(tmpDir, "host", "opt", "cni", "bin")
	HostConflist = filepath.Join(tmpDir, "host", "etc", "cni", "net.d", "10-galactic.conflist")
	HostEtcDir = filepath.Join(tmpDir, "host", "var", "lib", "galactic")
	SADir = filepath.Join(tmpDir, "serviceaccount")

	if err := os.MkdirAll(HostBinDir, 0755); err != nil {
		t.Fatalf("MkdirAll HostBinDir: %v", err)
	}
	if err := os.MkdirAll(SADir, 0755); err != nil {
		t.Fatalf("MkdirAll SADir: %v", err)
	}

	// Create stale old CNI binary wrapper to test cleanup
	oldBinPath := filepath.Join(HostBinDir, "galactic-cni.bin")
	if err := os.WriteFile(oldBinPath, []byte("stale-bin"), 0755); err != nil {
		t.Fatalf("write oldBinPath: %v", err)
	}

	// Create service account files
	if err := os.WriteFile(filepath.Join(SADir, "ca.crt"), []byte("dummy-ca"), 0644); err != nil {
		t.Fatalf("os.WriteFile ca.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(SADir, "token"), []byte("dummy-token"), 0644); err != nil {
		t.Fatalf("os.WriteFile token: %v", err)
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	healthPort := 25179 // use a non-colliding port for tests

	// Run in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, healthPort, healthPort+1000)
	}()

	// Query gRPC health endpoint
	time.Sleep(100 * time.Millisecond) // allow gRPC server to start
	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", healthPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	hc := grpc_health_v1.NewHealthClient(conn)

	resp, err := hc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Errorf("Health status = %v, want SERVING", resp.Status)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit on context cancel")
	}
}

// fakeDatapathCloser is a mocked io.Closer standing in for
// *prog.UsidObjects in tests, so Run's eBPF datapath wiring can be
// exercised without root, a real kernel BPF stack, or a live network
// interface. closed is an atomic.Bool (not a bare bool) because Run's
// deferred Close() runs on the goroutine Run itself executes on, which
// this test observes from its own goroutine with no other synchronization
// between the two.
type fakeDatapathCloser struct {
	closed atomic.Bool
	err    error
}

func (f *fakeDatapathCloser) Close() error {
	f.closed.Store(true)
	return f.err
}

// TestRun_EBPFDatapathEnabled_StartsAndClosesOnShutdown covers Milestone
// 3.1's wiring of the eBPF uSID datapath into the run subcommand: Run
// calls ebpfStartFn with attach.PinDir and closes the returned object on
// shutdown.
func TestRun_EBPFDatapathEnabled_StartsAndClosesOnShutdown(t *testing.T) {
	origEBPFStartFn := ebpfStartFn
	t.Cleanup(func() { ebpfStartFn = origEBPFStartFn })

	fakeDP := &fakeDatapathCloser{}
	var gotPinDir atomic.Value
	ebpfStartFn = func(_ context.Context, pinDir string) (io.Closer, []string, *attach.Watcher, error) {
		gotPinDir.Store(pinDir)
		return fakeDP, []string{"eth0"}, nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	healthPort := 25180

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, healthPort, healthPort+1000)
	}()

	time.Sleep(100 * time.Millisecond)
	if got, _ := gotPinDir.Load().(string); got != attach.PinDir {
		t.Errorf("ebpfStartFn pinDir = %q, want %q", got, attach.PinDir)
	}
	if fakeDP.closed.Load() {
		t.Error("datapath closed before shutdown")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit on context cancel")
	}

	if !fakeDP.closed.Load() {
		t.Error("datapath was not closed on shutdown")
	}
}

// TestRun_EBPFDatapathEnabled_StartFailureIsFatal covers the milestone's
// requirement that a preflight/load/attach failure blocks the datapath --
// here, that failure must also be fatal to Run itself, not silently
// swallowed or degraded into a partial datapath state.
func TestRun_EBPFDatapathEnabled_StartFailureIsFatal(t *testing.T) {
	origEBPFStartFn := ebpfStartFn
	t.Cleanup(func() { ebpfStartFn = origEBPFStartFn })

	wantErr := errors.New("simulated preflight/load/attach failure")
	ebpfStartFn = func(_ context.Context, _ string) (io.Closer, []string, *attach.Watcher, error) {
		return nil, nil, nil, wantErr
	}

	err := Run(context.Background(), 25181, 26181)
	if err == nil {
		t.Fatal("Run() error = nil, want the eBPF datapath start failure surfaced")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Run() error = %v, want it to wrap %v", err, wantErr)
	}
}

// TestRun_EBPFDatapathEnabled_MetricsAndHealthReflectRealDatapath is
// Milestone 4's real-kernel exit criterion, exercised through Run() itself
// rather than attach/metrics' own lower-level unit tests: metrics are
// visible in a local test run, and the gRPC "ebpf-datapath" health service
// flips to NOT_SERVING when the program is detached, then recovers once
// re-attached. Attaches to "lo" (always present, no test network namespace
// needed -- lo carries no traffic this test could disrupt) via
// GALACTIC_CNI_EBPF_INTERFACES, using a throwaway pin directory under the
// real bpffs so it never collides with attach.PinDir's production path.
func TestRun_EBPFDatapathEnabled_MetricsAndHealthReflectRealDatapath(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-run-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	t.Setenv(config.EnvCNIEBPFInterfaces, "lo")

	origEBPFStartFn := ebpfStartFn
	t.Cleanup(func() { ebpfStartFn = origEBPFStartFn })
	ebpfStartFn = func(ctx context.Context, _ string) (io.Closer, []string, *attach.Watcher, error) {
		return attach.StartWatching(ctx, pinDir)
	}

	origInterval := ebpfHealthCheckInterval
	t.Cleanup(func() { ebpfHealthCheckInterval = origInterval })
	ebpfHealthCheckInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const healthPort = 25182
	const metricsPort = 26182

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, healthPort, metricsPort)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Error("Run did not exit on context cancel during cleanup")
		}
	})

	// Allow Load/Attach and both listeners to come up.
	time.Sleep(300 * time.Millisecond)

	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", healthPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()
	hc := grpc_health_v1.NewHealthClient(conn)

	checkStatus := func(t *testing.T, want grpc_health_v1.HealthCheckResponse_ServingStatus) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		var last grpc_health_v1.HealthCheckResponse_ServingStatus
		for time.Now().Before(deadline) {
			resp, err := hc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: ebpfHealthServiceName})
			if err != nil {
				t.Fatalf("Health check for %q failed: %v", ebpfHealthServiceName, err)
			}
			last = resp.Status
			if last == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("Health status for %q = %v, want %v (timed out waiting)", ebpfHealthServiceName, last, want)
	}

	// Initially attached: SERVING.
	checkStatus(t, grpc_health_v1.HealthCheckResponse_SERVING)

	// Metrics endpoint is up and exposes this milestone's namespace.
	metricsReq, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort), nil)
	if err != nil {
		t.Fatalf("build /metrics request: %v", err)
	}
	metricsResp, err := http.DefaultClient.Do(metricsReq)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = metricsResp.Body.Close() }()
	if metricsResp.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics status = %d, want 200", metricsResp.StatusCode)
	}
	body := make([]byte, 64*1024)
	n, _ := metricsResp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "galactic_usid_") {
		t.Errorf("GET /metrics body does not contain the galactic_usid_ namespace: %q", string(body[:n]))
	}

	// Kill the attach (without closing our own fds -- same distinction
	// attach's own TestHealth_RealDatapath_FlipsAfterAttachIsKilled draws)
	// and confirm the health service flips.
	if err := attach.Detach([]string{"lo"}); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	checkStatus(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	// Re-attach and confirm recovery.
	objs, ifaces, _, err := ebpfStartFn(ctx, pinDir)
	if err != nil {
		t.Fatalf("re-attach via ebpfStartFn: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	if len(ifaces) != 1 || ifaces[0] != "lo" {
		t.Fatalf("re-attach ifaces = %v, want [lo]", ifaces)
	}
	checkStatus(t, grpc_health_v1.HealthCheckResponse_SERVING)
}

// radvTestEnv points reconcileRadvActors at a temporary state directory, a
// fake kernel reporting links[iface] for each interface, and a clock the test
// moves by hand. An interface absent from links does not exist.
type radvTestEnv struct {
	links map[string]radvTestLink
	now   time.Time
}

type radvTestLink struct{ carrier bool }

func newRadvTestEnv(t *testing.T) *radvTestEnv {
	t.Helper()
	env := &radvTestEnv{links: map[string]radvTestLink{}, now: time.Now()}

	origStateDir, origLinkState, origNow := radv.DefaultStateDir, radvLinkState, radvNow
	t.Cleanup(func() {
		radv.DefaultStateDir, radvLinkState, radvNow = origStateDir, origLinkState, origNow
	})
	radv.DefaultStateDir = t.TempDir()
	radvLinkState = func(iface string) (bool, bool, error) {
		link, ok := env.links[iface]
		return ok, link.carrier, nil
	}
	radvNow = func() time.Time { return env.now }
	return env
}

// radvTestIface is the one attachment these tests record. The real kernel has no
// such device, so radv.RunActor started on it always fails.
const radvTestIface = "does-not-exist0"

func recordRadvAttachment(t *testing.T) {
	t.Helper()
	if err := radv.RecordAttachment(radv.DefaultStateDir, radvTestIface, 1500); err != nil {
		t.Fatalf("RecordAttachment: %v", err)
	}
}

func radvRecordExists(t *testing.T) bool {
	t.Helper()
	records, err := radv.ListAttachments(radv.DefaultStateDir)
	if err != nil {
		t.Fatalf("ListAttachments: %v", err)
	}
	for _, r := range records {
		if r.HostInterface == radvTestIface {
			return true
		}
	}
	return false
}

// awaitRadvFailure waits for the actor started on radvTestIface to report that
// it could not start.
func awaitRadvFailure(t *testing.T, actors *radvActorSet) radvActorFailure {
	t.Helper()
	select {
	case failure := <-actors.failed:
		if failure.iface != radvTestIface {
			t.Fatalf("actors.failed sent %q, want %q", failure.iface, radvTestIface)
		}
		return failure
	case <-time.After(2 * time.Second):
		t.Fatalf("actors.failed never received a report for %q", radvTestIface)
	}
	return radvActorFailure{}
}

func TestReconcileRadvActors(t *testing.T) {
	const iface = radvTestIface

	tests := []struct {
		name string
		run  func(t *testing.T, env *radvTestEnv, ctx context.Context, actors *radvActorSet)
	}{
		{
			// A tap whose VMM never opened it has no carrier and never gets a
			// link-local address, so starting an actor on it can only fail.
			name: "NoCarrierIsNotStarted",
			run: func(t *testing.T, env *radvTestEnv, ctx context.Context, actors *radvActorSet) {
				env.links[iface] = radvTestLink{carrier: false}

				for range 3 {
					reconcileRadvActors(ctx, actors)
					env.now = env.now.Add(radvReconcileInterval)
				}

				if _, running := actors.cancel[iface]; running {
					t.Fatalf("actor started on %q without carrier", iface)
				}
				if !actors.pending[iface].noCarrier {
					t.Errorf("pending[%q].noCarrier = false, want true", iface)
				}
				if !radvRecordExists(t) {
					t.Errorf("record for %q removed, want it kept while its interface exists", iface)
				}
			},
		},
		{
			// A start that fails on an interface with carrier is retried, but
			// only once its backoff has elapsed, and the backoff doubles up to
			// its cap.
			name: "FailedStartBacksOff",
			run: func(t *testing.T, env *radvTestEnv, ctx context.Context, actors *radvActorSet) {
				env.links[iface] = radvTestLink{carrier: true}

				reconcileRadvActors(ctx, actors)
				recorded, running := actors.cancel[iface]
				if !running {
					t.Fatalf("no actor started on %q with carrier", iface)
				}
				failure := awaitRadvFailure(t, actors)

				// Cancelling releases the attempt's context from the daemon's
				// own, so a retry loop cannot grow memory without bound.
				cancelled := false
				actors.cancel[iface] = func() {
					cancelled = true
					recorded()
				}
				radvActorFailed(actors, failure)
				if !cancelled {
					t.Fatalf("radvActorFailed did not cancel %q's context", iface)
				}
				if _, running := actors.cancel[iface]; running {
					t.Fatalf("actors.cancel[%q] still present after radvActorFailed", iface)
				}

				// Still inside the first backoff: not retried.
				env.now = env.now.Add(radvReconcileInterval - time.Millisecond)
				reconcileRadvActors(ctx, actors)
				if _, running := actors.cancel[iface]; running {
					t.Fatalf("actor on %q retried before its backoff elapsed", iface)
				}

				// Each later failure doubles the wait, up to the cap.
				want := radvReconcileInterval
				for failures := 1; failures <= 12; failures++ {
					env.now = actors.pending[iface].retryAt
					reconcileRadvActors(ctx, actors)
					if _, running := actors.cancel[iface]; !running {
						t.Fatalf("failure %d: actor on %q not retried once its backoff elapsed", failures, iface)
					}
					radvActorFailed(actors, awaitRadvFailure(t, actors))

					want = min(want*2, radvMaxRetryBackoff)
					if got := actors.pending[iface].retryAt.Sub(env.now); got != want {
						t.Fatalf("failure %d: backoff = %v, want %v", failures+1, got, want)
					}
				}
				if got := actors.pending[iface].retryAt.Sub(env.now); got != radvMaxRetryBackoff {
					t.Errorf("backoff after many failures = %v, want the %v cap", got, radvMaxRetryBackoff)
				}
			},
		},
		{
			// Losing carrier, as a guest restarting does, resets the backoff
			// so the guest is served as soon as it is back.
			name: "LosingCarrierResetsBackoff",
			run: func(t *testing.T, env *radvTestEnv, ctx context.Context, actors *radvActorSet) {
				env.links[iface] = radvTestLink{carrier: true}
				for range 4 {
					if p, ok := actors.pending[iface]; ok {
						env.now = p.retryAt
					}
					reconcileRadvActors(ctx, actors)
					radvActorFailed(actors, awaitRadvFailure(t, actors))
				}

				env.links[iface] = radvTestLink{carrier: false}
				reconcileRadvActors(ctx, actors)
				env.links[iface] = radvTestLink{carrier: true}
				reconcileRadvActors(ctx, actors)

				if _, running := actors.cancel[iface]; !running {
					t.Fatalf("actor on %q not started right after carrier returned", iface)
				}
				awaitRadvFailure(t, actors)
			},
		},
		{
			// A record whose interface is gone is removed once the grace
			// period has passed, since no DEL is left to remove it.
			name: "MissingInterfaceRecordIsRemoved",
			run: func(t *testing.T, env *radvTestEnv, ctx context.Context, actors *radvActorSet) {
				// Found missing after the record was written.
				env.now = time.Now().Add(time.Minute)
				reconcileRadvActors(ctx, actors)
				if !radvRecordExists(t) {
					t.Fatalf("record for %q removed on the first tick, want it kept for the grace period", iface)
				}

				env.now = env.now.Add(radvStaleRecordGrace - time.Millisecond)
				reconcileRadvActors(ctx, actors)
				if !radvRecordExists(t) {
					t.Fatalf("record for %q removed before the grace period passed", iface)
				}

				env.now = env.now.Add(time.Millisecond)
				reconcileRadvActors(ctx, actors)
				if radvRecordExists(t) {
					t.Fatalf("record for %q kept after its interface stayed missing past the grace period", iface)
				}
				if _, ok := actors.pending[iface]; ok {
					t.Errorf("pending[%q] kept after its record was removed", iface)
				}
				if _, running := actors.cancel[iface]; running {
					t.Errorf("actor started on missing interface %q", iface)
				}
			},
		},
		{
			// A record written after the interface was first found missing
			// comes from an ADD creating it again, so it is kept.
			name: "RecordRewrittenWhileMissingIsKept",
			run: func(t *testing.T, env *radvTestEnv, ctx context.Context, actors *radvActorSet) {
				env.now = time.Now().Add(-time.Hour)
				reconcileRadvActors(ctx, actors)

				env.now = env.now.Add(radvStaleRecordGrace)
				reconcileRadvActors(ctx, actors)
				if !radvRecordExists(t) {
					t.Fatalf("record for %q removed although it was written after the interface went missing", iface)
				}
				if !actors.pending[iface].missingSince.IsZero() {
					t.Errorf("pending[%q].missingSince not reset after keeping a newer record", iface)
				}
			},
		},
		{
			// An interface that comes back within the grace period keeps its
			// record.
			name: "InterfaceReturningWithinGraceIsKept",
			run: func(t *testing.T, env *radvTestEnv, ctx context.Context, actors *radvActorSet) {
				env.now = time.Now().Add(time.Minute)
				reconcileRadvActors(ctx, actors)

				env.links[iface] = radvTestLink{carrier: false}
				env.now = env.now.Add(radvStaleRecordGrace / 2)
				reconcileRadvActors(ctx, actors)

				delete(env.links, iface)
				env.now = env.now.Add(radvStaleRecordGrace / 2)
				reconcileRadvActors(ctx, actors)
				if !radvRecordExists(t) {
					t.Fatalf("record for %q removed although its interface was only missing briefly", iface)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRadvTestEnv(t)
			recordRadvAttachment(t)

			ctx, cancel := context.WithCancel(context.Background())
			actors := &radvActorSet{}
			t.Cleanup(func() {
				cancel()
				actors.wg.Wait()
			})

			tt.run(t, env, ctx, actors)
		})
	}
}
