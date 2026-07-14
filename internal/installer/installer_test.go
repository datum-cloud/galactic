// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
)

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
	SourceCNIBinary = filepath.Join(tmpDir, "source-galactic-cni")
	SourceHostDeviceBinary = filepath.Join(tmpDir, "source-host-device")
	if err := os.WriteFile(SourceCNIBinary, []byte("cni-content"), 0755); err != nil {
		t.Fatalf("write SourceCNIBinary: %v", err)
	}
	if err := os.WriteFile(SourceHostDeviceBinary, []byte("host-device-content"), 0755); err != nil {
		t.Fatalf("write SourceHostDeviceBinary: %v", err)
	}

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

		err := Bootstrap(context.Background(), "test-node")
		if err != nil {
			t.Fatalf("Bootstrap failed unexpectedly: %v", err)
		}

		// Verify binaries copied
		cniContent, err := os.ReadFile(filepath.Join(HostBinDir, "galactic-cni"))
		if err != nil || string(cniContent) != "cni-content" {
			t.Fatalf("galactic-cni binary copy verification failed")
		}

		// Verify conflist written
		conflist, err := loadHostConf(HostConflist)
		if err != nil {
			t.Fatalf("failed to read conflist: %v", err)
		}
		if conflist.NodeName != "test-node" {
			t.Errorf("expected node_name test-node, got %s", conflist.NodeName)
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
}

func TestRun(t *testing.T) {
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
		errCh <- Run(ctx, healthPort)
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
