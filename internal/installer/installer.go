// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
)

// Default settings corresponding to CNI defaults
const (
	DefaultKubeconfig = "/var/lib/galactic/kubeconfig"
	DefaultNamespace  = "galactic-system"
	DefaultLogFile    = "/var/log/galactic/galactic-cni.log"
)

var (
	// Host paths, configurable for testing
	HostBinDir             = "/host/opt/cni/bin"
	HostConflist           = "/host/etc/cni/net.d/10-galactic.conflist"
	HostEtcDir             = "/host/var/lib/galactic"
	SADir                  = "/var/run/secrets/kubernetes.io/serviceaccount"
	SourceCNIBinary        = "/galactic-cni"
	SourceHostDeviceBinary = "/host-device"
)

// HostConf holds node-local settings read from the conflist.
type HostConf struct {
	NodeName   string `json:"node_name"`
	Kubeconfig string `json:"kubeconfig"`
	Namespace  string `json:"namespace"`
	LogFile    string `json:"log_file"`
	LogLevel   string `json:"log_level,omitempty"`
}

type conflistEnvelope struct {
	CNIVersion string            `json:"cniVersion"`
	Name       string            `json:"name"`
	Plugins    []json.RawMessage `json:"plugins"`
}

// loadHostConf is a helper to read the HostConf from HostConflist.
func loadHostConf(filePath string) (*HostConf, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var env conflistEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse conflist envelope: %w", err)
	}

	for _, raw := range env.Plugins {
		var meta struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if meta.Type == "galactic-cni" {
			var conf HostConf
			if err := json.Unmarshal(raw, &conf); err != nil {
				return nil, fmt.Errorf("parse host CNI config: %w", err)
			}
			return &conf, nil
		}
	}

	return nil, fmt.Errorf("conflist at %q does not contain a plugin with type \"galactic-cni\"", filePath)
}

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
// first, since binaries copied here (e.g. galactic-cni itself) run tens of
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
}

var newK8sClientFn = func() (client.Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %w", err)
	}
	return client.New(config, client.Options{Scheme: scheme})
}

// addrListFn can be overridden in tests to mock netlink interface addresses.
var addrListFn = func(family int) ([]netlink.Addr, error) {
	return netlink.AddrList(nil, family)
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

	// 1. Copy CNI and host-device binaries to the host
	if err := os.MkdirAll(HostBinDir, 0755); err != nil {
		return fmt.Errorf("create host CNI bin dir: %w", err)
	}
	if err := atomicCopyFile(SourceCNIBinary, filepath.Join(HostBinDir, "galactic-cni"), 0755); err != nil {
		return fmt.Errorf("copy galactic-cni binary: %w", err)
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
	conflistContent := fmt.Sprintf(`{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "plugins": [
    {
      "type": "galactic-cni",
      "node_name": %q,
      "kubeconfig": "/var/lib/galactic/kubeconfig",
      "namespace": "galactic-system",
      "log_file": "/var/log/galactic/galactic-cni.log",
      "log_level": "info"
    }
  ]
}
`, nodeName)

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

// Run executes the CNI installer main container tasks:
// 1. Sets up log rotation periodically.
// 2. Starts a simple ServiceAccount token refresh ticker.
// 3. Deferred cleanup of stale .bin wrapper file.
// 4. Starts the gRPC health check server.
func Run(ctx context.Context, grpcHealthPort int) error {
	slog.Info("Starting CNI installer run daemon", "grpcHealthPort", grpcHealthPort)

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

	for {
		select {
		case <-ctx.Done():
			slog.Info("CNI installer run daemon shutting down")
			return nil

		case <-cleanupTimer.C:
			// Cleanup old wrapper binary '/host/opt/cni/bin/galactic-cni.bin'
			oldBinPath := filepath.Join(HostBinDir, "galactic-cni.bin")
			if _, err := os.Stat(oldBinPath); err == nil {
				if err := os.Remove(oldBinPath); err != nil {
					slog.Warn("Failed to clean up old CNI binary wrapper", "path", oldBinPath, "err", err)
				} else {
					slog.Info("Stale CNI binary wrapper cleaned up successfully", "path", oldBinPath)
				}
			}

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
		}
	}
}

// getLogFileHostPath resolves the CNI log file path from HostConflist
// and prefixes it with "/host" since the container views host filesystem via /host mount.
func getLogFileHostPath() string {
	hostConf, err := loadHostConf(HostConflist)
	if err != nil || hostConf.LogFile == "" {
		return filepath.Join("/host", DefaultLogFile)
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
