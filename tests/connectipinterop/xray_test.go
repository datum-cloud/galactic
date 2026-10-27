// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectipinterop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
)

// xrayClient is one Xray process in the client namespace. Its dokodemo-door
// inbound on 127.0.0.1:port forwards TCP and UDP to the echo server through
// the MASQUE outbound, so every datagram the harness sends crosses the
// CONNECT-IP tunnel inside Xray's own IP stack, whose MTU is 1280.
type xrayClient struct {
	h       *harness
	port    int
	logPath string
	stop    func()
}

// startXray runs Xray for connector c over alpn ("h3" or "h2"), trusting caFile.
func (h *harness) startXray(t *testing.T, name string, c connector, alpn, caFile string) *xrayClient {
	t.Helper()
	port := int(h.nextPort.Add(1))
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "debug", "access": "none"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "dokodemo-door",
			"settings": withNetwork(endpoint(echoAddr.String(), echoPort), "tcp,udp"),
		}},
		"outbounds": []any{map[string]any{
			"protocol": "masque",
			"settings": endpoint(serverAddr.String(), 443),
			"streamSettings": map[string]any{
				"network":  "masque",
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":        serverName,
					"alpn":              []string{alpn},
					"disableSystemRoot": true,
					"certificates":      []any{map[string]any{"usage": "verify", "certificateFile": caFile}},
				},
				"masqueSettings": map[string]any{
					"path": "/.well-known/masque/ip/{target}/{ipproto}/",
					"headers": map[string]string{
						"Authorization": "Bearer " + c.token,
						"Galactic-VPC":  vpcName,
					},
				},
			},
		}},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(h.dir, name+".json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	x := &xrayClient{h: h, port: port, logPath: filepath.Join(h.artifacts, "xray-"+name+".log")}
	logFile, err := os.Create(x.logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(),
		"ip", "netns", "exec", h.nsName(roleClient), h.xray, "run", "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start Xray: %v", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	var once sync.Once
	x.stop = func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			<-exited
			_ = logFile.Close()
			h.clients.Delete(x)
		})
	}
	h.clients.Store(x, struct{}{})
	t.Cleanup(x.stop)
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(x.log(), "started") {
		select {
		case <-exited:
			t.Fatalf("Xray exited:\n%s", x.log())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("Xray did not start:\n%s", x.log())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return x
}

func endpoint(addr string, port int) map[string]any {
	return map[string]any{"address": addr, "port": port}
}

func withNetwork(m map[string]any, network string) map[string]any {
	m["network"] = network
	return m
}

func (x *xrayClient) addr() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(x.port)) }

func (x *xrayClient) log() string {
	b, _ := os.ReadFile(x.logPath)
	return string(b)
}

// udpRoundTrips sends n echoPayload-byte datagrams, one at a time, and
// requires each to come back unchanged within timeout.
func (x *xrayClient) udpRoundTrips(n int, timeout time.Duration) error {
	var conn net.Conn
	if err := x.h.client.Do(func(ns.NetNS) error {
		var err error
		conn, err = (&net.Dialer{}).DialContext(context.Background(), "udp4", x.addr())
		return err
	}); err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 65535)
	for i := range n {
		payload := bytes.Repeat([]byte{byte(i + 1)}, echoPayload)
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		m, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("datagram %d: %w", i, err)
		}
		if !bytes.Equal(buf[:m], payload) {
			return fmt.Errorf("datagram %d: echo of %d bytes differs from the %d sent", i, m, len(payload))
		}
	}
	return nil
}

// tcpRoundTrip streams size bytes through the tunnel and requires the same
// bytes back.
func (x *xrayClient) tcpRoundTrip(size int) error {
	var conn net.Conn
	if err := x.h.client.Do(func(ns.NetNS) error {
		var err error
		conn, err = (&net.Dialer{}).DialContext(context.Background(), "tcp4", x.addr())
		return err
	}); err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	sent := make([]byte, size)
	for i := range sent {
		sent[i] = byte(i * 7)
	}
	go func() { _, _ = conn.Write(sent) }()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, sent) {
		return errors.New("TCP echo differs")
	}
	return nil
}
