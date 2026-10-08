// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package traffic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testDestination = "fd70:100::10"
	testListen      = "[::1]:0"
)

type readyOutput struct{ address chan string }

func (r readyOutput) Write(data []byte) (int, error) {
	fields := strings.Fields(string(data))
	r.address <- fields[len(fields)-1]
	return len(data), nil
}

func startService(t *testing.T, cfg RelayConfig) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := readyOutput{address: make(chan string, 1)}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg, ready) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("stop relay: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("relay did not stop")
		}
	})
	select {
	case address := <-ready.address:
		return address
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not become ready")
		return ""
	}
}

func TestProducerRelayAndQuery(t *testing.T) {
	for _, transport := range []string{transportUDP, transportTCP} {
		t.Run(transport, func(t *testing.T) {
			root := startService(t, RelayConfig{Mode: modeRoot, Transport: transport,
				Listen: testListen, Target: net.JoinHostPort(testDestination, "8443")})
			stateDir := t.TempDir()
			producer := startService(t, RelayConfig{Mode: modeProducer, Transport: transport,
				Listen: testListen, Target: root, StateDir: stateDir})
			cfg := QueryConfig{Transport: transport, Frontend: producer, Source: testListen,
				Expected: testDestination, Payload: "consumer-a request", Timeout: time.Second}
			if _, _, err := Query(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			directive := []byte(`{"seconds":0.05,"token":"delayed-request"}`)
			if err := os.WriteFile(filepath.Join(stateDir, "psc-delay.json"), directive, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Query(context.Background(), cfg); err != nil {
				t.Fatalf("delayed reply: %v", err)
			}
			raw, err := os.ReadFile(filepath.Join(stateDir, "psc-delay-trace.json"))
			if err != nil {
				t.Fatal(err)
			}
			var trace delayTrace
			if err := json.Unmarshal(raw, &trace); err != nil {
				t.Fatal(err)
			}
			if trace.Token != "delayed-request" || trace.Transport != transport ||
				trace.UpstreamResponseAt < trace.RequestReceivedAt || trace.ReplyAttemptAt < trace.UpstreamResponseAt+0.04 {
				t.Fatalf("incorrect reply trace: %+v", trace)
			}
			if _, err := os.Stat(filepath.Join(stateDir, "psc-delay.json")); !os.IsNotExist(err) {
				t.Fatalf("delay directive not consumed: %v", err)
			}
			if _, _, err := Query(context.Background(), cfg); err != nil {
				t.Fatalf("next request: %v", err)
			}
			cfg.Expected = "fd70:100::11"
			if _, _, err := Query(context.Background(), cfg); err == nil {
				t.Fatal("accepted the wrong producer identity")
			}
		})
	}
}

func TestFramedTCPRequests(t *testing.T) {
	address := startService(t, RelayConfig{Mode: modeRoot, Transport: transportTCP,
		Listen: testListen, Target: net.JoinHostPort(testDestination, "8443")})
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp6", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{"first request", "second request"} {
		var frame bytes.Buffer
		if err := writeFrame(&frame, []byte(payload)); err != nil {
			t.Fatal(err)
		}
		// Deliver the frame in separate bytes to exercise partial socket reads.
		for _, value := range frame.Bytes() {
			if _, err := conn.Write([]byte{value}); err != nil {
				t.Fatal(err)
			}
		}
		raw, err := readFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		var reply Reply
		if err := json.Unmarshal(raw, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Payload != payload || reply.Destination != testDestination {
			t.Fatalf("unexpected reply: %+v", reply)
		}
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 2, 1})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame: %v", err)
	}
	if err := writeFrame(io.Discard, make([]byte, maxFrameSize+1)); err == nil {
		t.Fatal("accepted oversized frame")
	}
}

func TestDelayedTCPReply(t *testing.T) {
	root := startService(t, RelayConfig{Mode: modeRoot, Transport: transportTCP,
		Listen: testListen, Target: net.JoinHostPort(testDestination, "8443")})
	stateDir := t.TempDir()
	producer := startService(t, RelayConfig{Mode: modeProducer, Transport: transportTCP,
		Listen: testListen, Target: root, StateDir: stateDir})
	directive := []byte(`{"seconds":4.1,"token":"past-read-deadline"}`)
	if err := os.WriteFile(filepath.Join(stateDir, "psc-delay.json"), directive, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := QueryConfig{Transport: transportTCP, Frontend: producer, Source: testListen,
		Expected: testDestination, Payload: "delayed TCP request", Timeout: 6 * time.Second}
	if _, _, err := Query(context.Background(), cfg); err != nil {
		t.Fatalf("intentional delay must not expire the write deadline: %v", err)
	}
}

func TestQueryCommandExitStatus(t *testing.T) {
	listener, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp6", testListen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	args := []string{commandQuery, "--transport", transportUDP, "--frontend", listener.LocalAddr().String(),
		"--source", testListen, "--expected", testDestination, "--payload", "request", "--timeout", "20ms"}
	var output bytes.Buffer
	code, err := Run(context.Background(), args, &output)
	if code != 3 || err == nil || !strings.Contains(output.String(), `"timeout":true`) {
		t.Fatalf("blocked query: status=%d err=%v output=%s", code, err, output.String())
	}
	code, err = Run(context.Background(), []string{commandQuery, "--transport", "invalid"}, io.Discard)
	if code != 2 || err == nil {
		t.Fatalf("invalid command: status=%d err=%v", code, err)
	}
}
