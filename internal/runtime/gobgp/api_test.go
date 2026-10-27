// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
)

var testAPIKey = types.NamespacedName{Namespace: "ns", Name: "node-a"}

// startAPIServer runs a Server serving its API on a socket in a fresh
// directory and returns a client dialed the way the gobgp CLI's --target
// flag dials it.
func startAPIServer(t *testing.T, prepare func(socket string)) api.GoBgpServiceClient {
	t.Helper()
	// t.TempDir paths can exceed a socket address's length.
	dir, err := os.MkdirTemp("", "gobgp-api")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := apiSocketPath(dir, testAPIKey)
	if prepare != nil {
		prepare(socket)
	}

	s := newServer(Config{APISocket: socket})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	if err := s.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.bgp.Load().StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 65001, RouterId: "192.0.2.1", ListenPort: -1,
	}}); err != nil {
		t.Fatalf("StartBgp: %v", err)
	}

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return api.NewGoBgpServiceClient(conn)
}

func callCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestAPISocketServesReads(t *testing.T) {
	c := startAPIServer(t, nil)
	ctx := callCtx(t)

	got, err := c.GetBgp(ctx, &api.GetBgpRequest{}, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("GetBgp: %v", err)
	}
	if got.GetGlobal().GetAsn() != 65001 {
		t.Errorf("GetBgp ASN = %d, want 65001", got.GetGlobal().GetAsn())
	}

	stream, err := c.ListPeer(ctx, &api.ListPeerRequest{})
	if err != nil {
		t.Fatalf("ListPeer: %v", err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("ListPeer Recv = %v, want EOF with no peers", err)
	}
}

func TestAPISocketRefusesWrites(t *testing.T) {
	c := startAPIServer(t, nil)
	ctx := callCtx(t)

	_, err := c.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: "192.0.2.2", PeerAsn: 65002},
	}}, grpc.WaitForReady(true))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AddPeer = %v, want PermissionDenied", err)
	}

	stream, err := c.AddPathStream(ctx)
	if err != nil {
		t.Fatalf("AddPathStream: %v", err)
	}
	if _, err := stream.CloseAndRecv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AddPathStream = %v, want PermissionDenied", err)
	}
}

func TestAPISocketReplacesStaleFile(t *testing.T) {
	c := startAPIServer(t, func(socket string) {
		// A listener that exits without closing leaves its file behind.
		lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		lis.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = lis.Close()
	})
	if _, err := c.GetBgp(callCtx(t), &api.GetBgpRequest{}, grpc.WaitForReady(true)); err != nil {
		t.Fatalf("GetBgp after stale socket: %v", err)
	}
}

// deniedMethods are the GoBgpService methods that change state, which the
// socket refuses.
var deniedMethods = []string{
	"StartBgp", "StopBgp", "AddPeer", "DeletePeer", "UpdatePeer", "ResetPeer",
	"ShutdownPeer", "EnablePeer", "DisablePeer", "AddPeerGroup", "DeletePeerGroup",
	"UpdatePeerGroup", "AddDynamicNeighbor", "DeleteDynamicNeighbor", "AddPath",
	"DeletePath", "AddPathStream", "AddVrf", "DeleteVrf", "AddPolicy", "DeletePolicy",
	"SetPolicies", "AddDefinedSet", "DeleteDefinedSet", "AddStatement",
	"DeleteStatement", "AddPolicyAssignment", "DeletePolicyAssignment",
	"SetPolicyAssignment", "AddRpki", "DeleteRpki", "EnableRpki", "DisableRpki",
	"ResetRpki", "EnableZebra", "EnableMrt", "DisableMrt", "AddBmp", "DeleteBmp",
	"SetLogLevel", "AddTcpAoKeychain", "UpdateTcpAoKeychain", "DeleteTcpAoKeychain",
}

// TestReadOnlyMethodCoversService fails when GoBGP adds a method, so a bump
// decides whether the socket serves it instead of the interceptor refusing it
// unseen.
func TestReadOnlyMethodCoversService(t *testing.T) {
	denied := make(map[string]bool, len(deniedMethods))
	for _, m := range deniedMethods {
		denied[m] = true
		if readOnlyMethods[m] {
			t.Errorf("%s is in both readOnlyMethods and deniedMethods", m)
		}
	}
	desc := api.GoBgpService_ServiceDesc
	names := make([]string, 0, len(desc.Methods)+len(desc.Streams))
	for _, m := range desc.Methods {
		names = append(names, m.MethodName)
	}
	for _, s := range desc.Streams {
		names = append(names, s.StreamName)
	}
	for _, name := range names {
		full := "/" + desc.ServiceName + "/" + name
		switch {
		case readOnlyMethods[name]:
			if !readOnlyMethod(full) {
				t.Errorf("readOnlyMethod(%q) = false, want true", full)
			}
		case denied[name]:
			if readOnlyMethod(full) {
				t.Errorf("readOnlyMethod(%q) = true, want false", full)
			}
		default:
			t.Errorf("GoBgpService method %s is new: add it to readOnlyMethods or deniedMethods", name)
		}
	}
}

// TestAPISocketAfterReconfigure replaces the server straight after it starts,
// the order in which the old server's late listen could take the path.
func TestAPISocketAfterReconfigure(t *testing.T) {
	dir, err := os.MkdirTemp("", "gobgp-api")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := apiSocketPath(dir, testAPIKey)
	s := newServer(Config{APISocket: socket})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	if err := s.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := s.Reconfigure(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.bgp.Load().StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 65003, RouterId: "192.0.2.3", ListenPort: -1,
	}}); err != nil {
		t.Fatalf("StartBgp: %v", err)
	}

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	got, err := api.NewGoBgpServiceClient(conn).GetBgp(callCtx(t), &api.GetBgpRequest{})
	if err != nil {
		t.Fatalf("GetBgp after Reconfigure: %v", err)
	}
	if got.GetGlobal().GetAsn() != 65003 {
		t.Errorf("GetBgp ASN = %d, want 65003 from the replacement server", got.GetGlobal().GetAsn())
	}
}

func TestAPISocketPath(t *testing.T) {
	if got := apiSocketPath("", types.NamespacedName{Name: "a"}); got != "" {
		t.Errorf("empty dir = %q, want empty", got)
	}
	got := apiSocketPath("/run/galactic-router", testAPIKey)
	if want := "/run/galactic-router/ns_node-a.sock"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	long := apiSocketPath("/run/galactic-router", types.NamespacedName{Namespace: "ns", Name: strings.Repeat("n", 200)})
	if len(long) > maxSocketPath || filepath.Dir(long) != "/run/galactic-router" {
		t.Errorf("long name path = %q, want a hashed name under the directory", long)
	}
}

// TestAPISocketUnboundDoesNotStall checks a socket that can't be bound costs
// the server start no wait.
func TestAPISocketUnboundDoesNotStall(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "missing", "node.sock")
	s := newServer(Config{APISocket: socket})
	start := time.Now()
	b := s.newBgpServer()
	defer b.Stop()
	if d := time.Since(start); d > time.Second {
		t.Errorf("newBgpServer took %s with an unbindable socket, want no wait", d)
	}
}
