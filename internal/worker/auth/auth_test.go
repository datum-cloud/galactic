// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/refusal"
)

const podOne = "pod-1"

func TestParseAllowlist(t *testing.T) {
	a, err := ParseAllowlist([]byte(`
serviceAccounts:
- serviceAccount: galactic-system/galactic-nat
  capabilities: [local.veth_pair, fabric.srv6]
- serviceAccount: galactic-system/galactic-gateway
  capabilities: [local.tap]
`))
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := a.Capabilities("galactic-system/galactic-nat"); !ok || len(c) != 2 {
		t.Fatalf("nat capabilities = %v, %t", c, ok)
	}
	if _, ok := a.Capabilities("galactic-system/unknown"); ok {
		t.Fatal("an unlisted ServiceAccount is listed")
	}
	for name, doc := range map[string]string{
		"unknown capability": "serviceAccounts:\n- serviceAccount: a/b\n  capabilities: [local.everything]\n",
		"no namespace":       "serviceAccounts:\n- serviceAccount: b\n  capabilities: []\n",
		"listed twice":       "serviceAccounts:\n- serviceAccount: a/b\n- serviceAccount: a/b\n",
		"unknown field":      "serviceAccounts:\n- serviceAccount: a/b\n  role: admin\n",
	} {
		if _, err := ParseAllowlist([]byte(doc)); err == nil {
			t.Errorf("%s: ParseAllowlist() = nil error", name)
		}
	}
}

func TestPodUIDFromCgroup(t *testing.T) {
	const uid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	for name, tc := range map[string]struct {
		cgroup string
		want   string
	}{
		"systemd v2": {"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" +
			"0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0.slice/cri-containerd-abc.scope\n", uid},
		"cgroupfs v1": {"12:memory:/kubepods/besteffort/pod" + uid + "/0123456789abcdef\n" +
			"11:cpu:/kubepods/besteffort/pod" + uid + "/0123456789abcdef\n", uid},
		"not in a pod": {"0::/system.slice/kubelet.service\n", ""},
		"two pods": {"1:a:/kubepods/pod" + uid + "/x\n2:b:/kubepods/pod" +
			"11111111-2222-3333-4444-555555555555/y\n", ""},
	} {
		got, err := PodUIDFromCgroup(tc.cgroup)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: got %q, want an error", name, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", name, got, err, tc.want)
		}
	}
	if _, err := (CgroupPodResolver{}).PodUID(0); err == nil {
		t.Error("PID 0 resolved; a peer outside the host PID namespace must be refused")
	}
}

func TestCgroupPodResolverReadsProc(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "42", "cgroup"),
		[]byte("0::/kubepods/pod11111111-2222-3333-4444-555555555555/c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := CgroupPodResolver{ProcRoot: root}.PodUID(42)
	if err != nil || got != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("PodUID = %q, %v", got, err)
	}
}

type reviewer struct {
	calls atomic.Int32
	users map[string]authenticationv1.UserInfo
}

func (r *reviewer) Review(_ context.Context, token string) (authenticationv1.UserInfo, error) {
	r.calls.Add(1)
	u, ok := r.users[token]
	if !ok {
		return authenticationv1.UserInfo{}, errors.New("not authenticated")
	}
	return u, nil
}

type pods map[int32]string

func (p pods) PodUID(pid int32) (string, error) {
	if uid, ok := p[pid]; ok {
		return uid, nil
	}
	return "", fmt.Errorf("pid %d not in a pod", pid)
}

func jwt(exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix()))) + ".sig"
}

func user(sa, pod, node string) authenticationv1.UserInfo {
	return authenticationv1.UserInfo{Username: "system:serviceaccount:" + sa,
		Extra: map[string]authenticationv1.ExtraValue{
			ExtraPodUID: {pod}, ExtraPodName: {"p"}, ExtraNodeName: {node},
		}}
}

// TestAuthenticatorOverUnixSocket runs the chain on a real unix socket, so
// SO_PEERCRED reports this test process.
func TestAuthenticatorOverUnixSocket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	valid, expired := jwt(now.Add(time.Hour)), jwt(now.Add(-time.Minute))
	rev := &reviewer{users: map[string]authenticationv1.UserInfo{
		valid:        user("galactic-system:galactic-nat", podOne, "node-a"),
		"other-node": user("galactic-system:galactic-nat", podOne, "node-b"),
		"other-pod":  user("galactic-system:galactic-nat", "pod-2", "node-a"),
		"unlisted":   user("galactic-system:intruder", podOne, "node-a"),
		"user":       {Username: "alice", Extra: map[string]authenticationv1.ExtraValue{ExtraPodUID: {podOne}}},
		"unbound":    {Username: "system:serviceaccount:galactic-system:galactic-nat"},
	}}
	a := &Authenticator{
		Reviewer: rev,
		Pods:     pods{int32(os.Getpid()): podOne},
		Allowlist: NewAllowlist(map[string][]string{
			"galactic-system/galactic-nat": {workerv1alpha1.CapabilityLocalVethPair},
		}),
		Node: "node-a",
		Now:  func() time.Time { return now },
	}

	results := make(chan any, 1)
	sock := filepath.Join(t.TempDir(), "w.sock")
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(PeerCredentials{}), grpc.UnaryInterceptor(
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if p, ok := PeerFromContext(ctx); !ok || p.PID != int32(os.Getpid()) {
				return nil, status.Error(codes.Internal, "peer credentials missing or wrong")
			}
			c, err := a.Authenticate(ctx)
			if err != nil {
				return nil, err
			}
			results <- c
			return h(ctx, req)
		}))
	grpc_health_v1.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///w", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	hc := grpc_health_v1.NewHealthClient(cc)
	call := func(token string) error {
		ctx := context.Background()
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}
		_, err := hc.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		return err
	}

	if err := call(valid); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	c := (<-results).(Caller)
	if c.ServiceAccount != "galactic-system/galactic-nat" || c.PodUID != podOne ||
		!c.Allowed(workerv1alpha1.CapabilityLocalVethPair) || c.Allowed(workerv1alpha1.CapabilityFabricSRv6) {
		t.Fatalf("caller = %+v", c)
	}
	if err := call(valid); err != nil {
		t.Fatal(err)
	}
	<-results
	if n := rev.calls.Load(); n != 1 {
		t.Fatalf("TokenReview ran %d times, want 1: the result is cached until the token expires", n)
	}

	for name, tc := range map[string]struct {
		token  string
		code   codes.Code
		reason string
	}{
		"no token":   {"", codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity},
		"expired":    {expired, codes.Unauthenticated, workerv1alpha1.ReasonIdentityExpired},
		"refused":    {"forged", codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity},
		"other node": {"other-node", codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity},
		"other pod":  {"other-pod", codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity},
		"not an SA":  {"user", codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity},
		"not bound":  {"unbound", codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity},
		"not listed": {"unlisted", codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed},
	} {
		err := call(tc.token)
		if !refusal.Is(err, tc.code, tc.reason) {
			t.Errorf("%s: got %v (reason %q), want %s/%s", name, err, refusal.Reason(err), tc.code, tc.reason)
		}
	}
}
