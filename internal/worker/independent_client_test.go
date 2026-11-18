// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/module"
)

type tokenReviewer map[string]authenticationv1.UserInfo

func (r tokenReviewer) Review(_ context.Context, token string) (authenticationv1.UserInfo, error) {
	if u, ok := r[token]; ok {
		return u, nil
	}
	return authenticationv1.UserInfo{}, errors.New("not authenticated")
}

// exePods maps a peer to a pod by its executable: the built client binary
// stands in for a process of the client's pod.
type exePods struct {
	exe string
	pod string
}

func (p exePods) PodUID(pid int32) (string, error) {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	if exe != p.exe {
		return "", fmt.Errorf("peer %d runs %s, not the client", pid, exe)
	}
	return p.pod, nil
}

// TestIndependentClient builds examples/worker-client, an independent module
// that imports only the published Worker API, and runs its lifecycle
// against a real Worker on a unix socket with the real authentication
// chain: TokenReview (faked), SO_PEERCRED and the allowlist. The client's
// ServiceAccount may use local.veth_pair only; the lifecycle also checks
// that a tap claim is refused.
func TestIndependentClient(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the example client")
	}
	dir, err := os.MkdirTemp("", "wk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "worker-client")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".")
	build.Dir = filepath.Join("..", "..", "examples", "worker-client")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the example client: %v\n%s", err, out)
	}
	bin, err = filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("client-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := newEnv(t)
	const sa = "galactic-system/worker-client"
	authn := &auth.Authenticator{
		Reviewer: tokenReviewer{"client-token": {Username: "system:serviceaccount:galactic-system:worker-client",
			Extra: map[string]authenticationv1.ExtraValue{auth.ExtraPodUID: {"pod-client"}, auth.ExtraNodeName: {node}}}},
		Pods:      exePods{exe: bin, pod: "pod-client"},
		Allowlist: auth.NewAllowlist(map[string][]string{sa: {workerv1alpha1.CapabilityLocalVethPair}}),
		Node:      node,
	}
	e.start() // for the fake modules over the shared host
	e.crash()
	reg, err := module.NewRegistry(e.local, e.fabric)
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(e.cfg, Deps{Store: e.store, Fence: e.fence, Sources: e.src, Modules: reg, Auth: authn})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "worker.sock")
	lis, err := Listen(ctx, sock, -1)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(sock); err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, %v; want 0660", st.Mode(), err)
	}
	srv := w.NewServer()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	cctx, ccancel := context.WithTimeout(ctx, time.Minute)
	defer ccancel()
	run := exec.CommandContext(cctx, bin, "lifecycle", "--socket", sock, "--token-file", tokenFile,
		"--node", node, "--vpc", vpcA, "--attachment", "svc-a",
		"--destination", "guest-a1", "--update-destination", "guest-a1", "--update-destination", "guest-a3",
		"--handoff", "veth_pair", "--forbidden-handoff", "tap")
	out, err := run.CombinedOutput()
	t.Logf("client output:\n%s", out)
	if err != nil {
		t.Fatalf("independent client failed: %v", err)
	}
	if !strings.Contains(string(out), "lifecycle passed") {
		t.Fatal("the client did not complete its lifecycle")
	}
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows after the client released its claim = %v", rowIDs(rows))
	}

	// Another process with the client's token is not the client's pod.
	other := exec.CommandContext(cctx, "go", "run", ".", "capabilities", "--socket", sock, "--token-file", tokenFile)
	other.Dir = build.Dir
	if out, err := other.CombinedOutput(); err == nil || !strings.Contains(string(out), workerv1alpha1.ReasonNoIdentity) &&
		!strings.Contains(string(out), "Unauthenticated") {
		t.Fatalf("a process outside the token's pod was accepted: %v\n%s", err, out)
	}
}
