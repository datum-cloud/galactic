// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestQualify runs every scenario in order against one cell. The order
// matters: the scenarios that restart or isolate the gateway leader come
// last, since each costs a 125 s recovery hold, and the routing-impact
// trials run after the functional ones so a broken service fails fast.
func TestQualify(t *testing.T) {
	l := getLab(t)
	ctx := t.Context()

	clientBin := os.Getenv("LG_QUALIFY_CLIENT")
	fabricAPIBin := os.Getenv("LG_QUALIFY_FABRIC_API")
	if clientBin == "" || fabricAPIBin == "" {
		t.Fatal("LG_QUALIFY_CLIENT and LG_QUALIFY_FABRIC_API must name the client and fabric-api binaries")
	}
	expired, err := expiredCert(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.installClient(clientBin, fabricAPIBin, expired); err != nil {
		t.Fatal(err)
	}
	if err := installChain(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeChain(); err != nil {
			t.Error(err)
		}
		_, _ = nodeExec(clientNode, "rm", "-rf", clientDir)
	})
	logsFrom := time.Now()
	use := l.startSampler(ctx)
	t.Logf("evidence: %s", l.out)

	l.scenario(ctx, t, "preflight", preflight, rowA17)
	l.scenario(ctx, t, "authorization", authorization, rowA1, rowA2)
	l.scenario(ctx, t, "compatibility", compatibility, rowA7)
	l.scenario(ctx, t, "diagnostics", diagnostics, rowA3, rowA6)
	l.scenario(ctx, t, "coverage", coverage, rowA4, rowA5)
	l.scenario(ctx, t, "destinations", destinations, rowA3)
	l.scenario(ctx, t, "legacy", legacy, rowA16)
	l.scenario(ctx, t, "bursts", bursts, rowA8)
	l.scenario(ctx, t, "fairness", fairness, rowA8)
	l.scenario(ctx, t, "destination-budget", destinationBudget, rowA9, rowA10)
	l.scenario(ctx, t, "cancellation", cancellation, rowA12)
	l.scenario(ctx, t, "deadline", deadline, rowA12)
	l.scenario(ctx, t, "service-switch", serviceSwitch, rowA12, rowA15)
	l.scenario(ctx, t, "blackhole", blackhole, rowA12)
	l.scenario(ctx, t, "routing-impact", routingImpact, rowA17)
	l.scenario(ctx, t, "leader-crash", leaderCrash, rowA11, rowA14)
	l.scenario(ctx, t, "leader-pause", leaderPause, rowA14)
	l.scenario(ctx, t, "api-isolation", apiIsolation, rowA11, rowA14)
	l.scenario(ctx, t, "resources", func(_ context.Context, t *testing.T, _ *lab, ev *evidence) {
		resources(t, ev, use.close())
	}, rowA13, rowA17)
	l.scenario(ctx, t, "confidentiality", func(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
		confidentiality(ctx, t, l, ev, logsFrom)
	}, rowA15, rowA17)
	l.scenario(ctx, t, "cleanup", cleanup, rowA17)
}

// expiredCert issues, from the cell's lab CA, a looking-glass service
// certificate that expired an hour ago: cert-manager will not issue one.
func expiredCert(ctx context.Context, l *lab) ([2][]byte, error) {
	ca, err := l.cs.CoreV1().Secrets(ns).Get(ctx, "fabric-api-ca", metav1.GetOptions{})
	if err != nil {
		return [2][]byte{}, err
	}
	pair, err := tls.X509KeyPair(ca.Data[certFile], ca.Data[keyFile])
	if err != nil {
		return [2][]byte{}, err
	}
	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return [2][]byte{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return [2][]byte{}, err
	}
	u, _ := url.Parse("spiffe://fabric-api.datumapis.com/cell/" + cell + "/service/looking-glass")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, pair.PrivateKey)
	if err != nil {
		return [2][]byte{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return [2][]byte{}, err
	}
	return [2][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// preflight records what is under test and waits for admission.
func preflight(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	lines, err := l.lgc(ctx, idService, "capabilities")
	if err != nil {
		t.Fatal(err)
	}
	var caps struct {
		Status       struct{ Code string } `json:"status"`
		Capabilities struct {
			Enabled          bool              `json:"enabled"`
			ContractRevision string            `json:"contractRevision"`
			PolicyRevision   string            `json:"policyRevision"`
			Features         []string          `json:"features"`
			Operations       []json.RawMessage `json:"operations"`
			Limits           json.RawMessage   `json:"limits"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(lines[0], &caps); err != nil {
		t.Fatal(err)
	}
	c := caps.Capabilities
	ev.Observed["capabilities"] = lines[0]
	if caps.Status.Code != "OK" || !c.Enabled || len(c.Features) != 3 || len(c.Operations) != 4 {
		t.Fatalf("capabilities: %s", lines[0])
	}

	images := map[string]string{}
	pods, err := l.cs.CoreV1().Pods(ns).List(ctx,
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/name in (fabric-api-gateway,fabric-router)"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name == "gateway" || cs.Name == "fabric-api" {
				images[p.Name+"/"+cs.Name] = cs.ImageID
			}
		}
	}
	ev.Observed["images"] = images
	head, _ := exec.CommandContext(ctx, "git", "-C", l.root, "rev-parse", "HEAD").Output()
	dirty, _ := exec.CommandContext(ctx, "git", "-C", l.root, "status", "--porcelain").Output()
	ev.Observed["checkout"] = map[string]any{"commit": strings.TrimSpace(string(head)), "dirty": len(dirty) > 0}
	if nm, err := l.nodeMetrics(ctx); err == nil {
		frr := map[string]string{}
		for node, text := range nm {
			for line := range strings.SplitSeq(text, "\n") {
				if strings.HasPrefix(line, "fabric_api_node_frr_info{") {
					frr[node] = line
				}
			}
		}
		ev.Observed["frr"] = frr
	}
	ready, err := l.waitReady(ctx, recoveryHold+resumeSlack)
	if err != nil {
		t.Fatal(err)
	}
	ev.Observed["admittingAt"] = ready
	settle()
}

// expectRefused checks r was refused before its snapshot with code and,
// when reason is not empty, that reason.
func expectRefused(t *testing.T, name string, r Record, code, reason string) {
	t.Helper()
	switch {
	case r.Events != 0:
		t.Errorf("%s: %d events delivered to a refused request", name, r.Events)
	case code != "" && r.Status.Code != code:
		t.Errorf("%s: status %s, want %s", name, r.status(), code)
	case reason != "" && r.Status.Reason != reason:
		t.Errorf("%s: status %s, want reason %s", name, r.status(), reason)
	case r.ok():
		t.Errorf("%s: admitted", name)
	}
}

// expectDelivered checks r delivered a valid stream ending reason.
func expectDelivered(t *testing.T, name string, r Record, reason string) {
	t.Helper()
	if !r.ok() || !r.Stream.Delivered || len(r.Stream.Violations) > 0 {
		t.Errorf("%s: status %s, delivered %t, violations %v", name, r.status(), r.Stream.Delivered, r.Stream.Violations)
		return
	}
	if reason != "" && r.Stream.Reason != reason {
		t.Errorf("%s: complete %s, want %s", name, r.Stream.Reason, reason)
	}
}

// outcomeSummary is "node:result[:reason]" per delivered outcome.
func outcomeSummary(r Record) []string {
	out := make([]string, 0, len(r.Stream.Outcomes))
	for _, o := range r.Stream.Outcomes {
		s := o.Node + ":" + o.Result
		if o.Reason != "" {
			s += ":" + o.Reason
		}
		out = append(out, s)
	}
	return out
}

// brief is what the evidence keeps of a record.
func brief(r Record) map[string]any {
	m := map[string]any{"status": r.status(), "events": r.Events, "bytes": r.Bytes}
	if r.Stream.Reason != "" {
		m["complete"] = r.Stream.Reason
		m["counts"] = r.Stream.Complete
	}
	if len(r.Stream.Outcomes) > 0 {
		m["outcomes"] = outcomeSummary(r)
	}
	if len(r.Status.Metadata) > 0 {
		m["metadata"] = r.Status.Metadata
	}
	if r.Status.RetryDelayMS >= 0 {
		m["retryDelayMs"] = r.Status.RetryDelayMS
	}
	if r.Timing.CompleteMS >= 0 {
		m["completeMs"] = r.Timing.CompleteMS
	}
	if len(r.Stream.Violations) > 0 {
		m["violations"] = r.Stream.Violations
	}
	return m
}

// pace spaces requests so a scenario never draws down the cell's request
// bucket (2 tokens/s): its refusals are then its own.
const pace = 550 * time.Millisecond

// mustRun runs one diagnostic, paced, or fails the test on a client error.
func mustRun(ctx context.Context, t *testing.T, l *lab, id identity, args ...string) Record {
	t.Helper()
	time.Sleep(pace)
	r, err := l.run(ctx, id, args...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var errNoLine = errors.New("no matching log line")

// finishedLine returns the gateway's "Looking Glass request finished" log
// line for requestID from any replica.
func (l *lab) finishedLine(ctx context.Context, requestID string, since time.Time) (map[string]any, error) {
	pods, err := l.gatewayPods(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pods {
		logs, err := l.podLogs(ctx, p.Name, "gateway", since)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(logs, "\n") {
			if !strings.Contains(line, requestID) || !strings.Contains(line, "Looking Glass request finished") {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				return m, nil
			}
		}
	}
	return nil, fmt.Errorf("%w for %s", errNoLine, requestID)
}
