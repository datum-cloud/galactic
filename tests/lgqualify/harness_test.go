// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lgqualify_test qualifies the Looking Glass service backend
// (docs/designs/looking-glass-service.md) on real fabric routers: the
// containerlab lab's dfw cell, with the service enabled by
// deploy:looking-glass. Every request goes through the independent client
// in examples/looking-glass-client, built from the published service API
// alone; this package only drives the lab around it (certificates, faults,
// packet counters, metrics) and judges the client's records against
// thresholds fixed in thresholds.go before any run.
//
// It skips unless LG_QUALIFY_KUBECONFIG names dfw's kubeconfig. The client
// runs inside the dfw-worker node container, the node both gateway
// replicas run on, and reaches them through the gateway Service. Probe
// packets are counted by iptables rules in every dfw node's network
// namespace, where the fabric-api sidecars send them. Run it with
// task verify:looking-glass, which writes evidence to bin/lg-qualify/.
package lgqualify_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	ns          = "galactic-system"
	cell        = "dfw"
	gatewayPort = 9346
	// clientNode runs the client: both gateway replicas run there, and it
	// is the dfw node that reaches the gateway Service.
	clientNode = "dfw-worker"
	clientDir  = "/opt/lg-qualify"
	leaseName  = "fabric-api-gateway"
	switchName = "fabric-api-service"
	// The lab's probe destinations (deploy/containerlab/node_files/tr4):
	// remote-host answers on the first two; the sink prefixes are dropped
	// silently, so probes toward them are lost and traceroutes run long.
	answer4 = "11.1.40.2"
	answer6 = "2c0f:40::2"
)

// The client's query types and outcome results.
const (
	bgpSummary  = "BGPSummary"
	routeLookup = "RouteLookup"
	ping        = "Ping"
	traceroute  = "Traceroute"
	observation = "observation"
	failure     = "failure"
)

// The client's run flags the suite sets.
const (
	fProject = "-project"
	fType    = "-type"
	fTarget  = "-target"
	fFamily  = "-family"
	fNodes   = "-nodes"
	fExpires = "-expires-in"
)

const (
	ipv4 = "IPv4"
	ipv6 = "IPv6"
)

// Status codes and reasons the suite expects by name.
const (
	codeFailedPrecondition      = "FailedPrecondition"
	reasonInvalidQuery          = "InvalidQuery"
	reasonDestinationNotAllowed = "DestinationNotAllowed"
	reasonNotRequested          = "NotRequested"
)

// The contract's acceptance rows (looking-glass-service.md, "Acceptance matrix
// and evidence") each scenario evidences.
const (
	rowA1  = "A1"
	rowA2  = "A2"
	rowA3  = "A3"
	rowA4  = "A4"
	rowA5  = "A5"
	rowA6  = "A6"
	rowA7  = "A7"
	rowA8  = "A8"
	rowA9  = "A9"
	rowA10 = "A10"
	rowA11 = "A11"
	rowA12 = "A12"
	rowA13 = "A13"
	rowA14 = "A14"
	rowA15 = "A15"
	rowA16 = "A16"
	rowA17 = "A17"
)

const (
	fabricRouterSelector = "app.kubernetes.io/name=fabric-router"
	certsSelector        = "app.kubernetes.io/name=fabric-api-certs"
	iptables             = "iptables"
	ip6tables            = "ip6tables"
	certFile             = "tls.crt"
	keyFile              = "tls.key"
	caFile               = "ca.crt"
	dockerExec           = "exec"
	// projectPrefix starts every project UID the suite sends.
	projectPrefix = "lgq-"
	// commandTimeout bounds every command the suite runs on a node.
	commandTimeout = 2 * time.Minute
)

// spec is the client's workload spec (examples/looking-glass-client,
// internal/load).
type spec struct {
	Groups []group `json:"groups"`
}

type group struct {
	Name        string   `json:"name"`
	Count       int      `json:"count"`
	Concurrency int      `json:"concurrency"`
	Interval    string   `json:"interval,omitempty"`
	StartAfter  string   `json:"startAfter,omitempty"`
	Projects    []string `json:"projects,omitempty"`
	Options     options  `json:"options"`
}

type options struct {
	Query query    `json:"query"`
	Nodes []string `json:"nodes,omitempty"`
}

type query struct {
	Type   string `json:"type"`
	Target string `json:"target,omitempty"`
	Family string `json:"family,omitempty"`
}

// routers are dfw's fabric routers.
var routers = []string{"dfw-worker", "dfw-worker2", "dfw-worker3"}

// sink returns a distinct address in the lab's probe sink for family 4 or
// 6, so tests do not share a destination host bucket.
func sink(family, n int) string {
	if family == 4 {
		return fmt.Sprintf("11.1.42.%d", n)
	}
	return fmt.Sprintf("2c0f:42::%x", n)
}

// lab is the cell under test.
type lab struct {
	kubeconfig string
	cs         kubernetes.Interface
	root       string
	out        string
	runID      string
	clusterIP  string

	mu   sync.Mutex
	seq  int
	sink int
}

var (
	theLab     *lab
	labOnce    sync.Once
	errLabInit error
	skipReason string
)

func getLab(t *testing.T) *lab {
	t.Helper()
	labOnce.Do(func() {
		kc := os.Getenv("LG_QUALIFY_KUBECONFIG")
		if kc == "" {
			skipReason = "LG_QUALIFY_KUBECONFIG is not set; run task verify:looking-glass"
			return
		}
		theLab, errLabInit = newLab(kc)
	})
	if skipReason != "" {
		t.Skip(skipReason)
	}
	if errLabInit != nil {
		t.Fatalf("lab: %v", errLabInit)
	}
	return theLab
}

func newLab(kubeconfig string) (*lab, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return nil, err
	}
	runID := time.Now().UTC().Format("20060102t150405")
	out := os.Getenv("LG_QUALIFY_ARTIFACTS")
	if out == "" {
		out = filepath.Join(root, "bin", "lg-qualify", runID)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	svc, err := cs.CoreV1().Services(ns).Get(context.Background(), "fabric-api-gateway", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return &lab{
		kubeconfig: kubeconfig, cs: cs, root: root, out: out, runID: runID, clusterIP: svc.Spec.ClusterIP, sink: 10,
	}, nil
}

// project returns a project UID no earlier request of the run used, so a
// test starts with a full project bucket.
func (l *lab) project() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	return fmt.Sprintf("%s%s-%d", projectPrefix, l.runID, l.seq)
}

// sinkHost returns a probe sink address no earlier test of the run used.
func (l *lab) sinkHost(family int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sink++
	return sink(family, l.sink)
}

// nodeExec runs a command in a Kind node container.
func nodeExec(node string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{dockerExec, node}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("%s %v: %w: %s", node, args, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// clientWrite writes data to path on clientNode. docker cp cannot write
// below a tmpfs mount, which Kind nodes have, so it streams through a shell.
func clientWrite(path string, data []byte, mode os.FileMode) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", dockerExec, "-i", clientNode, "sh", "-c",
		fmt.Sprintf("mkdir -p %q && cat > %q && chmod %o %q", filepath.Dir(path), path, mode, path))
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write %s:%s: %w: %s", clientNode, path, err, out)
	}
	return nil
}

// kubectl runs kubectl against the cell.
func (l *lab) kubectl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", l.kubeconfig}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("kubectl %v: %w: %s", args, err, out)
	}
	return string(out), nil
}

// identity names a set of credentials installed under clientDir on
// clientNode.
type identity string

const (
	idService   identity = "service"
	idUnlisted  identity = "unlisted"
	idOtherCell identity = "other-cell"
	idOperator  identity = "operator"
	idExpired   identity = "expired"
	idNone      identity = "none"
)

// installClient copies the client binary, the fabric-api CLI and every
// identity's credentials onto clientNode.
func (l *lab) installClient(clientBin, fabricAPIBin string, expired [2][]byte) error {
	for path, src := range map[string]string{"lgc": clientBin, "fabric-api": fabricAPIBin} {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := clientWrite(clientDir+"/"+path, data, 0o755); err != nil {
			return err
		}
	}
	secrets := map[identity]string{
		idService: "lg-qualify-looking-glass", idUnlisted: "lg-qualify-unlisted",
		idOtherCell: "lg-qualify-other-cell", idOperator: "fabric-api-operator",
	}
	for id, name := range secrets {
		s, err := l.cs.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, f := range []string{certFile, keyFile, caFile} {
			if err := clientWrite(fmt.Sprintf("%s/%s/%s", clientDir, id, f), s.Data[f], 0o600); err != nil {
				return err
			}
		}
	}
	ca, err := l.cs.CoreV1().Secrets(ns).Get(context.Background(), "fabric-api-ca", metav1.GetOptions{})
	if err != nil {
		return err
	}
	for f, data := range map[string][]byte{certFile: expired[0], keyFile: expired[1], caFile: ca.Data[certFile]} {
		if err := clientWrite(fmt.Sprintf("%s/%s/%s", clientDir, idExpired, f), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// lgc runs the client on clientNode as id and returns its JSON lines.
func (l *lab) lgc(ctx context.Context, id identity, sub string, args ...string) ([]json.RawMessage, error) {
	lines, _, err := l.lgcEvents(ctx, id, sub, args...)
	return lines, err
}

// lgcEvents is lgc that also returns what the client printed to stderr:
// with run --events, every event as a JSON line.
func (l *lab) lgcEvents(
	ctx context.Context, id identity, sub string, args ...string,
) ([]json.RawMessage, []json.RawMessage, error) {
	cred := id
	if id == idNone {
		cred = idService
	}
	full := []string{dockerExec, clientNode, clientDir + "/lgc", sub,
		"--addr", fmt.Sprintf("[%s]:%d", l.clusterIP, gatewayPort), "--cell", cell,
		"--ca", fmt.Sprintf("%s/%s/ca.crt", clientDir, cred)}
	if id == idNone {
		full = append(full, "--cert", "")
	} else {
		full = append(full,
			"--cert", fmt.Sprintf("%s/%s/%s", clientDir, id, certFile),
			"--key", fmt.Sprintf("%s/%s/%s", clientDir, id, keyFile))
	}
	cmd := exec.CommandContext(ctx, "docker", append(full, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("client %s %v: %w: %s", sub, args, err, strings.TrimSpace(stderr.String()))
	}
	lines, err := jsonLines(&stdout)
	if err != nil {
		return nil, nil, err
	}
	events, _ := jsonLines(&stderr)
	return lines, events, nil
}

func jsonLines(b *bytes.Buffer) ([]json.RawMessage, error) {
	var lines []json.RawMessage
	sc := bufio.NewScanner(b)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 && sc.Bytes()[0] == '{' {
			lines = append(lines, json.RawMessage(slices.Clone(sc.Bytes())))
		}
	}
	return lines, sc.Err()
}

// Record mirrors the client's record (examples/looking-glass-client,
// internal/run.Record) as far as the suite judges it.
type Record struct {
	Group     string    `json:"group,omitempty"`
	StartMS   float64   `json:"startMs,omitempty"`
	RequestID string    `json:"requestId"`
	Project   string    `json:"project"`
	StartedAt time.Time `json:"startedAt"`
	Status    struct {
		Code         string            `json:"code"`
		Reason       string            `json:"reason"`
		Domain       string            `json:"domain"`
		Metadata     map[string]string `json:"metadata"`
		RetryDelayMS int64             `json:"retryDelayMs"`
		MessageBytes int               `json:"messageBytes"`
	} `json:"status"`
	Stream struct {
		Delivered      bool              `json:"delivered"`
		Violations     []string          `json:"violations"`
		Selected       []string          `json:"selected"`
		OmittedReasons map[string]string `json:"omittedReasons"`
		Outcomes       []struct {
			Node      string `json:"node"`
			Result    string `json:"result"`
			Reason    string `json:"reason"`
			Scope     string `json:"scope"`
			Truncated bool   `json:"truncated"`
		} `json:"outcomes"`
		Pending  []string `json:"pending"`
		Complete *struct {
			Expected   int `json:"expected"`
			Successful int `json:"successful"`
			Failed     int `json:"failed"`
			Omitted    int `json:"omitted"`
		} `json:"complete"`
		Reason string `json:"reason"`
	} `json:"stream"`
	Events        int `json:"events"`
	Bytes         int `json:"bytes"`
	MaxEventBytes int `json:"maxEventBytes"`
	Timing        struct {
		FirstEventMS  float64   `json:"firstEventMs"`
		SnapshotMS    float64   `json:"snapshotMs"`
		CompleteMS    float64   `json:"completeMs"`
		EndMS         float64   `json:"endMs"`
		CancelMS      float64   `json:"cancelMs"`
		CancelToEndMS float64   `json:"cancelToEndMs"`
		OutcomeMS     []float64 `json:"outcomeMs"`
	} `json:"timing"`
}

// ok reports whether r ended with gRPC OK.
func (r Record) ok() bool { return r.Status.Code == "OK" }

// status is "<code>/<reason>".
func (r Record) status() string { return r.Status.Code + "/" + r.Status.Reason }

// endAt is when r's stream ended, on the wall clock.
func (r Record) endAt() time.Time {
	return r.StartedAt.Add(time.Duration(r.Timing.EndMS * float64(time.Millisecond)))
}

// run runs one diagnostic as id with the client's run flags.
func (l *lab) run(ctx context.Context, id identity, args ...string) (Record, error) {
	lines, err := l.lgc(ctx, id, "run", args...)
	if err != nil {
		return Record{}, err
	}
	if len(lines) != 1 {
		return Record{}, fmt.Errorf("client printed %d lines", len(lines))
	}
	var r Record
	return r, json.Unmarshal(lines[0], &r)
}

// runEvents runs one diagnostic as id and also returns its events,
// payloads included.
func (l *lab) runEvents(ctx context.Context, id identity, args ...string) (Record, []json.RawMessage, error) {
	lines, events, err := l.lgcEvents(ctx, id, "run", append([]string{"-events"}, args...)...)
	if err != nil {
		return Record{}, nil, err
	}
	if len(lines) != 1 {
		return Record{}, nil, fmt.Errorf("client printed %d lines", len(lines))
	}
	var r Record
	return r, events, json.Unmarshal(lines[0], &r)
}

// load runs a workload and returns its records and summaries.
func (l *lab) load(ctx context.Context, s spec) ([]Record, []json.RawMessage, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, nil, err
	}
	path := fmt.Sprintf("%s/spec-%d.json", clientDir, time.Now().UnixNano())
	if err := clientWrite(path, data, 0o600); err != nil {
		return nil, nil, err
	}
	lines, err := l.lgc(ctx, idService, "load", "--spec", path)
	if err != nil {
		return nil, nil, err
	}
	var recs []Record
	var sums []json.RawMessage
	for _, line := range lines {
		var probe struct {
			Summary json.RawMessage `json:"summary"`
		}
		if json.Unmarshal(line, &probe) == nil && probe.Summary != nil {
			sums = append(sums, probe.Summary)
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, nil, err
		}
		recs = append(recs, r)
	}
	return recs, sums, nil
}

// operator runs the fabric-api CLI's query subcommand on clientNode with
// the lab's operator identity, as the legacy operator interface.
func (l *lab) operator(ctx context.Context, args ...string) (string, error) {
	full := append([]string{dockerExec, clientNode, clientDir + "/fabric-api",
		"--log-level", "warn",
		"query", "--cell", cell, "--operator", "lab-verify",
		"--tls-cert", clientDir + "/operator/tls.crt", "--tls-key", clientDir + "/operator/tls.key",
		"--tls-ca", clientDir + "/operator/ca.crt"}, args...)
	out, err := exec.CommandContext(ctx, "docker", full...).CombinedOutput()
	return string(out), err
}

// viaGateway prefixes the query CLI's arguments with the gateway's
// address, for an operator call through the gateway's debug service.
func (l *lab) viaGateway(args ...string) []string {
	return append([]string{"--gateway", fmt.Sprintf("[%s]:%d", l.clusterIP, gatewayPort)}, args...)
}

// answers is a legacy query's result in the evidence.
type answers struct {
	Reason       string   `json:"reason,omitempty"`
	Observations int      `json:"observations"`
	Errors       []string `json:"errors,omitempty"`
	Failed       bool     `json:"failed,omitempty"`
}

// fault records which gateway pod a fault hit, and when.
type fault struct {
	Pod string    `json:"pod"`
	At  time.Time `json:"at"`
}

// waitReady waits until a request is admitted: after a gateway start the
// leader serves its 125 s recovery hold first.
func (l *lab) waitReady(ctx context.Context, timeout time.Duration) (time.Time, error) {
	deadline := time.Now().Add(timeout)
	for {
		r, err := l.run(ctx, idService, fProject, l.project(), fType, bgpSummary, fFamily, "IPv4", fNodes, routers[0])
		if err == nil && r.ok() {
			return r.StartedAt, nil
		}
		if time.Now().After(deadline) {
			return time.Time{}, fmt.Errorf("not admitting after %s: %+v: %w", timeout, r.Status, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// settle waits for the cell's request bucket to refill: 8 tokens at 2/s.
func settle() { time.Sleep(4500 * time.Millisecond) }

// leader returns the gateway pod holding the lease and its holder identity.
func (l *lab) leader(ctx context.Context) (string, string, error) {
	lease, err := l.cs.CoordinationV1().Leases(ns).Get(ctx, leaseName, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	return leaseHolder(lease)
}

func leaseHolder(lease *coordinationv1.Lease) (string, string, error) {
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return "", "", errors.New("lease has no holder")
	}
	h := *lease.Spec.HolderIdentity
	pod, _, _ := strings.Cut(h, "_")
	return pod, h, nil
}

// waitNewLeader waits until the lease names a holder other than old and
// returns it with the moment it was observed.
func (l *lab) waitNewLeader(ctx context.Context, old string, timeout time.Duration) (string, time.Time, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, holder, err := l.leader(ctx); err == nil && holder != old {
			return holder, time.Now(), nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", time.Time{}, fmt.Errorf("no new leader within %s", timeout)
}

// gatewayPods returns the gateway pods.
func (l *lab) gatewayPods(ctx context.Context) ([]corev1.Pod, error) {
	pods, err := l.cs.CoreV1().Pods(ns).List(ctx,
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=fabric-api-gateway"})
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

// setSwitch sets the service switch.
func (l *lab) setSwitch(ctx context.Context, value string) error {
	patch := fmt.Sprintf(`{"data":{"service":%q}}`, value)
	_, err := l.cs.CoreV1().ConfigMaps(ns).Patch(ctx, switchName, types.MergePatchType, []byte(patch),
		metav1.PatchOptions{})
	return err
}

// metrics scrapes a /metrics endpoint from clientNode, which reaches both
// the gateway pods and every node's sidecar.
func metrics(ctx context.Context, url string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", dockerExec, clientNode, "curl", "-sf", "--max-time", "3", url).Output()
	return string(out), err
}

// metricValue sums the samples of name whose labels include every label in
// match (`key="value"` strings).
func metricValue(text, name string, match ...string) (float64, bool) {
	var sum float64
	found := false
	for line := range strings.SplitSeq(text, "\n") {
		if !strings.HasPrefix(line, name) || strings.HasPrefix(line, "#") {
			continue
		}
		rest := line[len(name):]
		if rest == "" || (rest[0] != '{' && rest[0] != ' ') {
			continue
		}
		if !allIn(rest, match) {
			continue
		}
		f := strings.Fields(rest[strings.LastIndex(rest, "}")+1:])
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err == nil {
			sum += v
			found = true
		}
	}
	return sum, found
}

func allIn(s string, subs []string) bool {
	for _, m := range subs {
		if !strings.Contains(s, m) {
			return false
		}
	}
	return true
}

// gatewayMetrics scrapes pod's gateway metrics.
func (l *lab) gatewayMetrics(ctx context.Context, pod corev1.Pod) (string, error) {
	return metrics(ctx, fmt.Sprintf("http://[%s]:9347/metrics", pod.Status.PodIP))
}

// nodeMetrics scrapes the fabric-api sidecar's metrics on each router.
func (l *lab) nodeMetrics(ctx context.Context) (map[string]string, error) {
	pods, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: fabricRouterSelector})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range pods.Items {
		ip, err := netip.ParseAddr(p.Status.HostIP)
		if err != nil {
			return nil, err
		}
		text, err := metrics(ctx, "http://"+netip.AddrPortFrom(ip, 9345).String()+"/metrics")
		if err != nil {
			return nil, fmt.Errorf("%s metrics: %w", p.Spec.NodeName, err)
		}
		out[p.Spec.NodeName] = text
	}
	return out, nil
}

// evidence is one scenario's record in the run's artifacts.
type evidence struct {
	Scenario   string         `json:"scenario"`
	Rows       []string       `json:"rows"`
	Thresholds map[string]any `json:"thresholds,omitempty"`
	Observed   map[string]any `json:"observed"`
	Outcome    string         `json:"outcome"`
	Notes      []string       `json:"notes,omitempty"`
	Started    time.Time      `json:"started"`
	Finished   time.Time      `json:"finished"`
}

// scenarioFunc is one scenario of the suite.
type scenarioFunc func(ctx context.Context, t *testing.T, l *lab, ev *evidence)

// scenario runs fn as a subtest and writes its evidence whatever happens,
// naming the acceptance rows it evidences. A scenario fails through
// t.Errorf/Fatalf; its outcome is "passed" only when the subtest did not
// fail or skip.
func (l *lab) scenario(ctx context.Context, t *testing.T, name string, fn scenarioFunc, rows ...string) {
	t.Run(name, func(t *testing.T) {
		ev := &evidence{Scenario: name, Rows: rows, Observed: map[string]any{}, Started: time.Now().UTC()}
		defer func() {
			ev.Finished = time.Now().UTC()
			switch {
			case t.Skipped():
				ev.Outcome = "not run"
			case t.Failed():
				ev.Outcome = "failed"
			default:
				ev.Outcome = "passed"
			}
			data, _ := json.MarshalIndent(ev, "", "  ")
			_ = os.WriteFile(filepath.Join(l.out, name+".json"), data, 0o644)
		}()
		fn(ctx, t, l, ev)
	})
}

// saveRecords writes records to the run's artifacts as JSON lines.
func (l *lab) saveRecords(name string, recs []Record) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, r := range recs {
		_ = enc.Encode(r)
	}
	_ = os.WriteFile(filepath.Join(l.out, name+".records.jsonl"), b.Bytes(), 0o644)
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// podLogs returns a pod container's log since t, its previous instance's
// first when it restarted.
func (l *lab) podLogs(ctx context.Context, pod, container string, since time.Time) (string, error) {
	st := metav1.NewTime(since)
	pods := l.cs.CoreV1().Pods(ns)
	prev, _ := pods.GetLogs(pod, &corev1.PodLogOptions{Container: container, SinceTime: &st, Previous: true}).DoRaw(ctx)
	raw, err := pods.GetLogs(pod, &corev1.PodLogOptions{Container: container, SinceTime: &st}).DoRaw(ctx)
	return ansi.ReplaceAllString(string(prev)+string(raw), ""), err
}
