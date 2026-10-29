// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The load harness runs only when CONNECTIP_LOAD is set; see
// docs/edge/masque-capacity.md.
const (
	loadEnv           = "CONNECTIP_LOAD"
	loadDurationEnv   = "CONNECTIP_LOAD_DURATION"
	loadWarmupEnv     = "CONNECTIP_LOAD_WARMUP"
	loadRunsEnv       = "CONNECTIP_LOAD_RUNS"
	loadConnectorsEnv = "CONNECTIP_LOAD_CONNECTORS"
	loadReportEnv     = "CONNECTIP_LOAD_REPORT"

	tokenFlood = "test-token-flood"

	// loadExpiryBound is a tenth of how long a revoked session may take to
	// end before the harness fails the run.
	loadExpiryBound = time.Second
	// loadRecoveryWait bounds how long resources may take to return to
	// their level before the run once every client has gone. It exceeds the
	// 30 s QUIC idle timeout, which is how the server learns of a client that
	// vanished without closing its connection.
	loadRecoveryWait = 40 * time.Second
	// loadGoroutineSlack is how many goroutines above that level still
	// count as recovered.
	loadGoroutineSlack = 8
)

type loadConfig struct {
	Duration   time.Duration
	Warmup     time.Duration
	Runs       int
	Connectors []int
	Report     string
}

func loadConfigFromEnv(t *testing.T) loadConfig {
	t.Helper()
	cfg := loadConfig{Duration: 10 * time.Second, Warmup: 2 * time.Second, Runs: 1, Connectors: []int{1, 8, 32},
		Report: os.Getenv(loadReportEnv)}
	for env, d := range map[string]*time.Duration{loadDurationEnv: &cfg.Duration, loadWarmupEnv: &cfg.Warmup} {
		if v := os.Getenv(env); v != "" {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				t.Fatalf("%s: %v", env, err)
			}
			*d = parsed
		}
	}
	if v := os.Getenv(loadRunsEnv); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("%s must be a positive integer", loadRunsEnv)
		}
		cfg.Runs = n
	}
	if v := os.Getenv(loadConnectorsEnv); v != "" {
		cfg.Connectors = nil
		for f := range strings.SplitSeq(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || n < 1 || n > DefaultMaxSessions {
				t.Fatalf("%s: %q is not a connector count from 1 to %d", loadConnectorsEnv, f, DefaultMaxSessions)
			}
			cfg.Connectors = append(cfg.Connectors, n)
		}
	}
	return cfg
}

// loadResult is one run of one scenario.
type loadResult struct {
	Scenario    string `json:"scenario"`
	Transport   string `json:"transport"`
	Connectors  int    `json:"connectors"`
	PacketBytes int    `json:"packetBytes"`
	Run         int    `json:"run"`

	// GoodputMbps counts inner IP bytes in both directions.
	GoodputMbps   float64 `json:"goodputMbps"`
	PacketsPerSec float64 `json:"packetsPerSecPerDirection"`
	RTTp50Ms      float64 `json:"rttP50Ms"`
	RTTp99Ms      float64 `json:"rttP99Ms"`
	LossPct       float64 `json:"lossPct"`
	Misdelivered  uint64  `json:"misdelivered"`
	CPUCores      float64 `json:"cpuCores"`
	RSSPeakMiB    float64 `json:"rssPeakMiB"`
	HeapPeakMiB   float64 `json:"heapPeakMiB"`
	QueueDrops    int64   `json:"queueDrops"`
	QueuePeak     int64   `json:"queuePeakPackets"`

	// Outcomes counts the requests a flood or churn made, by result, and
	// OutcomeErrors gives the first error of each.
	Outcomes      map[string]int    `json:"outcomes,omitempty"`
	OutcomeErrors map[string]string `json:"outcomeErrors,omitempty"`
	// ExpiryMaxMs is the longest a revoked lease's session took to end.
	ExpiryMaxMs float64 `json:"expiryMaxMs,omitempty"`
	// SlowClientEndSec is how long a stalled client's session lasted.
	SlowClientEndSec float64 `json:"slowClientEndSec,omitempty"`
	// Starved counts connectors that received nothing during a disturbance.
	Starved     int     `json:"starved"`
	Recovered   bool    `json:"recovered"`
	RecoverySec float64 `json:"recoverySec"`
}

// loadEnvironment is a server with the reflecting backend.
type loadEnvironment struct {
	*testEnv
	adm *testAdmission
	rb  *reflectBackend
	// base is the goroutine count with the server up and no clients.
	base int
}

func startLoad(t *testing.T, wrap func(*testAdmission) Admission) *loadEnvironment {
	t.Helper()
	adm, rb := newTestAdmission(), newReflectBackend()
	var admission Admission = adm
	if wrap != nil {
		admission = wrap(adm)
	}
	env := startServer(t, func(c *Config) {
		c.Admission = admission
		c.Backend = rb
	})
	time.Sleep(100 * time.Millisecond)
	return &loadEnvironment{testEnv: env, adm: adm, rb: rb, base: runtime.NumGoroutine()}
}

// connect opens n connectors over transport, alternating two tenants whose
// gVPCs hand out the same /96 values. imp, when set, impairs each HTTP/3
// client's socket.
func (e *loadEnvironment) connect(t *testing.T, transport string, n int, imp *impairment) []*connector {
	t.Helper()
	conns := make([]*connector, 0, n)
	t.Cleanup(func() { closeConnectors(conns) })
	for i := range n {
		token, vpc := tokenAlice, vpcBlue
		if i%2 == 1 {
			token, vpc = tokenBob, vpcGreen
		}
		var ic *impairedConn
		if imp != nil && transport == "h3" {
			ic = &impairedConn{imp: *imp}
		}
		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		lc, prefix, err := e.dialLoad(ctx, transport, loadSource().String(), token, vpc, ic)
		cancel()
		if err != nil {
			t.Fatalf("connector %d: %v", i+1, err)
		}
		conns = append(conns, &connector{idx: uint64(i + 1), vpc: vpc, prefix: prefix, conn: lc, imp: ic})
	}
	return conns
}

func closeConnectors(conns []*connector) {
	for _, c := range conns {
		c.conn.close()
	}
}

// traffic runs every connector until stop is called, which waits for their
// senders and then for replies in flight.
type traffic struct {
	ctrs  loadCounters
	hist  atomic.Pointer[rttHist]
	epoch time.Time
	stop  func()
}

func startTraffic(conns []*connector, size int) *traffic {
	tr := &traffic{epoch: time.Now()}
	tr.hist.Store(&rttHist{})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() { c.run(ctx, tr.epoch, size, &tr.ctrs, &tr.hist) })
	}
	tr.stop = func() {
		cancel()
		wg.Wait()
		time.Sleep(500 * time.Millisecond)
	}
	return tr
}

// window measures goodput, latency, CPU and memory between begin and end.
type window struct {
	tr        *traffic
	start     counterSnapshot
	usage     usage
	peakRSS   atomic.Int64
	peakHeap  atomic.Int64
	stopWatch func()
}

func (tr *traffic) begin() *window {
	w := &window{tr: tr}
	tr.hist.Store(&rttHist{})
	w.start, w.usage = tr.ctrs.snapshot(), readUsage()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		var ms runtime.MemStats
		for {
			w.peakRSS.Store(max(w.peakRSS.Load(), rssBytes()))
			runtime.ReadMemStats(&ms)
			w.peakHeap.Store(max(w.peakHeap.Load(), int64(ms.HeapInuse)))
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	})
	w.stopWatch = func() { close(done); wg.Wait() }
	return w
}

func (w *window) end(res *loadResult) {
	w.stopWatch()
	now, end := readUsage(), w.tr.ctrs.snapshot()
	secs := now.at.Sub(w.usage.at).Seconds()
	res.GoodputMbps = 2 * float64(end.recvBytes-w.start.recvBytes) * 8 / secs / 1e6
	res.PacketsPerSec = float64(end.recv-w.start.recv) / secs
	h := w.tr.hist.Load()
	res.RTTp50Ms, res.RTTp99Ms = h.quantile(0.50), h.quantile(0.99)
	res.CPUCores = (now.cpu - w.usage.cpu).Seconds() / secs
	res.RSSPeakMiB = float64(w.peakRSS.Load()) / (1 << 20)
	res.HeapPeakMiB = float64(w.peakHeap.Load()) / (1 << 20)
}

// finish records loss, isolation and queue counters after traffic stops,
// then closes every connector and waits for the server to release them.
func (e *loadEnvironment) finish(t *testing.T, res *loadResult, tr *traffic, conns []*connector) {
	t.Helper()
	tr.stop()
	if sent := tr.ctrs.sent.Load(); sent > 0 {
		res.LossPct = 100 * float64(sent-min(sent, tr.ctrs.recv.Load())) / float64(sent)
	}
	res.Misdelivered = tr.ctrs.misdelivered.Load()
	res.QueueDrops, res.QueuePeak = e.rb.drops.Load(), e.rb.peak.Load()
	if res.Misdelivered != 0 {
		t.Errorf("%d packets reached a connector other than the one that sent them", res.Misdelivered)
	}
	closeConnectors(conns)
	res.Recovered, res.RecoverySec = e.waitRecovered(t)
}

// waitRecovered waits until no session, backend session or QUIC connection
// is open and goroutines are back within loadGoroutineSlack of the level
// before the run.
func (e *loadEnvironment) waitRecovered(t *testing.T) (bool, float64) {
	t.Helper()
	start := time.Now()
	for {
		sessions, open, conns, g := len(e.server.active), e.rb.open.Load(), e.server.conns.Load(), runtime.NumGoroutine()
		if sessions == 0 && open == 0 && conns == 0 && g <= e.base+loadGoroutineSlack {
			return true, time.Since(start).Seconds()
		}
		if time.Since(start) > loadRecoveryWait {
			t.Errorf("not recovered after %v: %d sessions, %d backend sessions, %d QUIC connections, "+
				"%d goroutines (%d before the run)", loadRecoveryWait, sessions, open, conns, g, e.base)
			return false, time.Since(start).Seconds()
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func runThroughput(t *testing.T, cfg loadConfig, res loadResult, imp *impairment) loadResult {
	e := startLoad(t, nil)
	conns := e.connect(t, res.Transport, res.Connectors, imp)
	tr := startTraffic(conns, res.PacketBytes)
	time.Sleep(cfg.Warmup)
	w := tr.begin()
	time.Sleep(cfg.Duration)
	w.end(&res)
	e.finish(t, &res, tr, conns)
	return res
}

// floodAdmission admits flood tokens as bob after delay, so a flood holds
// admission slots the way a slow authority would.
type floodAdmission struct {
	*testAdmission
	delay time.Duration
}

func (a floodAdmission) Admit(ctx context.Context, token, vpc string) (Lease, error) {
	if strings.HasPrefix(token, tokenFlood) {
		select {
		case <-time.After(a.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		token = tokenBob
	}
	return a.testAdmission.Admit(ctx, token, vpc)
}

type outcomes struct {
	mu sync.Mutex
	m  map[string]int
	// examples holds the first error of each outcome.
	examples map[string]string
}

func (o *outcomes) add(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil {
		o.m, o.examples = map[string]int{}, map[string]string{}
	}
	k := outcome(err)
	o.m[k]++
	if _, ok := o.examples[k]; !ok && err != nil {
		o.examples[k] = err.Error()
	}
}

// runOverload floods the server with twice its connection cap of clients,
// each request held in a 2 s admission and kept for 1 s once admitted, while
// 32 connectors carry traffic. One flooder in eight shares a single source
// address. Halfway through, four connectors' leases are revoked.
func runOverload(t *testing.T, cfg loadConfig, res loadResult) loadResult {
	e := startLoad(t, func(a *testAdmission) Admission { return floodAdmission{a, 2 * time.Second} })
	conns := e.connect(t, res.Transport, res.Connectors, nil)
	tr := startTraffic(conns, res.PacketBytes)
	time.Sleep(cfg.Warmup)
	before := make([]uint64, len(conns))
	for i, c := range conns {
		before[i] = c.recv.Load()
	}
	w := tr.begin()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()
	var out outcomes
	var wg sync.WaitGroup
	shared := net.IPv4(127, 3, 0, 1).String()
	for g := range 2 * DefaultMaxConnections {
		wg.Go(func() {
			token := fmt.Sprintf("%s-%d", tokenFlood, g%64)
			for ctx.Err() == nil {
				src := loadSource().String()
				if g%8 == 0 {
					src = shared
				}
				dctx, dcancel := context.WithTimeout(ctx, testTimeout)
				lc, _, err := e.dialLoad(dctx, res.Transport, src, token, vpcGreen, nil)
				dcancel()
				if ctx.Err() != nil && err != nil {
					if lc != nil {
						lc.close()
					}
					return
				}
				out.add(err)
				if err == nil {
					time.Sleep(time.Second)
					lc.close()
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
	time.Sleep(cfg.Duration / 2)
	res.ExpiryMaxMs = e.revoke(t, conns[:4])
	wg.Wait()
	w.end(&res)
	for i, c := range conns[4:] {
		if c.recv.Load() == before[i+4] {
			res.Starved++
		}
	}
	if res.Starved > 0 {
		t.Errorf("%d connectors received nothing during the flood", res.Starved)
	}
	res.Outcomes, res.OutcomeErrors = out.m, out.examples
	e.finish(t, &res, tr, conns)
	return res
}

// revoke closes the leases of conns and returns the longest any of their
// sessions took to end, in milliseconds.
func (e *loadEnvironment) revoke(t *testing.T, conns []*connector) float64 {
	t.Helper()
	leases := make([]*testLease, 0, len(conns))
	sessions := make([]*reflectSession, 0, len(conns))
	e.adm.mu.Lock()
	for _, c := range conns {
		leases = append(leases, e.adm.leases[c.vpc][c.prefix])
	}
	e.adm.mu.Unlock()
	for _, c := range conns {
		sessions = append(sessions, e.rb.session(c.vpc, c.prefix))
	}
	start := time.Now()
	for _, l := range leases {
		if l != nil {
			_ = l.Close()
		}
	}
	for {
		ended := 0
		for _, s := range sessions {
			if s == nil || s.isClosed() {
				ended++
			}
		}
		took := time.Since(start)
		if ended == len(sessions) {
			return float64(took.Microseconds()) / 1000
		}
		if took > 10*loadExpiryBound {
			t.Errorf("%d of %d revoked sessions still open after %v", len(sessions)-ended, len(sessions), took)
			return float64(took.Microseconds()) / 1000
		}
		time.Sleep(time.Millisecond)
	}
}

// runSlowReader stops one client receiving while it keeps sending, beside
// res.Connectors connectors that carry traffic, and measures how long its
// session lasts.
func runSlowReader(t *testing.T, cfg loadConfig, res loadResult) loadResult {
	e := startLoad(t, nil)
	conns := e.connect(t, res.Transport, res.Connectors, nil)
	stalled := e.connect(t, res.Transport, 1, &impairment{})[0]
	stalled.idx = uint64(len(conns) + 1)
	tr := startTraffic(append(slices.Clone(conns), stalled), res.PacketBytes)
	time.Sleep(cfg.Warmup)
	w := tr.begin()
	sess := e.rb.session(stalled.vpc, stalled.prefix)
	before := make([]uint64, len(conns))
	for i, c := range conns {
		before[i] = c.recv.Load()
	}
	start := time.Now()
	switch lc := stalled.conn.(type) {
	case *h3LoadConn:
		stalled.imp.stalled.Store(true)
	case *h2LoadConn:
		lc.s.pause()
	}
	// A stalled QUIC client soon stops sending too, so the gVPC side keeps
	// offering it packets, as a workload would.
	if sess != nil {
		go func() {
			pkt := make([]byte, res.PacketBytes)
			putLoadPacket(pkt, stalled.prefix.Addr().Next(), testTarget, stalled.idx<<40, 0)
			for !sess.isClosed() {
				_ = sess.WritePacket(pkt)
				time.Sleep(200 * time.Microsecond)
			}
		}()
	}
	for sess != nil && !sess.isClosed() && time.Since(start) < 4*deliveryTimeout {
		time.Sleep(10 * time.Millisecond)
	}
	res.SlowClientEndSec = time.Since(start).Seconds()
	if limit := deliveryTimeout + checkInterval(); sess == nil || !sess.isClosed() ||
		res.SlowClientEndSec > limit.Seconds() {
		t.Errorf("stalled session lasted %.2fs, want at most %v", res.SlowClientEndSec, limit)
	}
	time.Sleep(max(cfg.Duration-time.Since(start), 0))
	w.end(&res)
	for i, c := range conns {
		if c.recv.Load() == before[i] {
			res.Starved++
		}
	}
	if res.Starved > 0 {
		t.Errorf("%d connectors received nothing while a client was stalled", res.Starved)
	}
	e.finish(t, &res, tr, append(conns, stalled))
	return res
}

// runChurn opens and closes 10 requests a second, each from a new source and
// carrying 10 packets, beside res.Connectors connectors that carry traffic.
func runChurn(t *testing.T, cfg loadConfig, res loadResult) loadResult {
	e := startLoad(t, nil)
	conns := e.connect(t, res.Transport, res.Connectors, nil)
	tr := startTraffic(conns, res.PacketBytes)
	time.Sleep(cfg.Warmup)
	w := tr.begin()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()
	var out outcomes
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			tick := time.NewTicker(400 * time.Millisecond)
			defer tick.Stop()
			pkt := make([]byte, res.PacketBytes)
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
				dctx, dcancel := context.WithTimeout(ctx, testTimeout)
				lc, prefix, err := e.dialLoad(dctx, res.Transport, loadSource().String(), tokenAlice, vpcBlue, nil)
				dcancel()
				if ctx.Err() != nil && err != nil {
					return
				}
				out.add(err)
				if err != nil {
					continue
				}
				for i := range 10 {
					putLoadPacket(pkt, prefix.Addr().Next(), testTarget, uint64(i), 0)
					_ = lc.writePacket(pkt)
				}
				lc.close()
			}
		})
	}
	wg.Wait()
	w.end(&res)
	res.Outcomes, res.OutcomeErrors = out.m, out.examples
	e.finish(t, &res, tr, conns)
	return res
}

// TestLoad runs the CONNECT-IP load harness. It is skipped unless
// CONNECTIP_LOAD is set; task test:connectip-load sets it.
func TestLoad(t *testing.T) {
	if os.Getenv(loadEnv) == "" {
		t.Skip("set " + loadEnv + "=1 to run the CONNECT-IP load harness (task test:connectip-load)")
	}
	cfg := loadConfigFromEnv(t)
	var results []loadResult
	run := func(name string, res loadResult, fn func(*testing.T, loadConfig, loadResult) loadResult) {
		t.Run(name, func(t *testing.T) { results = append(results, fn(t, cfg, res)) })
	}
	throughput := func(t *testing.T, cfg loadConfig, res loadResult) loadResult {
		return runThroughput(t, cfg, res, nil)
	}
	for _, transport := range []string{"h3", "h2"} {
		for _, n := range cfg.Connectors {
			for _, size := range []int{MinInnerMTU, minLoadPacket} {
				for r := range cfg.Runs {
					res := loadResult{Scenario: "throughput", Transport: transport, Connectors: n, PacketBytes: size,
						Run: r + 1}
					run(fmt.Sprintf("throughput/%s/%d/%dB/%d", transport, n, size, r+1), res, throughput)
				}
			}
		}
	}
	for _, transport := range []string{"h3", "h2"} {
		for r := range cfg.Runs {
			base := loadResult{Transport: transport, PacketBytes: MinInnerMTU, Run: r + 1}
			res := base
			res.Scenario, res.Connectors = "overload", 32
			run(fmt.Sprintf("overload/%s/%d", transport, r+1), res, runOverload)
			res = base
			res.Scenario, res.Connectors = "slow_reader", 8
			run(fmt.Sprintf("slow_reader/%s/%d", transport, r+1), res, runSlowReader)
			res = base
			res.Scenario, res.Connectors = "churn", 8
			run(fmt.Sprintf("churn/%s/%d", transport, r+1), res, runChurn)
		}
	}
	for r := range cfg.Runs {
		res := loadResult{Scenario: "impaired", Transport: "h3", Connectors: 8, PacketBytes: MinInnerMTU, Run: r + 1}
		run(fmt.Sprintf("impaired/h3/%d", r+1), res, func(t *testing.T, cfg loadConfig, res loadResult) loadResult {
			return runThroughput(t, cfg, res, &impairment{loss: 0.01, delay: 50 * time.Millisecond})
		})
	}

	report := loadReport(cfg, results)
	t.Log("\n" + report)
	if cfg.Report != "" {
		if err := os.WriteFile(cfg.Report, []byte(report), 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
		raw, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(strings.TrimSuffix(cfg.Report, ".md")+".json", raw, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}
}

// loadReport renders results as Markdown tables.
func loadReport(cfg loadConfig, results []loadResult) string {
	var b strings.Builder
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	fmt.Fprintf(&b, "Host: %s, %d CPUs, Linux %s, %s. Warm-up %v, measured %v, %d run(s) each.\n\n",
		cpuModel(), runtime.NumCPU(), unix.ByteSliceToString(uts.Release[:]), runtime.Version(),
		cfg.Warmup, cfg.Duration, cfg.Runs)
	b.WriteString("| Scenario | Transport | Connectors | Packet | Run | Goodput Mbit/s | Packets/s | " +
		"RTT p50 ms | RTT p99 ms | Loss % | CPU cores | RSS MiB | Heap MiB | Queue drops | Queue peak | " +
		"Recovered |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | %s | %d | %d B | %d | %.0f | %.0f | %.2f | %.2f | %.2f | %.2f | %.0f | %.0f | %d | %d | "+
			"%v |\n",
			r.Scenario, r.Transport, r.Connectors, r.PacketBytes, r.Run, r.GoodputMbps, r.PacketsPerSec,
			r.RTTp50Ms, r.RTTp99Ms, r.LossPct, r.CPUCores, r.RSSPeakMiB, r.HeapPeakMiB, r.QueueDrops,
			r.QueuePeak, r.Recovered)
	}
	b.WriteString("\n| Scenario | Transport | Run | Outcomes | Revoked session end, max ms | " +
		"Stalled session lasted s | Starved connectors |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, r := range results {
		if r.Scenario == "throughput" || r.Scenario == "impaired" {
			continue
		}
		keys := make([]string, 0, len(r.Outcomes))
		for k := range r.Outcomes {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, c string) int { return cmp.Compare(r.Outcomes[c], r.Outcomes[a]) })
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%s %d", k, r.Outcomes[k])
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %.1f | %.1f | %d |\n", r.Scenario, r.Transport, r.Run,
			strings.Join(parts, ", "), r.ExpiryMaxMs, r.SlowClientEndSec, r.Starved)
	}
	return b.String()
}

func cpuModel() string {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown CPU"
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return "unknown CPU"
}
