// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fabric-api-loadtest measures what fabric-api queries cost FRR with
// a full Internet table, the release gate for enabling AS-path, community and
// large-community searches (plan step 8).
//
// It runs, in Docker, an FRR router at the production version and a GoBGP
// feeder that injects the best paths of a RouteViews MRT RIB dump over one
// IPv4 and one IPv6 eBGP session, then runs the real fabric-api node sidecar
// beside that FRR and drives it as an operator over mTLS. It reports, per
// phase:
//
//   - baseline: the time FRR takes to (re)learn the full table with no
//     queries running, after a session reset;
//   - cheap: route lookups and summaries at the given concurrency;
//   - expensive: AS-path, community and large-community searches mixed with
//     cheap queries, with the node's own budgets;
//   - convergence under load: the same session reset while searches run.
//
// For every phase it records per-query-type latency percentiles and outcome
// codes, bgpd CPU seconds and peak RSS (from /proc), and BGP sessions dropped
// other than by the harness's own resets.
//
// Usage (from the repository root, after `go install
// github.com/osrg/gobgp/v4/cmd/gobgpd@v4.10.0 github.com/osrg/gobgp/v4/cmd/gobgp@v4.10.0`):
//
//	go run ./hack/fabric-api-loadtest --mrt rib --gobgp-bin $(go env GOPATH)/bin
//
// It needs Docker and about 4 GiB of memory, and removes its containers and
// network when it exits.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand/v2"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

const (
	network   = "fabricload"
	routerC   = "fabricload-r0"
	feederC   = "fabricload-feeder"
	routerV4  = "172.31.0.10"
	feederV4  = "172.31.0.11"
	routerV6  = "fd31::10"
	feederV6  = "fd31::11"
	routerASN = 65000
	feederASN = 64600
	cell      = "load"
	namespace = "load"

	dockerExec = "exec"
)

type options struct {
	mrt         string
	gobgpBin    string
	frrImage    string
	count       int
	duration    time.Duration
	concurrency int
	out         string
	keep        bool
	// searchSource is the sidecar's --search-source.
	searchSource string
}

func main() {
	o := options{}
	flag.StringVar(&o.mrt, "mrt", "", "Comma-separated uncompressed MRT TABLE_DUMP_V2 RIB files, e.g. RouteViews' "+
		"route-views2 (IPv4) and route-views6 (IPv6) rib.YYYYMMDD.HHMM")
	flag.StringVar(&o.gobgpBin, "gobgp-bin", "", "Directory holding static gobgpd and gobgp binaries")
	flag.StringVar(&o.frrImage, "frr-image", "quay.io/frrouting/frr:10.7.1", "FRR image")
	flag.IntVar(&o.count, "count", 0, "Inject at most this many MRT entries (0: all)")
	flag.DurationVar(&o.duration, "duration", 2*time.Minute, "Length of each workload phase")
	flag.IntVar(&o.concurrency, "concurrency", 8, "Concurrent query workers")
	flag.StringVar(&o.out, "out", "fabric-api-loadtest.json", "Where to write the JSON report")
	flag.BoolVar(&o.keep, "keep", false, "Leave the containers running")
	flag.StringVar(&o.searchSource, "search-source", "index", "The sidecar's --search-source: index or frr")
	flag.Parse()
	if o.mrt == "" || o.gobgpBin == "" {
		log.Fatal("--mrt and --gobgp-bin are required")
	}
	if err := run(o); err != nil {
		log.Fatal(err)
	}
}

// docker runs a docker command and returns its trimmed output.
func docker(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(context.Background(), "docker", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func vtysh(cmd string) (string, error) {
	return docker(dockerExec, routerC, "vtysh", "-c", cmd)
}

func cleanup() {
	_, _ = docker("rm", "-f", routerC, feederC)
	_, _ = docker("network", "rm", network)
}

func run(o options) error {
	work, err := os.MkdirTemp("", "fabric-api-loadtest")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	if !o.keep {
		defer cleanup()
	}
	cleanup()

	log.Print("building fabric-api")
	bin := filepath.Join(work, "fabric-api")
	build := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "./cmd/fabric-api")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build fabric-api: %w: %s", err, out)
	}
	if err := writeConfigs(work); err != nil {
		return err
	}

	log.Print("starting containers")
	steps := [][]string{
		{"network", "create", "--ipv6", "--subnet", "172.31.0.0/24", "--subnet", "fd31::/64", network},
		{"run", "-d", "--name", routerC, "--privileged", "--network", network, "--ip", routerV4, "--ip6", routerV6,
			"-v", filepath.Join(work, "daemons") + ":/etc/frr/daemons",
			"-v", filepath.Join(work, "frr.conf") + ":/etc/frr/frr.conf",
			o.frrImage},
		{"run", "-d", "--name", feederC, "--network", network, "--ip", feederV4, "--ip6", feederV6,
			"--entrypoint", "sleep", o.frrImage, "infinity"},
		{"cp", filepath.Join(o.gobgpBin, "gobgpd"), feederC + ":/gobgpd"},
		{"cp", filepath.Join(o.gobgpBin, "gobgp"), feederC + ":/gobgp"},
		{"cp", filepath.Join(work, "gobgpd.toml"), feederC + ":/gobgpd.toml"},
		{dockerExec, "-d", feederC, "sh", "-c", "/gobgpd -f /gobgpd.toml -p > /tmp/gobgpd.log 2>&1"},
	}
	for _, s := range steps {
		if _, err := docker(s...); err != nil {
			return err
		}
	}
	if err := waitSessions(2, 2*time.Minute); err != nil {
		return err
	}

	start := time.Now()
	for i, f := range strings.Split(o.mrt, ",") {
		log.Printf("injecting the best paths of %s", f)
		dst := fmt.Sprintf("/rib%d", i)
		if _, err := docker("cp", f, feederC+":"+dst); err != nil {
			return err
		}
		// One pass per family, each with a next hop of that family:
		// collector dumps carry next hops GoBGP refuses to originate (the
		// feeder rewrites them to its own address on export anyway).
		for _, fam := range [][]string{{"--no-ipv6", "--nexthop", feederV4}, {"--no-ipv4", "--nexthop", feederV6}} {
			inject := append([]string{dockerExec, feederC, "/gobgp", "mrt", "inject", "global", "--only-best"}, fam...)
			inject = append(inject, dst)
			if o.count > 0 {
				inject = append(inject, strconv.Itoa(o.count))
			}
			if _, err := docker(inject...); err != nil {
				return err
			}
		}
		if _, err := docker(dockerExec, feederC, "rm", "-f", dst); err != nil {
			return err
		}
	}
	log.Printf("injected in %s", time.Since(start).Round(time.Second))
	v4, v6, err := waitStable(15 * time.Minute)
	if err != nil {
		return err
	}
	log.Printf("FRR holds %d IPv4 and %d IPv6 prefixes", v4, v6)

	cpu0, _, err := bgpdStat()
	if err != nil {
		return err
	}
	syncStart := time.Now()
	if err := startSidecar(work, bin, o.searchSource); err != nil {
		return err
	}
	client, conn, err := dialSidecar(work)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	rep := report{FRRImage: o.frrImage, IPv4Prefixes: v4, IPv6Prefixes: v6, Concurrency: o.concurrency,
		PhaseDuration: o.duration.String(), SearchSource: o.searchSource}
	if o.searchSource == "index" {
		log.Print("waiting for the search index to sync over BMP")
		if err := waitSearchable(client, 15*time.Minute); err != nil {
			return err
		}
		cpu1, rss, err := bgpdStat()
		if err != nil {
			return err
		}
		rep.IndexSync = &indexSync{Duration: time.Since(syncStart).Round(time.Millisecond).String(),
			BgpdCPUSeconds: cpu1 - cpu0, BgpdRSSMiB: rss}
		log.Printf("index synced in %s", rep.IndexSync.Duration)
	}

	if o.searchSource == "index" {
		log.Print("checking the index's search results against FRR's own")
		rep.Consistency, err = checkConsistency(client)
		if err != nil {
			return err
		}
	}

	log.Print("phase baseline: convergence after a session reset, no queries")
	conv, err := measureConvergence(v4, v6)
	if err != nil {
		return err
	}
	rep.BaselineConvergence = conv.String()

	cheap := []gen{lookupGen(), summaryGen()}
	expensive := append(slices.Clone(cheap), asPathGen(), communityGen(), largeCommunityGen())
	for _, ph := range []struct {
		name  string
		gens  []gen
		reset bool
	}{
		{"cheap", cheap, false},
		{"expensive", expensive, false},
		{"expensive+reset", expensive, true},
	} {
		log.Printf("phase %s", ph.name)
		pr, err := runPhase(client, ph.gens, o, ph.reset, v4, v6)
		if err != nil {
			return err
		}
		pr.Name = ph.name
		rep.Phases = append(rep.Phases, pr)
	}

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.out, b, 0o600); err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func writeConfigs(dir string) error {
	files := map[string]string{
		"daemons": "zebra=yes\nbgpd=yes\nvtysh_enable=yes\nzebra_options=\"  -A 127.0.0.1 -s 90000000\"\n" +
			"bgpd_options=\"   -A 127.0.0.1 -M bmp\"\n",
		"frr.conf": fmt.Sprintf(`frr defaults traditional
hostname r0
log stdout informational
router bgp %d
 bgp router-id %s
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 neighbor %s remote-as %d
 neighbor %s remote-as %d
 address-family ipv4 unicast
  neighbor %s activate
 exit-address-family
 address-family ipv6 unicast
  neighbor %s activate
 exit-address-family
 bmp targets fabric-api
  bmp connect 127.0.0.1 port 9348 min-retry 1000 max-retry 5000
  bmp monitor ipv4 unicast loc-rib
  bmp monitor ipv6 unicast loc-rib
 exit
`, routerASN, routerV4, feederV4, feederASN, feederV6, feederASN, feederV4, feederV6),
		"gobgpd.toml": fmt.Sprintf(`[global.config]
  as = %d
  router-id = "%s"
[[neighbors]]
  [neighbors.config]
    neighbor-address = "%s"
    peer-as = %d
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
[[neighbors]]
  [neighbors.config]
    neighbor-address = "%s"
    peer-as = %d
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-unicast"
`, feederASN, feederV4, routerV4, routerASN, routerV6, routerASN),
	}
	for name, content := range files {
		// FRR reads these inside its container, as another user.
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil { //nolint:gosec // see above
			return err
		}
	}
	return nil
}

// summary returns prefixes received and connections dropped across both
// families' sessions.
func summary() (v4, v6, drops int, established int, err error) {
	for _, fam := range []string{"ipv4", "ipv6"} {
		out, err := vtysh("show bgp " + fam + " unicast summary json")
		if err != nil {
			return 0, 0, 0, 0, err
		}
		var s struct {
			Peers map[string]struct {
				State              string `json:"state"`
				PfxRcd             int    `json:"pfxRcd"`
				ConnectionsDropped int    `json:"connectionsDropped"`
			} `json:"peers"`
		}
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			return 0, 0, 0, 0, err
		}
		for _, p := range s.Peers {
			if p.State == "Established" {
				established++
			}
			drops += p.ConnectionsDropped
			if fam == "ipv4" {
				v4 += p.PfxRcd
			} else {
				v6 += p.PfxRcd
			}
		}
	}
	return v4, v6, drops, established, nil
}

func waitSessions(n int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, _, _, est, err := summary(); err == nil && est >= n {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("BGP sessions did not come up")
}

// waitStable waits until both families' prefix counts stop changing for 20s.
func waitStable(timeout time.Duration) (int, int, error) {
	deadline := time.Now().Add(timeout)
	last4, last6, since := -1, -1, time.Now()
	for time.Now().Before(deadline) {
		v4, v6, _, _, err := summary()
		if err == nil {
			if v4 != last4 || v6 != last6 {
				last4, last6, since = v4, v6, time.Now()
			} else if v4 > 0 && time.Since(since) > 20*time.Second {
				return v4, v6, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return 0, 0, errors.New("the table did not settle")
}

// measureConvergence resets both sessions and times how long FRR takes to
// hold the full table again.
func measureConvergence(v4, v6 int) (time.Duration, error) {
	start := time.Now()
	if _, err := vtysh("clear bgp *"); err != nil {
		return 0, err
	}
	time.Sleep(time.Second)
	for time.Since(start) < 15*time.Minute {
		g4, g6, _, est, err := summary()
		if err == nil && est == 2 && g4 >= v4*99/100 && g6 >= v6*99/100 {
			return time.Since(start), nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0, errors.New("did not reconverge")
}

// certs writes a CA, the sidecar's certificate and an operator certificate.
func certs(dir string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fabric-api load"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	for name, id := range map[string]identity.ID{
		"node":     identity.Node(cell, namespace, "r0-certs"),
		"operator": identity.Operator(cell, "loadtest"),
	} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		u, _ := url.Parse(id.URI())
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // copied into a container
			return err
		}
		for f, b := range map[string][]byte{
			"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
			"ca.crt":  caPEM,
		} {
			if err := os.WriteFile(filepath.Join(d, f), b, 0o644); err != nil { //nolint:gosec // test credentials
				return err
			}
		}
	}
	return nil
}

func startSidecar(work, bin, searchSource string) error {
	if err := certs(work); err != nil {
		return err
	}
	for _, s := range [][]string{
		{"cp", bin, routerC + ":/fabric-api"},
		{"cp", filepath.Join(work, "node"), routerC + ":/tls"},
		{dockerExec, "-d", routerC, "sh", "-c", "/fabric-api --log-format text node --node-name r0 --namespace " + namespace +
			" --pod-name r0 --cell " + cell + " --host-ip " + routerV4 + " --frr-socket-dir /var/run/frr" +
			" --tls-cert /tls/tls.crt --tls-key /tls/tls.key --tls-ca /tls/ca.crt --probe-source-interface ''" +
			" --enable-expensive-queries --expensive-breaker-cooldown 5s --search-source " + searchSource +
			" > /tmp/fabric-api.log 2>&1"},
	} {
		if _, err := docker(s...); err != nil {
			return err
		}
	}
	return nil
}

func dialSidecar(work string) (fabricv1.FabricServiceClient, *grpc.ClientConn, error) {
	d := filepath.Join(work, "operator")
	creds := &identity.Credentials{CertFile: filepath.Join(d, "tls.crt"), KeyFile: filepath.Join(d, "tls.key"),
		CAFile: filepath.Join(d, "ca.crt"), Self: identity.Operator(cell, "loadtest")}
	if err := creds.Reload(); err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient(routerV4+":9344", grpc.WithTransportCredentials(credentials.NewTLS(
		creds.ClientConfig(identity.Node(cell, namespace, "r0-certs")))))
	if err != nil {
		return nil, nil, err
	}
	c := fabricv1.NewFabricServiceClient(conn)
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		info, err := c.Info(ctx, &fabricv1.InfoRequest{})
		cancel()
		if err == nil && info.GetDiagnosticsAvailable() {
			return c, conn, nil
		}
		time.Sleep(time.Second)
	}
	return nil, nil, errors.New("sidecar did not become available")
}

// waitSearchable waits until the sidecar lists AS-path searches as enabled,
// which with the index means it holds bgpd's full table.
func waitSearchable(c fabricv1.FabricServiceClient, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		info, err := c.Info(ctx, &fabricv1.InfoRequest{})
		cancel()
		if err == nil && slices.Contains(info.GetEnabledQueryTypes(), fabricv1.QueryType_QUERY_TYPE_AS_PATH) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("the search index did not sync")
}

// gen produces queries of one type.
type gen struct {
	name    string
	next    func(r *mrand.Rand) query.Query
	targets []string
}

func lookupGen() gen {
	return gen{"RouteLookup", func(r *mrand.Rand) query.Query {
		if r.IntN(4) == 0 {
			var b [16]byte
			b[0], b[1] = 0x20, byte(r.IntN(256))
			for i := 2; i < 6; i++ {
				b[i] = byte(r.IntN(256))
			}
			return query.Query{Type: query.TypeRouteLookup, Target: netip.AddrFrom16(b).String()}
		}
		a := netip.AddrFrom4([4]byte{byte(1 + r.IntN(222)), byte(r.IntN(256)), byte(r.IntN(256)), 1})
		return query.Query{Type: query.TypeRouteLookup, Target: a.String()}
	}, nil}
}

func summaryGen() gen {
	return gen{"BGPSummary", func(*mrand.Rand) query.Query { return query.Query{Type: query.TypeBGPSummary} }, nil}
}

func pick[T any](r *mrand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func asPathGen() gen {
	exprs := []string{"_13335$", "_15169$", "^174_", "_3356_", "_6939_", "_2914$", "^$", "_64512$", "_7018_701_"}
	return gen{"ASPath", func(r *mrand.Rand) query.Query {
		return query.Query{Type: query.TypeASPath, Target: pick(r, exprs)}
	}, exprs}
}

func communityGen() gen {
	cs := []string{"3356:3", "174:21000", "6939:7000", "2914:410", "no-export", "65535:666", "64512:1"}
	return gen{"Community", func(r *mrand.Rand) query.Query {
		return query.Query{Type: query.TypeCommunity, Target: pick(r, cs)}
	}, cs}
}

func largeCommunityGen() gen {
	cs := []string{"6695:1000:1", "8283:1:31", "50629:203:1", "64512:1:1"}
	return gen{"LargeCommunity", func(r *mrand.Rand) query.Query {
		return query.Query{Type: query.TypeLargeCommunity, Target: pick(r, cs)}
	}, cs}
}

type typeStats struct {
	Count     int            `json:"count"`
	Outcomes  map[string]int `json:"outcomes"`
	P50       string         `json:"p50"`
	P95       string         `json:"p95"`
	P99       string         `json:"p99"`
	Max       string         `json:"max"`
	MaxBytes  int            `json:"maxResponseBytes"`
	latencies []time.Duration
}

type phaseReport struct {
	Name               string                `json:"name"`
	Queries            map[string]*typeStats `json:"queries"`
	BgpdCPUSeconds     float64               `json:"bgpdCPUSeconds"`
	BgpdCPUPercent     float64               `json:"bgpdCPUPercentOfOneCore"`
	BgpdRSSStartMiB    int                   `json:"bgpdRSSStartMiB"`
	BgpdRSSPeakMiB     int                   `json:"bgpdRSSPeakMiB"`
	SessionsDropped    int                   `json:"sessionsDroppedUnplanned"`
	ConvergenceUnderIt string                `json:"convergenceUnderLoad,omitempty"`
}

type indexSync struct {
	Duration       string  `json:"duration"`
	BgpdCPUSeconds float64 `json:"bgpdCPUSeconds"`
	BgpdRSSMiB     int     `json:"bgpdRSSMiB"`
}

type report struct {
	FRRImage            string         `json:"frrImage"`
	SearchSource        string         `json:"searchSource"`
	IndexSync           *indexSync     `json:"indexSync,omitempty"`
	IPv4Prefixes        int            `json:"ipv4Prefixes"`
	IPv6Prefixes        int            `json:"ipv6Prefixes"`
	Concurrency         int            `json:"concurrency"`
	PhaseDuration       string         `json:"phaseDuration"`
	BaselineConvergence string         `json:"baselineConvergence"`
	Phases              []*phaseReport `json:"phases"`
	Consistency         []consistency  `json:"consistency,omitempty"`
}

// consistency compares one search's matched count from the sidecar's index
// with FRR's own answer.
type consistency struct {
	Query string `json:"query"`
	Index int    `json:"index"`
	FRR   int    `json:"frr"`
	Match bool   `json:"match"`
}

// checkConsistency runs every search target through the sidecar and through
// FRR directly, while no workload runs.
func checkConsistency(c fabricv1.FabricServiceClient) ([]consistency, error) {
	var out []consistency
	for _, g := range []gen{asPathGen(), communityGen(), largeCommunityGen()} {
		for _, fam := range []query.AddressFamily{query.IPv4, query.IPv6} {
			for _, target := range g.targets {
				q, err := query.Canonicalize(query.Query{Type: query.Type(g.name), Target: target, AddressFamily: fam})
				if err != nil {
					return nil, err
				}
				ctx, cancel := context.WithTimeout(context.Background(), query.MaxNodeExecution)
				resp, err := c.Execute(ctx, &fabricv1.ExecuteRequest{
					RequestId: fmt.Sprintf("consistency-%d", time.Now().UnixNano()), Node: "r0",
					Query: node.QueryToProto(q), ExpiresAt: timestamppb.New(time.Now().Add(query.MaxNodeExecution)),
				})
				cancel()
				if err != nil {
					return nil, fmt.Errorf("index %s %s: %w", g.name, target, err)
				}
				cmd, err := frr.SearchCommand(q)
				if err != nil {
					return nil, err
				}
				raw, err := vtysh(cmd.String())
				if err != nil {
					return nil, err
				}
				res, err := frr.ParseSearch(frr.Response{Output: []byte(raw)})
				if err != nil {
					return nil, fmt.Errorf("parse FRR %s: %w", cmd, err)
				}
				// The index holds each prefix's selected path: count the
				// prefixes whose matching paths, as FRR lists them, include
				// the best one.
				best := 0
				for _, r := range res.Routes {
					if slices.ContainsFunc(r.Paths, func(p frr.Path) bool { return p.Best }) {
						best++
					}
				}
				n := int(resp.GetObservation().GetMatched())
				out = append(out, consistency{Query: fmt.Sprintf("%s %s %s", fam, g.name, target), Index: n,
					FRR: best, Match: n == best})
			}
		}
	}
	return out, nil
}

// bgpdStat returns bgpd's CPU seconds and RSS in MiB.
func bgpdStat() (float64, int, error) {
	out, err := docker(dockerExec, routerC, "sh", "-c",
		"p=$(cat /var/run/frr/bgpd.pid); cut -d' ' -f14,15 /proc/$p/stat; grep VmRSS /proc/$p/status")
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return 0, 0, fmt.Errorf("unexpected stat output %q", out)
	}
	ticks := strings.Fields(lines[0])
	u, _ := strconv.ParseFloat(ticks[0], 64)
	s, _ := strconv.ParseFloat(ticks[1], 64)
	rss, _ := strconv.Atoi(strings.Fields(lines[1])[1])
	return (u + s) / 100, rss / 1024, nil
}

func runPhase(c fabricv1.FabricServiceClient, gens []gen, o options, reset bool, v4, v6 int) (*phaseReport, error) {
	pr := &phaseReport{Queries: map[string]*typeStats{}}
	for _, g := range gens {
		pr.Queries[g.name] = &typeStats{Outcomes: map[string]int{}}
	}
	cpu0, rss0, err := bgpdStat()
	if err != nil {
		return nil, err
	}
	_, _, drops0, _, err := summary()
	if err != nil {
		return nil, err
	}
	pr.BgpdRSSStartMiB, pr.BgpdRSSPeakMiB = rss0, rss0

	ctx, cancel := context.WithTimeout(context.Background(), o.duration)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var seq int64
	for w := range o.concurrency {
		wg.Go(func() {
			r := mrand.New(mrand.NewPCG(uint64(w), uint64(time.Now().UnixNano()))) //nolint:gosec // workload choice only
			for ctx.Err() == nil {
				g := gens[r.IntN(len(gens))]
				q, err := query.Canonicalize(g.next(r))
				if err != nil {
					continue
				}
				mu.Lock()
				seq++
				id := fmt.Sprintf("load-%d", seq)
				mu.Unlock()
				qctx, qcancel := context.WithTimeout(context.Background(), query.MaxNodeExecution)
				start := time.Now()
				resp, err := c.Execute(qctx, &fabricv1.ExecuteRequest{RequestId: id, Node: "r0", Query: node.QueryToProto(q),
					ExpiresAt: timestamppb.New(time.Now().Add(query.MaxNodeExecution))})
				qcancel()
				lat := time.Since(start)
				outcome := "OK"
				if err != nil {
					outcome = string(errcode.Of(err))
				}
				mu.Lock()
				st := pr.Queries[g.name]
				st.Count++
				st.Outcomes[outcome]++
				st.latencies = append(st.latencies, lat)
				if resp != nil {
					st.MaxBytes = max(st.MaxBytes, proto.Size(resp))
				}
				mu.Unlock()
				if outcome == string(errcode.NodeBusy) {
					time.Sleep(50 * time.Millisecond)
				}
			}
		})
	}

	// Sample bgpd while the workload runs; optionally reset the sessions
	// halfway and time reconvergence under the load.
	var resetErr error
	convDone := make(chan time.Duration, 1)
	if reset {
		go func() {
			time.Sleep(o.duration / 4)
			d, err := measureConvergence(v4, v6)
			resetErr = err
			convDone <- d
		}()
	}
	t := time.NewTicker(time.Second)
	for ctx.Err() == nil {
		<-t.C
		if _, rss, err := bgpdStat(); err == nil {
			pr.BgpdRSSPeakMiB = max(pr.BgpdRSSPeakMiB, rss)
		}
	}
	t.Stop()
	wg.Wait()
	if reset {
		d := <-convDone
		if resetErr != nil {
			return nil, resetErr
		}
		pr.ConvergenceUnderIt = d.String()
	}
	cpu1, _, err := bgpdStat()
	if err != nil {
		return nil, err
	}
	pr.BgpdCPUSeconds = cpu1 - cpu0
	pr.BgpdCPUPercent = 100 * pr.BgpdCPUSeconds / o.duration.Seconds()
	_, _, drops1, _, err := summary()
	if err != nil {
		return nil, err
	}
	pr.SessionsDropped = drops1 - drops0
	if reset {
		// The deliberate reset drops each of the two sessions once.
		pr.SessionsDropped -= 2
	}
	for _, st := range pr.Queries {
		slices.Sort(st.latencies)
		if n := len(st.latencies); n > 0 {
			q := func(p float64) string {
				return st.latencies[min(n-1, int(p*float64(n)))].Round(time.Millisecond).String()
			}
			st.P50, st.P95, st.P99, st.Max = q(0.50), q(0.95), q(0.99), st.latencies[n-1].Round(time.Millisecond).String()
		}
	}
	return pr, nil
}
