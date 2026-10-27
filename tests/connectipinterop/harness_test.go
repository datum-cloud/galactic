// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package connectipinterop proves CONNECT-IP interoperability over HTTP/3 and
// HTTP/2 between Galactic's servers and an independent client, Xray-core's
// MASQUE outbound. connectip.Server serves HTTP/3; h2Server, a prototype on
// net/http's Extended CONNECT, serves HTTP/2. Both use the same test admission
// and a connectip.TUNBackend whose device sits in a VPC network namespace with
// UDP and TCP echo servers.
//
// The fixture needs root, nftables and the pinned Xray binary named by
// CONNECTIP_INTEROP_XRAY; without them every test skips. task
// test:connectip-interop downloads the binary and runs the suite.
// CONNECTIP_INTEROP_ARTIFACTS, when set, receives results.json and each
// client's log. See docs/edge/connectip-interop.md.
package connectipinterop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/edge/connectip"
)

const (
	envXray      = "CONNECTIP_INTEROP_XRAY"
	envArtifacts = "CONNECTIP_INTEROP_ARTIFACTS"

	serverName = "connectip.test"
	vpcName    = "blue"
	echoPort   = 7
	tunName    = "cip0"

	// innerPacketSize is the inner IPv6 packet every round trip carries:
	// the 40-byte IPv6 and 8-byte UDP headers plus echoPayload bytes.
	innerPacketSize = 1280
	echoPayload     = innerPacketSize - 40 - 8
)

var (
	serverAddr = netip.MustParseAddr("fd00:973:1::1")
	clientAddr = netip.MustParseAddr("fd00:973:1::2")
	// vpcRoute is the one route advertised to every connector; echoAddr
	// lives in it. Connector prefixes come from connectorRange, which the
	// VPC namespace routes into the TUN device.
	vpcRoute       = netip.MustParsePrefix("fd00:973:a::/64")
	echoAddr       = netip.MustParseAddr("fd00:973:a::1")
	connectorRange = netip.MustParsePrefix("fd00:973:b::/64")
)

// connector is one credential the test admission accepts.
type connector struct {
	token  string
	prefix netip.Prefix
}

// Each test uses its own connectors, so a session that outlives its test
// cannot collide with the next one's prefix.
var (
	connectorsMu sync.Mutex
	connectors   = map[string]connector{}
)

func newConnector(name string) connector {
	connectorsMu.Lock()
	defer connectorsMu.Unlock()
	n := len(connectors) + 1
	token := "token-" + strings.ReplaceAll(name, " ", "-")
	if _, dup := connectors[token]; dup {
		panic("connector " + name + " already exists")
	}
	c := connector{
		token:  token,
		prefix: netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, 0x09, 0x73, 0, 0x0b, 0, 0, 0, byte(n)}), 96),
	}
	connectors[c.token] = c
	return c
}

func connectorByToken(token string) (connector, bool) {
	connectorsMu.Lock()
	defer connectorsMu.Unlock()
	c, ok := connectors[token]
	return c, ok
}

var (
	fixture    *harness
	skipReason string
	errSetup   error
)

// TestMain re-runs the test binary with GODEBUG=http2xconnect=1 when it is
// missing: net/http reads it once at init, and without it the HTTP/2 server
// does not offer Extended CONNECT.
func TestMain(m *testing.M) {
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		cmd := exec.CommandContext(context.Background(), os.Args[0], os.Args[1:]...)
		cmd.Env = append(os.Environ(), "GODEBUG="+strings.TrimPrefix(os.Getenv("GODEBUG")+",http2xconnect=1", ","))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			if exit, ok := errors.AsType[*exec.ExitError](err); ok {
				os.Exit(exit.ExitCode())
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	switch {
	case os.Getenv(envXray) == "":
		skipReason = envXray + " is not set; run task test:connectip-interop"
	case os.Geteuid() != 0:
		skipReason = "the fixture needs root"
	default:
		// An interrupted run still removes its namespaces and clients; a
		// run killed by a test timeout leaves them for the next run's sweep.
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		var ready atomic.Pointer[harness]
		go func() {
			<-signals
			if h := ready.Load(); h != nil {
				h.close()
			} else {
				removeNamespaces(os.Getpid())
			}
			os.Exit(1)
		}()
		fixture, errSetup = newHarness()
		ready.Store(fixture)
	}
	code := m.Run()
	if fixture != nil {
		if err := fixture.writeResults(); err != nil {
			fmt.Fprintln(os.Stderr, "could not write results:", err)
			code = 1
		}
		fixture.close()
		if err := fixture.returnArtifacts(); err != nil {
			fmt.Fprintln(os.Stderr, "could not hand artifacts back to the sudo user:", err)
			code = 1
		}
	}
	os.Exit(code)
}

func requireFixture(t *testing.T) *harness {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
	if errSetup != nil {
		t.Fatalf("fixture setup: %v", errSetup)
	}
	return fixture
}

// harness is the shared fixture: three network namespaces, both servers and
// the VPC's echo servers.
//
//	client netns ── veth ── server netns   (HTTP/3 on UDP/443, HTTP/2 on TCP/443)
//	                         │ TUNBackend
//	                         └─ TUN device in the VPC netns (echo on echoAddr)
type harness struct {
	prefix               string
	client, server, vpc  ns.NetNS
	dir, artifacts, xray string
	caFile, otherCAFile  string
	admission            *admission
	backend              *recordingBackend
	h3                   *connectip.Server
	h2                   *http.Server
	closers              []func()
	closeOnce            sync.Once
	clients              sync.Map // *xrayClient still running
	alpn                 sync.Map // negotiated ALPN protocol -> count
	h2Protos             sync.Map // HTTP/2 request proto -> count
	results              resultLog
	nextPort             atomic.Int32
}

func newHarness() (h *harness, err error) {
	h = &harness{
		prefix:    fmt.Sprintf("cip%d", os.Getpid()),
		xray:      os.Getenv(envXray),
		artifacts: os.Getenv(envArtifacts),
	}
	h.nextPort.Store(20000)
	sweepStaleNamespaces()
	defer func() {
		if err != nil {
			h.close()
			h = nil
		}
	}()
	if h.dir, err = os.MkdirTemp("", "connectip-interop-"); err != nil {
		return h, err
	}
	h.closers = append(h.closers, func() { _ = os.RemoveAll(h.dir) })
	if h.artifacts == "" {
		h.artifacts = h.dir
	} else if err := os.MkdirAll(h.artifacts, 0o755); err != nil {
		return h, err
	}
	if err := h.network(); err != nil {
		return h, fmt.Errorf("network: %w", err)
	}
	serverCert, err := h.certificates()
	if err != nil {
		return h, fmt.Errorf("certificates: %w", err)
	}
	if err := h.vpcSide(); err != nil {
		return h, fmt.Errorf("VPC namespace: %w", err)
	}
	if err := h.servers(serverCert); err != nil {
		return h, fmt.Errorf("servers: %w", err)
	}
	return h, nil
}

func (h *harness) close() {
	h.closeOnce.Do(func() {
		h.clients.Range(func(k, _ any) bool {
			k.(*xrayClient).stop()
			return true
		})
		for i := len(h.closers) - 1; i >= 0; i-- {
			h.closers[i]()
		}
	})
}

// sweepStaleNamespaces removes the namespaces of earlier runs whose process
// no longer exists.
func sweepStaleNamespaces() {
	for pid := range fixtureNamespaces() {
		if pid != os.Getpid() && errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			removeNamespaces(pid)
		}
	}
}

// fixtureNamespaces maps each test process ID to its fixture namespaces.
func fixtureNamespaces() map[int][]string {
	out := map[int][]string{}
	entries, err := os.ReadDir("/run/netns")
	if err != nil {
		return out
	}
	for _, e := range entries {
		m := staleNamespace.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		if pid, err := strconv.Atoi(m[1]); err == nil {
			out[pid] = append(out[pid], e.Name())
		}
	}
	return out
}

// removeNamespaces kills any process left in pid's fixture namespaces, such
// as an Xray client, and deletes the namespaces.
func removeNamespaces(pid int) {
	for _, name := range fixtureNamespaces()[pid] {
		out, _ := exec.CommandContext(context.Background(), "ip", "netns", "pids", name).Output()
		for _, f := range strings.Fields(string(out)) {
			if p, err := strconv.Atoi(f); err == nil {
				_ = syscall.Kill(p, syscall.SIGKILL)
			}
		}
		_ = run("", "ip", "netns", "del", name)
	}
}

var staleNamespace = regexp.MustCompile(`^cip([0-9]+)-(client|server|vpc)$`)

// run runs a command, feeding it stdin when it is not empty.
func run(stdin string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), args[0], args[1:]...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ipBatch runs ip commands, one per line, in the role's namespace.
func (h *harness) ipBatch(role, script string) error {
	return run(script, "ip", "-n", h.nsName(role), "-batch", "-")
}

// nft applies an nftables script in the server namespace.
func (h *harness) nft(script string) error {
	return run(script, "ip", "netns", "exec", h.nsName(roleServer), "nft", "-f", "-")
}

func (h *harness) nsName(role string) string { return h.prefix + "-" + role }

// network creates the namespaces, the client-server veth and the nftables
// table that counts and, on demand, drops UDP/443 in the server namespace.
func (h *harness) network() error {
	for _, role := range []string{roleClient, roleServer, roleVPC} {
		name := h.nsName(role)
		if err := run("", "ip", "netns", "add", name); err != nil {
			return err
		}
		h.closers = append(h.closers, func() { _ = run("", "ip", "netns", "del", name) })
	}
	if err := run("", "ip", "link", "add", "c0", "netns", h.nsName(roleClient),
		"type", "veth", "peer", "s0", "netns", h.nsName(roleServer)); err != nil {
		return err
	}
	for role, script := range map[string]string{
		roleClient: "link set lo up\naddr add " + clientAddr.String() + "/64 dev c0 nodad\nlink set c0 up\n",
		roleServer: "link set lo up\naddr add " + serverAddr.String() + "/64 dev s0 nodad\nlink set s0 up\n",
		roleVPC:    "link set lo up\n",
	} {
		if err := h.ipBatch(role, script); err != nil {
			return err
		}
	}
	if err := h.nft(nftRules); err != nil {
		return err
	}
	var err error
	for role, dst := range map[string]*ns.NetNS{roleClient: &h.client, roleServer: &h.server, roleVPC: &h.vpc} {
		if *dst, err = ns.GetNS("/run/netns/" + h.nsName(role)); err != nil {
			return err
		}
		netns := *dst
		h.closers = append(h.closers, func() { _ = netns.Close() })
	}
	return nil
}

// Named nftables counters of outer packets in the server namespace.
// Namespace roles.
const (
	roleClient = "client"
	roleServer = "server"
	roleVPC    = "vpc"
)

const (
	counterUDP443        = "udp443"
	counterTCP443        = "tcp443"
	counterUDP443Dropped = "udp443_dropped"
)

// nftRules count the outer traffic of each transport. blockUDP443 inserts a
// drop rule ahead of them.
const nftRules = `
table inet connectip {
	counter udp443 {}
	counter tcp443 {}
	counter udp443_dropped {}
	chain input {
		type filter hook input priority 0; policy accept;
		udp dport 443 counter name udp443
		tcp dport 443 counter name tcp443
	}
}
`

func (h *harness) blockUDP443(t *testing.T) {
	t.Helper()
	if err := h.nft("insert rule inet connectip input udp dport 443 counter name udp443_dropped drop\n"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.nft("delete table inet connectip\n" + nftRules); err != nil {
			t.Error(err)
		}
	})
}

// counters returns the packet count of every named nftables counter.
func (h *harness) counters(t *testing.T) map[string]int64 {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "ip", "netns", "exec", h.nsName(roleServer),
		"nft", "-j", "list", "counters").Output()
	if err != nil {
		t.Fatalf("nft list counters: %v", err)
	}
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets int64  `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("parse nft counters: %v", err)
	}
	m := map[string]int64{}
	for _, e := range doc.Nftables {
		if e.Counter != nil {
			m[e.Counter.Name] = e.Counter.Packets
		}
	}
	return m
}

// certificates writes the CA Xray trusts, an unrelated CA for the negative
// check, and returns the server certificate signed by the first.
func (h *harness) certificates() (tls.Certificate, error) {
	caCert, caKey, caPEM, err := newCA("connectip interop CA")
	if err != nil {
		return tls.Certificate{}, err
	}
	_, _, otherPEM, err := newCA("unrelated CA")
	if err != nil {
		return tls.Certificate{}, err
	}
	h.caFile = filepath.Join(h.dir, "ca.pem")
	h.otherCAFile = filepath.Join(h.dir, "other-ca.pem")
	if err := os.WriteFile(h.caFile, caPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(h.otherCAFile, otherPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func newCA(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// vpcSide creates the TUN device and echo servers in the VPC namespace and the
// TUNBackend that reads and writes it.
func (h *harness) vpcSide() error {
	var dev *os.File
	err := h.vpc.Do(func(ns.NetNS) error {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		ifr, err := unix.NewIfreq(tunName)
		if err != nil {
			_ = unix.Close(fd)
			return err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			_ = unix.Close(fd)
			return err
		}
		dev = os.NewFile(uintptr(fd), tunName)
		return nil
	})
	if err != nil {
		return err
	}
	script := "link set " + tunName + " mtu 1500 up\n" +
		"route add " + connectorRange.String() + " dev " + tunName + "\n" +
		"link add dum0 type dummy\n" +
		"addr add " + echoAddr.String() + "/128 dev dum0 nodad\n" +
		"link set dum0 up\n"
	if err := h.ipBatch(roleVPC, script); err != nil {
		_ = dev.Close()
		return err
	}
	tun, err := connectip.NewTUNBackend(dev, vpcName)
	if err != nil {
		_ = dev.Close()
		return err
	}
	h.closers = append(h.closers, func() { _ = tun.Close() })
	h.backend = &recordingBackend{next: tun}
	return h.echoServers()
}

// echoServers answer UDP datagrams and TCP streams on echoAddr:echoPort with
// the same bytes.
func (h *harness) echoServers() error {
	addr := net.JoinHostPort(echoAddr.String(), strconv.Itoa(echoPort))
	var pc net.PacketConn
	var ln net.Listener
	err := h.vpc.Do(func(ns.NetNS) error {
		var err error
		var lc net.ListenConfig
		if pc, err = lc.ListenPacket(context.Background(), "udp6", addr); err != nil {
			return err
		}
		ln, err = lc.Listen(context.Background(), "tcp6", addr)
		return err
	})
	if err != nil {
		return err
	}
	h.closers = append(h.closers, func() { _ = pc.Close(); _ = ln.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return nil
}

// servers starts connectip.Server on UDP/443 and h2Server on TCP/443 in the
// server namespace. The TLS configuration records each handshake's ALPN.
func (h *harness) servers(cert tls.Certificate) error {
	h.admission = &admission{active: map[netip.Prefix]bool{}}
	log := slog.New(slog.NewTextHandler(h.logFile("servers.log"), &slog.HandlerOptions{Level: slog.LevelDebug}))
	tlsConf := func(protos ...string) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   protos,
			VerifyConnection: func(cs tls.ConnectionState) error {
				n, _ := h.alpn.LoadOrStore(cs.NegotiatedProtocol, new(atomic.Int64))
				n.(*atomic.Int64).Add(1)
				return nil
			},
		}
	}
	authority := serverName
	var err error
	h.h3, err = connectip.NewServer(connectip.Config{
		Authority: authority,
		TLSConfig: tlsConf(),
		Admission: h.admission,
		Backend:   h.backend,
		Logger:    log,
	})
	if err != nil {
		return err
	}
	h.h2 = &http.Server{
		Handler: &h2Server{
			authority: authority,
			admission: h.admission,
			backend:   h.backend,
			log:       log,
			observe: func(proto string) {
				n, _ := h.h2Protos.LoadOrStore(proto, new(atomic.Int64))
				n.(*atomic.Int64).Add(1)
			},
		},
		TLSConfig: tlsConf("h2"),
		ErrorLog:  slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	addr := net.JoinHostPort(serverAddr.String(), "443")
	var udp net.PacketConn
	var tcp net.Listener
	err = h.server.Do(func(ns.NetNS) error {
		var lc net.ListenConfig
		if udp, err = lc.ListenPacket(context.Background(), "udp6", addr); err != nil {
			return err
		}
		tcp, err = lc.Listen(context.Background(), "tcp6", addr)
		return err
	})
	if err != nil {
		return err
	}
	go func() { _ = h.h3.Serve(udp) }()
	go func() { _ = h.h2.ServeTLS(tcp, "", "") }()
	h.closers = append(h.closers, func() {
		_ = h.h2.Close()
		_ = h.h3.Close()
		_ = udp.Close()
	})
	return nil
}

func (h *harness) logFile(name string) io.Writer {
	f, err := os.Create(filepath.Join(h.artifacts, name))
	if err != nil {
		return io.Discard
	}
	h.closers = append(h.closers, func() { _ = f.Close() })
	return f
}

func (h *harness) alpnCount(proto string) int64 {
	if n, ok := h.alpn.Load(proto); ok {
		return n.(*atomic.Int64).Load()
	}
	return 0
}

func (h *harness) h2ProtoCount(proto string) int64 {
	if n, ok := h.h2Protos.Load(proto); ok {
		return n.(*atomic.Int64).Load()
	}
	return 0
}

// admission is the test authority: each connector's token admits it to
// vpcName with its own /96, one session at a time.
type admission struct {
	mu     sync.Mutex
	active map[netip.Prefix]bool
	nextID uint64
}

func (a *admission) Admit(_ context.Context, credential, vpc string) (connectip.Lease, error) {
	c, ok := connectorByToken(credential)
	if !ok {
		return nil, connectip.ErrUnauthenticated
	}
	if vpc != vpcName {
		return nil, connectip.ErrForbidden
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active[c.prefix] {
		return nil, errors.New("connector already has a session")
	}
	a.active[c.prefix] = true
	a.nextID++
	return &lease{
		a:    a,
		done: make(chan struct{}),
		info: connectip.SessionInfo{
			ID: a.nextID, Principal: c.token, VPC: vpc, Prefix: c.prefix,
			Connector: c.token, Attachment: "interop", Claim: c.prefix.String(), Epoch: 1,
		},
	}, nil
}

type lease struct {
	a    *admission
	info connectip.SessionInfo
	done chan struct{}
	once sync.Once
}

func (l *lease) Info() connectip.SessionInfo { return l.info }
func (l *lease) Routes() []netip.Prefix      { return []netip.Prefix{vpcRoute} }
func (l *lease) Done() <-chan struct{}       { return l.done }

func (l *lease) Close() error {
	l.once.Do(func() {
		l.a.mu.Lock()
		delete(l.a.active, l.info.Prefix)
		l.a.mu.Unlock()
	})
	return nil
}

// recordingBackend is the controlled packet backend: it forwards to the TUN
// backend and records the size of every packet per connector prefix.
type recordingBackend struct {
	next connectip.PacketBackend
	mu   sync.Mutex
	seen map[netip.Prefix]*packetSizes
}

// packetSizes counts packets by size in each direction.
type packetSizes struct {
	mu       sync.Mutex
	toVPC    map[int]int
	toClient map[int]int
	opened   int
	closed   int
}

func (b *recordingBackend) sizes(p netip.Prefix) *packetSizes {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil {
		b.seen = map[netip.Prefix]*packetSizes{}
	}
	s := b.seen[p]
	if s == nil {
		s = &packetSizes{toVPC: map[int]int{}, toClient: map[int]int{}}
		b.seen[p] = s
	}
	return s
}

func (b *recordingBackend) Open(ctx context.Context, info connectip.SessionInfo) (connectip.BackendSession, error) {
	sess, err := b.next.Open(ctx, info)
	if err != nil {
		return nil, err
	}
	s := b.sizes(info.Prefix)
	s.mu.Lock()
	s.opened++
	s.mu.Unlock()
	return &recordingSession{BackendSession: sess, sizes: s}, nil
}

type recordingSession struct {
	connectip.BackendSession
	sizes *packetSizes
	once  sync.Once
}

func (s *recordingSession) WritePacket(pkt []byte) error {
	s.sizes.mu.Lock()
	s.sizes.toVPC[len(pkt)]++
	s.sizes.mu.Unlock()
	return s.BackendSession.WritePacket(pkt)
}

func (s *recordingSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	n, err := s.BackendSession.ReadPacket(ctx, buf)
	if err == nil {
		s.sizes.mu.Lock()
		s.sizes.toClient[n]++
		s.sizes.mu.Unlock()
	}
	return n, err
}

func (s *recordingSession) Close() error {
	s.once.Do(func() {
		s.sizes.mu.Lock()
		s.sizes.closed++
		s.sizes.mu.Unlock()
	})
	return s.BackendSession.Close()
}

func (s *packetSizes) snapshot() (toVPC, toClient map[int]int, opened, closed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	toVPC, toClient = map[int]int{}, map[int]int{}
	for k, v := range s.toVPC {
		toVPC[k] = v
	}
	for k, v := range s.toClient {
		toClient[k] = v
	}
	return toVPC, toClient, s.opened, s.closed
}

// result is one recorded check for the report.
type result struct {
	Check     string         `json:"check"`
	Transport string         `json:"transport"`
	Client    string         `json:"client"`
	Outcome   string         `json:"outcome"`
	Detail    map[string]any `json:"detail,omitempty"`
}

type resultLog struct {
	mu      sync.Mutex
	results []result
}

// record adds r once the test ends, with the test's outcome.
func (h *harness) record(t *testing.T, r result) {
	t.Helper()
	t.Cleanup(func() {
		r.Outcome = "passed"
		if t.Failed() {
			r.Outcome = "failed"
		}
		h.results.mu.Lock()
		h.results.results = append(h.results.results, r)
		h.results.mu.Unlock()
	})
}

func (h *harness) writeResults() error {
	h.results.mu.Lock()
	defer h.results.mu.Unlock()
	xrayVersion, _ := exec.CommandContext(context.Background(), h.xray, "version").Output()
	doc := map[string]any{
		"xray":    strings.SplitN(string(xrayVersion), "\n", 2)[0],
		"go":      runtime.Version(),
		"kernel":  kernelRelease(),
		"results": h.results.results,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(h.artifacts, "results.json"), append(b, '\n'), 0o644)
}

// returnArtifacts gives the artifacts directory to the user who ran sudo, so
// the next run can replace it without root.
func (h *harness) returnArtifacts() error {
	uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uid == "" || gid == "" || h.artifacts == h.dir {
		return nil
	}
	u, err := strconv.Atoi(uid)
	if err != nil {
		return err
	}
	g, err := strconv.Atoi(gid)
	if err != nil {
		return err
	}
	return filepath.WalkDir(h.artifacts, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, u, g)
	})
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}
