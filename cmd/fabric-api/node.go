// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpchealth "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/index"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/probe"
	"go.datum.net/galactic/internal/fabric/query"
	"go.datum.net/galactic/internal/metadata"
)

// tlsFlags are the mTLS file paths every subcommand takes.
type tlsFlags struct {
	cert, key, ca string
}

func (t *tlsFlags) register(cmd *cobra.Command, dir string) {
	cmd.Flags().StringVar(&t.cert, "tls-cert", envOr("FABRIC_API_TLS_CERT", dir+"/tls.crt"),
		"Certificate file (env FABRIC_API_TLS_CERT)")
	cmd.Flags().StringVar(&t.key, "tls-key", envOr("FABRIC_API_TLS_KEY", dir+"/tls.key"),
		"Private key file (env FABRIC_API_TLS_KEY)")
	cmd.Flags().StringVar(&t.ca, "tls-ca", envOr("FABRIC_API_TLS_CA", dir+"/ca.crt"),
		"Trust bundle file (env FABRIC_API_TLS_CA)")
}

func (t *tlsFlags) credentials(self identity.ID) *identity.Credentials {
	return &identity.Credentials{CertFile: t.cert, KeyFile: t.key, CAFile: t.ca, Self: self}
}

const defaultTLSDir = "/var/run/fabric-api/tls"

// searchSourceIndex selects the BMP-fed search index.
const searchSourceIndex = "index"

type nodeOptions struct {
	nodeName, site, cell, namespace, podName string
	hostIP                                   string
	port                                     int
	metricsAddress                           string
	socketDir                                string
	tls                                      tlsFlags
	probeSourceV4, probeSourceV6             string
	probeSourceInterface                     string
	denyPrefixes, operatorAllow              []string
	enableExpensive                          bool
	maxConcurrent, maxExpensive, maxProbes   int
	packetRate                               float64
	breakerCooldown                          time.Duration
	searchSource, bmpAddress                 string
	indexMaxRoutes                           int
}

func newNodeCommand() *cobra.Command {
	o := &nodeOptions{}
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Run the node sidecar beside FRR in a fabric-router pod",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runNode(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.nodeName, "node-name", envOr("NODE_NAME", ""), "This node's name (required; env NODE_NAME)")
	f.StringVar(&o.site, "site", envOr("SITE", ""), "Site this node serves (env SITE)")
	f.StringVar(&o.cell, "cell", envOr("CELL", ""), "Cell name in the mTLS identities (required; env CELL)")
	f.StringVar(&o.namespace, "namespace", envOr("POD_NAMESPACE", ""),
		"This pod's namespace (required; env POD_NAMESPACE)")
	f.StringVar(&o.podName, "pod-name", envOr("POD_NAME", ""), "This pod's name (required; env POD_NAME)")
	f.StringVar(&o.hostIP, "host-ip", envOr("HOST_IP", ""),
		"Address the gRPC service binds to; the pod's selected hostIP (required; env HOST_IP)")
	f.IntVar(&o.port, "port", 9344, "gRPC port")
	f.StringVar(&o.metricsAddress, "metrics-bind-address", envOr("METRICS_BIND_ADDRESS", ""),
		"Address serving /metrics; defaults to <host-ip>:9345 (env METRICS_BIND_ADDRESS)")
	f.StringVar(&o.socketDir, "frr-socket-dir", "/run/frr", "Directory holding FRR's vty sockets")
	o.tls.register(cmd, defaultTLSDir)
	f.StringVar(&o.probeSourceV4, "probe-source-ipv4", envOr("PROBE_SOURCE_IPV4", ""),
		"IPv4 probe source address (env PROBE_SOURCE_IPV4)")
	f.StringVar(&o.probeSourceV6, "probe-source-ipv6", envOr("PROBE_SOURCE_IPV6", ""),
		"IPv6 probe source address (env PROBE_SOURCE_IPV6)")
	f.StringVar(&o.probeSourceInterface, "probe-source-interface", envOr("PROBE_SOURCE_INTERFACE", "lo"),
		"Interface whose single global address per family is the probe source for a family without an explicit one; "+
			"empty disables (env PROBE_SOURCE_INTERFACE)")
	f.StringSliceVar(&o.denyPrefixes, "deny-prefixes", nil, "Platform or management ranges no probe may target")
	f.StringSliceVar(&o.operatorAllow, "operator-allow-prefixes", nil,
		"Narrow ranges only operator identities may probe (lab loopbacks); never set in production")
	f.BoolVar(&o.enableExpensive, "enable-expensive-queries", false,
		"Enable AS-path, community and large-community searches (release-gated on full-table load tests)")
	f.IntVar(&o.maxConcurrent, "max-concurrent", node.DefaultMaxConcurrent, "Execute calls running at once")
	f.IntVar(&o.maxExpensive, "max-expensive", node.DefaultMaxExpensive, "Expensive searches running at once")
	f.IntVar(&o.maxProbes, "max-probes", node.DefaultMaxActiveProbes, "Probes running at once")
	f.Float64Var(&o.packetRate, "probe-packet-rate", node.DefaultPacketRate, "Probe packets per second")
	f.StringVar(&o.searchSource, "search-source", searchSourceIndex,
		"What answers AS-path and community searches: index (a local copy of bgpd's Loc-RIB fed over BMP) or frr "+
			"(FRR's own table scans, which starve bgpd on full tables)")
	f.StringVar(&o.bmpAddress, "bmp-station-address", index.DefaultStationAddress,
		"Loopback address the BMP station listens on for bgpd's Loc-RIB, with --search-source=index")
	f.IntVar(&o.indexMaxRoutes, "search-index-max-routes", 4_000_000, "Prefixes the search index holds at most")
	f.DurationVar(&o.breakerCooldown, "expensive-breaker-cooldown", node.DefaultBreakerCooldown,
		"How long expensive searches stay suspended after one times out")
	return cmd
}

func runNode(parent context.Context, o *nodeOptions) error {
	for name, v := range map[string]string{"node-name": o.nodeName, "namespace": o.namespace,
		"pod-name": o.podName, "host-ip": o.hostIP} {
		if v == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	hostIP, err := netip.ParseAddr(o.hostIP)
	if err != nil {
		return fmt.Errorf("--host-ip: %w", err)
	}
	if o.cell == "" {
		// The cell comes from per-cell configuration that may not exist
		// yet. Exiting would crash-loop a container in the fabric-router
		// pod and hold that pod's readiness, so stay up, unavailable.
		return idleUnconfigured(parent, hostIP, o)
	}
	sources, err := probeSources(o)
	if err != nil {
		return err
	}
	deny, err := query.ParsePrefixes(o.denyPrefixes)
	if err != nil {
		return fmt.Errorf("--deny-prefixes: %w", err)
	}
	allow, err := query.ParsePrefixes(o.operatorAllow)
	if err != nil {
		return fmt.Errorf("--operator-allow-prefixes: %w", err)
	}
	ctx, stop := signalContext(parent)
	defer stop()
	defer setupTracing(ctx, "node")()

	metrics := node.NewMetrics()
	// The certificate belongs to the fabric-api-certs pod on this node, not
	// to this pod; see the certsync subcommand.
	creds := o.tls.credentials(identity.Node(o.cell, o.namespace, ""))
	creds.AcceptAnyNode = true
	creds.OnLoad(func(leaf *x509.Certificate) { metrics.CertificateExpiry(float64(leaf.NotAfter.Unix())) })
	// certsync copies a renewed certificate every 10s; picking it up as
	// quickly keeps the window in which the sidecar presents a replaced
	// certs pod's identity short.
	go creds.Run(ctx, 10*time.Second)

	var ix *index.Index
	switch o.searchSource {
	case searchSourceIndex:
		ix = index.New()
		ix.MaxRoutes = o.indexMaxRoutes
		metrics.RegisterIndex(ix)
		st := &index.Station{Addr: o.bmpAddress, Index: ix, OnMessage: metrics.BMPMessage}
		go func() {
			if err := st.Run(ctx); err != nil {
				slog.Error("BMP station stopped; searches stay unavailable", "error", err)
			}
		}()
	case "frr":
	default:
		return fmt.Errorf("--search-source must be index or frr, not %q", o.searchSource)
	}

	srv, err := node.NewServer(node.Config{
		NodeName:         o.nodeName,
		Site:             o.site,
		FRR:              &frr.VTY{SocketDir: o.socketDir, MaxResponseBytes: query.MaxFRRResponseBytes},
		Prober:           &probe.Prober{},
		ProbeSources:     sources,
		PublicPolicy:     query.DestinationPolicy{Deny: deny},
		OperatorPolicy:   query.DestinationPolicy{Deny: deny, Allow: allow},
		ExpensiveEnabled: o.enableExpensive,
		MaxConcurrent:    o.maxConcurrent,
		MaxExpensive:     o.maxExpensive,
		MaxActiveProbes:  o.maxProbes,
		PacketRate:       o.packetRate,
		BreakerCooldown:  o.breakerCooldown,
		Index:            ix,
		Credentials:      creds,
		Metrics:          metrics,
	})
	if err != nil {
		return err
	}
	go srv.Run(ctx)

	health := grpchealth.NewServer()
	go reportHealth(ctx, srv, health)

	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(creds.ServerConfig(node.AllowedCaller))),
		grpc.ChainUnaryInterceptor(node.AuthInterceptor(nil)),
		grpc.MaxRecvMsgSize(64<<10),
		grpc.MaxSendMsgSize(query.Ceilings.MaxNodeResponseBytes+16<<10),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 30 * time.Second, PermitWithoutStream: true}),
		serverStats(),
	)
	fabricv1.RegisterFabricServiceServer(gs, srv)
	grpc_health_v1.RegisterHealthServer(gs, health)

	addr := net.JoinHostPort(hostIP.String(), strconv.Itoa(o.port))
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	metricsAddr := o.metricsAddress
	if metricsAddr == "" {
		metricsAddr = net.JoinHostPort(hostIP.String(), "9345")
	}
	stopMetrics := serveMetrics(metricsAddr, metrics.Handler())
	defer stopMetrics()

	slog.Info("starting fabric-api node", "version", metadata.Version, "node", o.nodeName, "site", o.site,
		"listen", addr, "metrics", metricsAddr, "probeSources", sources, "expensiveQueries", o.enableExpensive)
	errc := make(chan error, 1)
	go func() { errc <- gs.Serve(lis) }()
	select {
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() { gs.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			gs.Stop()
		}
		return nil
	case err := <-errc:
		return err
	}
}

// idleUnconfigured serves only metrics, reporting diagnostics unavailable,
// until the process is signalled.
func idleUnconfigured(parent context.Context, hostIP netip.Addr, o *nodeOptions) error {
	ctx, stop := signalContext(parent)
	defer stop()
	metrics := node.NewMetrics()
	addr := o.metricsAddress
	if addr == "" {
		addr = net.JoinHostPort(hostIP.String(), "9345")
	}
	stopMetrics := serveMetrics(addr, metrics.Handler())
	defer stopMetrics()
	slog.Error("fabric-api node is not configured: --cell (CELL) is empty; diagnostics are unavailable until it is set")
	<-ctx.Done()
	return nil
}

// reportHealth mirrors diagnostic availability into the gRPC health service.
// It is never wired to a pod probe: an unavailable diagnostic must not take
// FRR's pod out of service.
func reportHealth(ctx context.Context, srv *node.Server, h *grpchealth.Server) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		info, _ := srv.Info(ctx, &fabricv1.InfoRequest{})
		status := grpc_health_v1.HealthCheckResponse_NOT_SERVING
		if info.GetDiagnosticsAvailable() {
			status = grpc_health_v1.HealthCheckResponse_SERVING
		}
		h.SetServingStatus("", status)
		h.SetServingStatus(fabricv1.FabricService_ServiceDesc.ServiceName, status)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// probeSources returns the per-family probe sources: the explicit flags, else
// the single global unicast address of each family on the source interface.
// A family with no address, or with more than one on the interface, gets no
// source and answers ProbeSourceUnavailable; it never falls back to another
// interface or to loopback addresses.
func probeSources(o *nodeOptions) ([]netip.Addr, error) {
	var out []netip.Addr
	explicit := map[bool]bool{}
	for flag, s := range map[string]string{"probe-source-ipv4": o.probeSourceV4, "probe-source-ipv6": o.probeSourceV6} {
		if s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", flag, err)
		}
		if a.Is4() != (flag == "probe-source-ipv4") {
			return nil, fmt.Errorf("--%s: %s is the wrong family", flag, a)
		}
		out = append(out, a)
		explicit[a.Is4()] = true
	}
	if o.probeSourceInterface == "" || (explicit[true] && explicit[false]) {
		return out, nil
	}
	ifi, err := net.InterfaceByName(o.probeSourceInterface)
	if err != nil {
		slog.Warn("probe source interface unavailable; probes without an explicit source are disabled",
			"interface", o.probeSourceInterface, "error", err)
		return out, nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	found := map[bool][]netip.Addr{}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		found[ip.Is4()] = append(found[ip.Is4()], ip)
	}
	for _, v4 := range []bool{true, false} {
		if explicit[v4] {
			continue
		}
		switch len(found[v4]) {
		case 1:
			out = append(out, found[v4][0])
		case 0:
			slog.Warn("no probe source for a family", "ipv4", v4, "interface", o.probeSourceInterface)
		default:
			slog.Warn("several candidate probe sources; set one explicitly", "ipv4", v4, "candidates", found[v4])
		}
	}
	return out, nil
}

func serveMetrics(addr string, h http.Handler) func() {
	mux := http.NewServeMux()
	mux.Handle("/metrics", h)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server exited", "error", err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}
