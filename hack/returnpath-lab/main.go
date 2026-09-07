// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command returnpath-lab is a proof harness for the ingress sidecar's return
// path. It is a lab tool, not a shipped binary: it performs by hand, and
// reversibly, what production code would automate, so three kernel assumptions
// can be tested before anything is written against them.
//
// The assumptions, each proven by a successful `up` plus an end-to-end request:
//
//  1. bpf_fib_lookup with a table id resolves against a bare Linux routing
//     table with no VRF device attached. `up` installs the return route into
//     exactly such a table.
//  2. bpf_redirect_peer from the host root namespace into a VRF-enslaved
//     pod-side veth end delivers to a socket bound to that VRF master. `up`
//     builds that topology.
//  3. A packet arriving on one VRF-enslaved link is locally delivered for an
//     address configured on a different link in the same VRF: the gateway
//     address lives on the sidecar's own veth, not the link this tool creates.
//
// It reuses the production packages rather than hand-marshalling map keys, both
// to avoid layout bugs and so what it proves is proven about the real code
// paths.
//
// Must run in the host's root network namespace with CAP_NET_ADMIN, CAP_BPF,
// and host PID, since namespace discovery walks /proc, with the host's bpffs
// mounted. See the README beside it.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

type config struct {
	locator     string
	nodeID      uint
	vpc         string
	argument    uint
	gwAddr      string
	tableID     uint
	pinDir      string
	ifPrefix    string
	yes         bool
	backend     string
	ports       string
	timeout     time.Duration
	purge       bool
	egressTable uint
	addr        string
	netnsPath   string
	innerSrc    string
	innerSport  uint
	innerDport  uint
	count       int
	sidOverride string
	iface       string
	progID      uint
}

func main() {
	var cfg config
	flag.StringVar(&cfg.locator, "locator", "",
		"this node's BGPRouter spec.srv6Locator, e.g. 2607:ed40:8002::/48 (required)")
	flag.UintVar(&cfg.nodeID, "node-id", 0, "this node's BGPRouter spec.nodeID (required)")
	flag.StringVar(&cfg.vpc, "vpc", "", "base62 VPC id, e.g. 2 (required)")
	flag.UintVar(&cfg.argument, "argument", 0, "this VPC's BGPVRFInstance spec.vrfID on this node (required)")
	flag.StringVar(&cfg.gwAddr, "gw-addr", "",
		"the return-path gateway address the sidecar advertised (required for up/down)")
	flag.UintVar(&cfg.tableID, "table", 900,
		"reserved root-netns routing table id for the return route (plan D-7: a bare table, not a VRF)")
	flag.StringVar(&cfg.pinDir, "pin-dir", "/sys/fs/bpf/galactic", "bpffs directory holding the usid_ingress pinned maps")
	flag.StringVar(&cfg.ifPrefix, "if-prefix", "gwr",
		"root-side veth name prefix; the pair is <prefix><argument> / <prefix><argument>p")
	flag.BoolVar(&cfg.yes, "yes", false, "for up/down: actually apply, instead of only printing the plan")
	flag.StringVar(&cfg.backend, "backend", "", "for probe: a VPC backend address to connect to, e.g. fd20:0:2::3:0:0")
	flag.StringVar(&cfg.ports, "ports", "80,8080,443", "for probe: comma-separated TCP ports to try")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "for probe: per-port connect timeout")
	flag.UintVar(&cfg.egressTable, "egress-table", 0, "for egress-route: the Linux VRF table id to look the prefix up in")
	flag.StringVar(&cfg.addr, "addr", "", "for egress-route: the /128 address to look up")
	flag.StringVar(&cfg.innerSrc, "inner-src", "",
		"for inject: the VPC backend address the inner packet claims to come from")
	flag.UintVar(&cfg.innerSport, "inner-sport", 44444, "for inject: inner TCP source port")
	flag.UintVar(&cfg.innerDport, "inner-dport", 9999, "for inject: inner TCP destination port")
	flag.IntVar(&cfg.count, "count", 3, "for inject: how many packets to send")
	flag.UintVar(&cfg.progID, "prog-id", 0, "for verify-maps: the attached program id, from the filters output")
	flag.StringVar(&cfg.iface, "iface", "",
		"for filters/attach-iface/detach-iface: the interface to act on")
	flag.StringVar(&cfg.sidOverride, "sid", "",
		"for inject: send to this outer destination instead of the derived return SID. Use it to probe which "+
			"usid_ingress step a packet reaches: a SID sharing this node's Block+Node-ID but carrying an "+
			"unregistered Function must be counted as unknown_function if the program runs at all, so a zero "+
			"there means usid_ingress never executed on the packet (it never arrived, or an earlier tc filter "+
			"claimed it with a final verdict).")
	flag.StringVar(&cfg.netnsPath, "netns", "",
		"for probe: use this netns instead of discovering one. Needed where more than one namespace holds a VRF "+
			"for the same VPC -- e.g. a compute node has the tenant VRF in root netns AND its own Envoy pod's VRF "+
			"in that pod's netns. Pass /proc/1/ns/net to probe from the tenant side.")
	flag.BoolVar(&cfg.purge, "purge-locator", false,
		"for down: also remove the locator_table/function_table entries. Needed on a node that also runs "+
			"galactic-gateway, whose own SRv6 address shares this locator+Node-ID with Function 0x0: while a "+
			"locator_table entry exists, usid_ingress claims that address at step 2 and then drops it at step 4 "+
			"as UNKNOWN_FUNCTION instead of passing it through to the XDP/stack path that handles it.")
	flag.Usage = usage

	// The action is the first argument, consumed before flag parsing: Go's flag
	// package stops at the first non-flag argument, so a trailing subcommand
	// would silently swallow every flag after it.
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	action := os.Args[1]
	switch action {
	case "status", "up", "down", "probe", "egress-route", "inject", "filters",
		"verify-maps", "attach-iface", "detach-iface":
	default:
		usage()
		os.Exit(2)
	}
	if err := flag.CommandLine.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	if err := run(action, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\nreturnpath-lab: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `returnpath-lab <status|up|down> [flags]

  status  read-only: report every piece of state the return path needs, and
          whether it is present. Safe, changes nothing.
  up      install the missing state (needs -yes to apply).
  down    remove what up installed (needs -yes to apply). Leaves
          locator_table/function_table alone: those are per-node facts the
          plan's Piece 1 wants permanently, and they are harmless.
  egress-route
          look one /128 up in egress_route_table for a given VRF table id --
          i.e. ask "would usid_egress SRv6-encapsulate a packet this VRF
          sends to that address, and toward which SID?". Run it on a BACKEND
          node against the gateway address to see whether that node has
          imported the sidecar's return-path advertisement at all.
  attach-iface / detach-iface
          attach the already-loaded usid_ingress to an extra interface, or
          remove it. For testing the WireGuard/KubeSpan exclusion.
  filters list an interface's tc filter chain in evaluation order -- who runs
          before usid_ingress, and whether usid_ingress is attached at all.
  inject  send one real SRv6-encapsulated packet at a gateway node's return
          SID, carrying an inner TCP SYN from a backend address to the
          gateway address. Isolates the decap path from whether any tenant
          workload actually replies. Run from any node on the fabric.
  probe   open a VRF-bound TCP connection from inside the Envoy pod's own
          netns to -backend, exactly as an Envoy upstream socket would, and
          classify what comes back. Run it before "up" for a baseline and
          after "up" to see whether the return path now works. Changes no
          state. NOTE: connection *refused* counts as success -- a RST has
          to traverse the whole return path to reach us.

`)
	flag.PrintDefaults()
}

// derived holds the values every action computes from the flags, so the key
// arithmetic lives in one place and `status` prints the same numbers `up`
// writes.
type derived struct {
	block       uint64
	nodeID      uint16
	argument    uint16
	locatorKey  uint64
	functionKey uint64
	vrfKey      uint64
	returnSID   netip.Addr
	vrfName     string
	hostIf      string
	peerIf      string
	gwAddr      net.IP
}

func derive(cfg config) (derived, error) {
	var d derived

	if cfg.locator == "" || cfg.vpc == "" || cfg.nodeID == 0 || cfg.argument == 0 {
		return d, errors.New("-locator, -node-id, -vpc and -argument are all required")
	}
	prefix, err := netip.ParsePrefix(cfg.locator)
	if err != nil {
		return d, fmt.Errorf("parse -locator %q: %w", cfg.locator, err)
	}
	if d.block, err = uformat.Block(prefix.Addr()); err != nil {
		return d, fmt.Errorf("derive uSID Block from -locator %q: %w", cfg.locator, err)
	}
	if cfg.nodeID > uint(uformat.NodeIDMax) {
		return d, fmt.Errorf("-node-id %d exceeds NodeIDMax %#x", cfg.nodeID, uint16(uformat.NodeIDMax))
	}
	if cfg.argument < uint(uformat.ArgumentMin) || cfg.argument > uint(uformat.ArgumentMax) {
		return d, fmt.Errorf("-argument %d outside [%#x,%#x]",
			cfg.argument, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	d.nodeID = uint16(cfg.nodeID)
	d.argument = uint16(cfg.argument)

	// The three keys usid_ingress steps 2, 4 and 6 look up, composed
	// exactly as usid.c's own header comment specifies.
	d.locatorKey = d.block<<16 | uint64(d.nodeID)
	d.functionKey = d.block<<4 | uint64(uformat.FunctionEndDT46)
	d.vrfKey = d.block<<12 | uint64(d.argument)

	// The outer destination a backend node will address the reply to, so
	// status can print it for comparison against a packet capture.
	if d.returnSID, err = srv6.ComputeSID(cfg.locator, int32(cfg.nodeID), int32(cfg.argument),
		bgpv1alpha1.SRv6FunctionEndDT46); err != nil {
		return d, fmt.Errorf("compose return SID: %w", err)
	}

	d.vrfName = intf.GenerateInterfaceNameVRF(cfg.vpc)
	d.hostIf = fmt.Sprintf("%s%d", cfg.ifPrefix, d.argument)
	d.peerIf = d.hostIf + "p"

	if cfg.gwAddr != "" {
		if d.gwAddr = net.ParseIP(cfg.gwAddr); d.gwAddr == nil {
			return d, fmt.Errorf("parse -gw-addr %q", cfg.gwAddr)
		}
	}
	return d, nil
}

func run(action string, cfg config) error {
	d, err := derive(cfg)
	if err != nil {
		return err
	}

	fmt.Printf("=== derived ===\n")
	fmt.Printf("  uSID Block          %#x\n", d.block)
	fmt.Printf("  Node-ID             %d\n", d.nodeID)
	fmt.Printf("  Argument (VRFID)    %d\n", d.argument)
	fmt.Printf("  locator_key         %#x\n", d.locatorKey)
	fmt.Printf("  function_key        %#x  (Function %#x = End.DT46)\n", d.functionKey, uint8(uformat.FunctionEndDT46))
	fmt.Printf("  vrf_key             %#x\n", d.vrfKey)
	fmt.Printf("  expected return SID %s   <-- outer dst a backend node addresses replies to\n", d.returnSID)
	fmt.Printf("  pod-netns VRF       %s\n", d.vrfName)
	fmt.Printf("  veth pair           %s (root netns) <-> %s (pod netns, enslaved into %s)\n",
		d.hostIf, d.peerIf, d.vrfName)
	if d.gwAddr != nil {
		fmt.Printf("  gateway address     %s/128 -> table %d via %s\n", d.gwAddr, cfg.tableID, d.hostIf)
	}
	fmt.Println()

	switch action {
	case "status":
		return status(cfg, d)
	case "up":
		return up(cfg, d)
	case "down":
		return down(cfg, d)
	case "probe":
		return probe(cfg, d)
	case "egress-route":
		return egressRoute(cfg, d)
	case "inject":
		return inject(cfg, d)
	case "filters":
		return filters(cfg, d)
	case "verify-maps":
		return verifyMaps(cfg, d)
	case "attach-iface":
		return attachIface(cfg, d)
	case "detach-iface":
		return detachIface(cfg, d)
	}
	return nil
}

// ---------------------------------------------------------------------
// pod netns discovery
// ---------------------------------------------------------------------

type podNetns struct {
	path  string
	pid   string
	inode string
}

// findPodNetns locates the network namespaces holding vrfName by walking /proc,
// deduplicating by namespace inode, and entering each distinct namespace to look
// for that interface.
//
// This is the mechanism for identifying which pod's namespace holds a given
// VPC's VRF from a root-namespace process, with no CNI ADD ever having happened
// for that pod. The VRF's name is fully determined by the VPC id, so the
// interface itself is the identifier: no annotation, runtime call, or published
// inode is needed.
func findPodNetns(vrfName string) ([]podNetns, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc (is hostPID set?): %w", err)
	}

	seen := make(map[string]string) // netns inode -> first pid seen
	var pids []string
	for _, e := range entries {
		if !e.IsDir() || strings.IndexFunc(e.Name(), func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			continue
		}
		link, lerr := os.Readlink(filepath.Join("/proc", e.Name(), "ns", "net"))
		if lerr != nil {
			continue // process exited, or not visible to us
		}
		if _, dup := seen[link]; dup {
			continue
		}
		seen[link] = e.Name()
		pids = append(pids, e.Name())
	}
	sort.Strings(pids)

	var found []podNetns
	for _, pid := range pids {
		path := filepath.Join("/proc", pid, "ns", "net")
		var hit bool
		err := ns.WithNetNSPath(path, func(ns.NetNS) error {
			if _, lerr := netlink.LinkByName(vrfName); lerr == nil {
				hit = true
			}
			return nil
		})
		if err != nil {
			continue // namespace vanished mid-walk, or cannot be entered
		}
		if hit {
			inode := ""
			if l, lerr := os.Readlink(path); lerr == nil {
				inode = l
			}
			found = append(found, podNetns{path: path, pid: pid, inode: inode})
		}
	}
	return found, nil
}

// ---------------------------------------------------------------------
// status
// ---------------------------------------------------------------------

func status(cfg config, d derived) error {
	fmt.Printf("=== eBPF maps (%s) ===\n", cfg.pinDir)
	registry, closer, err := usidmap.OpenPinnedRegistry(cfg.pinDir)
	if err != nil {
		fmt.Printf("  !! cannot open pinned registry: %v\n", err)
	} else {
		defer func() { _ = closer.Close() }()

		locs, lerr := registry.Locator.List()
		fmt.Printf("  locator_table  %s\n", countOrErr(len(locs), lerr))
		for _, l := range locs {
			mark := " "
			if l.Block == d.block && l.NodeID == d.nodeID {
				mark = "*"
			}
			fmt.Printf("   %s block=%#x node-id=%d\n", mark, l.Block, l.NodeID)
		}

		fns, ferr := registry.Function.List()
		fmt.Printf("  function_table %s\n", countOrErr(len(fns), ferr))
		for _, f := range fns {
			mark := " "
			if f.Block == d.block && f.Function == uint8(uformat.FunctionEndDT46) {
				mark = "*"
			}
			fmt.Printf("   %s block=%#x function=%#x behavior=%d\n", mark, f.Block, f.Function, f.Behavior)
		}

		vrfs, verr := registry.VRF.List()
		fmt.Printf("  vrf_table      %s\n", countOrErr(len(vrfs), verr))
		for _, v := range vrfs {
			mark := " "
			if v.Block == d.block && v.Argument == d.argument {
				mark = "*"
			}
			note := ""
			if v.Block == uformat.BlockMax {
				note = "  (ingresssidecar's synthetic BlockMax entry, usid_egress only)"
			}
			fmt.Printf("   %s block=%#x arg=%d -> table=%d egress_kind=%d pkts=%d drops=%d%s\n",
				mark, v.Block, v.Argument, v.VRFTableID, v.EgressKind, v.Packets, v.DroppedPackets, note)
		}
		fmt.Printf("  (* = the entry this return path needs)\n")
	}

	fmt.Printf("\n=== root netns ===\n")
	reportLink(d.hostIf)
	reportRoute(d, cfg.tableID)
	reportNeigh(d)
	reportForwarding(d.hostIf)

	fmt.Printf("\n=== pod netns discovery (looking for %s) ===\n", d.vrfName)
	found, err := findPodNetns(d.vrfName)
	if err != nil {
		fmt.Printf("  !! %v\n", err)
	} else if len(found) == 0 {
		fmt.Printf("  !! no network namespace on this node holds %s\n", d.vrfName)
		fmt.Printf("     the sidecar has not created this VPC's VRF here; nothing to attach to yet\n")
	} else {
		for _, p := range found {
			fmt.Printf("  netns %s (pid %s, %s)\n", p.path, p.pid, p.inode)
			if derr := describePodNetns(p.path, d); derr != nil {
				fmt.Printf("    !! %v\n", derr)
			}
		}
	}

	fmt.Printf("\n=== drop_reasons (non-zero) ===\n")
	if err := reportDropReasons(cfg.pinDir); err != nil {
		fmt.Printf("  !! %v\n", err)
	}
	return nil
}

func countOrErr(n int, err error) string {
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	if n == 0 {
		return "EMPTY"
	}
	return fmt.Sprintf("%d entr%s", n, plural(n))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func reportLink(name string) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		fmt.Printf("  link %-10s ABSENT\n", name)
		return
	}
	a := link.Attrs()
	fmt.Printf("  link %-10s present ifindex=%d mac=%s oper=%s\n", name, a.Index, a.HardwareAddr, a.OperState)
}

func reportRoute(d derived, tableID uint) {
	if d.gwAddr == nil {
		fmt.Printf("  route             (skipped, no -gw-addr)\n")
		return
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		fmt.Printf("  route             ERROR: %v\n", err)
		return
	}
	if len(routes) == 0 {
		fmt.Printf("  table %-4d        EMPTY (no route for %s)\n", tableID, d.gwAddr)
		return
	}
	for _, r := range routes {
		dst := "default"
		if r.Dst != nil {
			dst = r.Dst.String()
		}
		name := strconv.Itoa(r.LinkIndex)
		if l, lerr := netlink.LinkByIndex(r.LinkIndex); lerr == nil {
			name = l.Attrs().Name
		}
		fmt.Printf("  table %-4d        %s dev %s\n", tableID, dst, name)
	}
}

func reportNeigh(d derived) {
	if d.gwAddr == nil {
		fmt.Printf("  neigh             (skipped, no -gw-addr)\n")
		return
	}
	link, err := netlink.LinkByName(d.hostIf)
	if err != nil {
		fmt.Printf("  neigh             (skipped, %s absent)\n", d.hostIf)
		return
	}
	neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
	if err != nil {
		fmt.Printf("  neigh             ERROR: %v\n", err)
		return
	}
	for _, n := range neighs {
		if n.IP.Equal(d.gwAddr) {
			perm := ""
			if n.State&netlink.NUD_PERMANENT != 0 {
				perm = " NUD_PERMANENT"
			}
			fmt.Printf("  neigh             %s lladdr %s dev %s%s\n", n.IP, n.HardwareAddr, d.hostIf, perm)
			return
		}
	}
	fmt.Printf("  neigh             ABSENT for %s on %s  <-- bpf_fib_lookup would return NO_NEIGH\n", d.gwAddr, d.hostIf)
}

func reportForwarding(hostIf string) {
	for _, k := range []string{"all", hostIf} {
		p := filepath.Join("/proc/sys/net/ipv6/conf", k, "forwarding")
		b, err := os.ReadFile(p) //nolint:gosec // fixed, non-user-controlled proc path
		if err != nil {
			fmt.Printf("  fwd %-13s (unreadable: %v)\n", k, err)
			continue
		}
		v := strings.TrimSpace(string(b))
		note := ""
		if v == "0" {
			note = "  <-- bpf_fib_lookup can return FWD_DISABLED, which usid.c counts as generic fib_lookup_failed"
		}
		fmt.Printf("  fwd %-13s %s%s\n", k, v, note)
	}
}

// describePodNetns reports, from inside the pod's namespace, the three things
// the return path depends on there: the VRF and its table, which links are
// enslaved to it, and which of those carries the gateway address. Delivery is
// cross-interface within one VRF, so that is expected not to be the link this
// tool creates.
func describePodNetns(path string, d derived) error {
	return ns.WithNetNSPath(path, func(ns.NetNS) error {
		vrfLink, err := netlink.LinkByName(d.vrfName)
		if err != nil {
			return fmt.Errorf("look up %s: %w", d.vrfName, err)
		}
		vrfDev, ok := vrfLink.(*netlink.Vrf)
		if !ok {
			return fmt.Errorf("%s is a %s, not a VRF", d.vrfName, vrfLink.Type())
		}
		fmt.Printf("    %s ifindex=%d table=%d oper=%s\n",
			d.vrfName, vrfDev.Attrs().Index, vrfDev.Table, vrfDev.Attrs().OperState)

		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("list links: %w", err)
		}
		for _, l := range links {
			a := l.Attrs()
			if a.MasterIndex != vrfDev.Attrs().Index {
				continue
			}
			addrs, _ := netlink.AddrList(l, netlink.FAMILY_V6) //nolint:errcheck // reported as empty below
			var strs []string
			for _, ad := range addrs {
				mark := ""
				if d.gwAddr != nil && ad.IP.Equal(d.gwAddr) {
					mark = " <-- gateway address"
				}
				strs = append(strs, ad.IPNet.String()+mark)
			}
			fmt.Printf("      enslaved: %-12s (%s) mac=%s oper=%s addrs=%s\n",
				a.Name, l.Type(), a.HardwareAddr, a.OperState, strings.Join(strs, ", "))
		}
		if _, err := netlink.LinkByName(d.peerIf); err == nil {
			fmt.Printf("      %s present in this netns\n", d.peerIf)
		} else {
			fmt.Printf("      %s ABSENT from this netns\n", d.peerIf)
		}
		return nil
	})
}

func reportDropReasons(pinDir string) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "drop_reasons"), nil)
	if err != nil {
		return fmt.Errorf("open pinned drop_reasons: %w", err)
	}
	defer func() { _ = m.Close() }()

	// The entry count matters: loading reuses an already-pinned map as-is, so a
	// node whose pin predates a newly added drop reason has a map too small to
	// hold it and the counter for that index silently fails. Two nodes running
	// the same image can therefore expose different counters, so report the
	// size rather than let it look like a genuine zero.
	fmt.Printf("  (map max_entries=%d; usid.c currently defines 29)\n", m.MaxEntries())

	any := false
	for idx := range m.MaxEntries() {
		var perCPU []uint64
		if err := m.Lookup(&idx, &perCPU); err != nil {
			fmt.Printf("  !! lookup index %d failed: %v\n", idx, err)
			break
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		if total == 0 {
			continue
		}
		any = true
		name, ok := prog.DropReasonNames[idx]
		if !ok {
			// The datapath carries diagnostic counters above the Go mirror's
			// count, which stops there and which the metrics collector
			// deliberately does not export. They are the most useful signal
			// here, so name them locally rather than widen the production
			// mirror for a set documented as temporary.
			if n, tok := traceReasonNames[idx]; tok {
				name = n
			} else {
				name = fmt.Sprintf("unknown(%d)", idx)
			}
		}
		fmt.Printf("  %-28s %d\n", name, total)
	}
	if !any {
		fmt.Printf("  (all zero)\n")
	}
	return nil
}

// traceReasonNames mirrors the datapath's diagnostic checkpoints, which sit
// above the Go mirror's drop-reason count and so have no name there. Read
// together they say how far usid_egress got: entry, ifindex hit, room adjusted,
// reached redirect, redirect ok is a fully successful encapsulation.
//
// The higher slots are the same idea for usid_ingress, which had no success
// counter at all, bracketing its own redirect step. One of them is a value
// rather than a count, the ifindex the FIB lookup resolved, printed as-is. One
// is a real drop.
var traceReasonNames = map[uint32]string{
	16: "trace_multicast_ll_bail",
	17: "trace_miss_vrf",
	18: "trace_miss_route",
	19: "trace_passthrough_entry",
	20: "trace_adjust_room_ok",
	21: "trace_reached_redirect",
	22: "trace_redirect_ok",
	23: "trace_ifindex_miss",
	24: "trace_entry",
	25: "trace_pull_data_failed",
	26: "trace_eth_bounds_failed",
	27: "trace_ethertype_mismatch",
	28: "trace_ifindex_hit",
	29: "trace_ing_reached_redirect",
	30: "trace_ing_redirect_ok",
	31: "trace_ing_last_ifindex (VALUE, not a count)",
	32: "fib_no_ifindex",
	33: "trace_ing_entry",
	34: "trace_ing_pull_data_failed",
	35: "trace_ing_eth_bounds_failed",
	36: "trace_ing_ethertype_mismatch",
	37: "trace_ing_ip6_bounds_failed",
	38: "trace_ing_locator_miss",
}

// ---------------------------------------------------------------------
// up
// ---------------------------------------------------------------------

func up(cfg config, d derived) error {
	if d.gwAddr == nil {
		return errors.New("-gw-addr is required for up")
	}

	found, err := findPodNetns(d.vrfName)
	if err != nil {
		return fmt.Errorf("discover pod netns: %w", err)
	}
	switch len(found) {
	case 0:
		return fmt.Errorf(
			"no network namespace on this node holds %s -- the sidecar has not created this VPC's VRF here", d.vrfName)
	case 1:
	default:
		return fmt.Errorf("ambiguous: %d namespaces hold %s; refusing to guess", len(found), d.vrfName)
	}
	target := found[0]
	fmt.Printf("=== plan ===\n")
	fmt.Printf("  1. create veth %s <-> %s in root netns\n", d.hostIf, d.peerIf)
	fmt.Printf("  2. move %s into %s (pid %s), enslave into %s, set up\n", d.peerIf, target.path, target.pid, d.vrfName)
	fmt.Printf("  3. root netns: ip -6 route replace %s/128 dev %s table %d\n", d.gwAddr, d.hostIf, cfg.tableID)
	fmt.Printf("  4. root netns: ip -6 neigh replace %s lladdr <%s mac> dev %s nud permanent\n",
		d.gwAddr, d.peerIf, d.hostIf)
	fmt.Printf("  5. locator_table.Register(block=%#x, node-id=%d)\n", d.block, d.nodeID)
	fmt.Printf("  6. function_table.Register(block=%#x, function=%#x)\n", d.block, uint8(uformat.FunctionEndDT46))
	fmt.Printf("  7. vrf_table.Register(block=%#x, arg=%d, table=%d, egress_kind=veth)\n",
		d.block, d.argument, cfg.tableID)
	fmt.Println()

	if !cfg.yes {
		fmt.Printf("dry run: pass -yes to apply\n")
		return nil
	}

	// The veth. Both ends are created in this root namespace and then the peer
	// is moved, the same order the CNI uses for a tenant pod, and the reason
	// this side can know the peer's MAC without entering the pod's namespace.
	peerMAC, err := ensureVeth(d)
	if err != nil {
		return err
	}
	fmt.Printf("  [1,2] veth ready, %s mac=%s\n", d.peerIf, peerMAC)

	if err := moveAndEnslave(target.path, d); err != nil {
		return err
	}
	fmt.Printf("  [2]   %s moved into %s and enslaved into %s\n", d.peerIf, target.path, d.vrfName)

	hostLink, err := netlink.LinkByName(d.hostIf)
	if err != nil {
		return fmt.Errorf("look up %s after setup: %w", d.hostIf, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("set %s up: %w", d.hostIf, err)
	}

	// 3: the return route, into a bare table with no VRF device (plan D-7).
	route := &netlink.Route{
		Dst:       &net.IPNet{IP: d.gwAddr, Mask: net.CIDRMask(128, 128)},
		LinkIndex: hostLink.Attrs().Index,
		Table:     int(cfg.tableID),
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("install %s/128 dev %s table %d: %w", d.gwAddr, d.hostIf, cfg.tableID, err)
	}
	fmt.Printf("  [3]   route %s/128 dev %s table %d\n", d.gwAddr, d.hostIf, cfg.tableID)

	// The permanent neighbor entry. Without it, bpf_fib_lookup returns
	// NO_NEIGH and usid_ingress drops the packet.
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    hostLink.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           d.gwAddr,
		HardwareAddr: peerMAC,
	}); err != nil {
		return fmt.Errorf("install permanent neighbor %s -> %s on %s: %w", d.gwAddr, peerMAC, d.hostIf, err)
	}
	fmt.Printf("  [4]   neigh %s lladdr %s dev %s NUD_PERMANENT\n", d.gwAddr, peerMAC, d.hostIf)

	// 5-7: the three map entries.
	registry, closer, err := usidmap.OpenPinnedRegistry(cfg.pinDir)
	if err != nil {
		return fmt.Errorf("open pinned registry: %w", err)
	}
	defer func() { _ = closer.Close() }()

	if err := registry.Locator.Register(d.block, d.nodeID); err != nil {
		return fmt.Errorf("register locator_table: %w", err)
	}
	fmt.Printf("  [5]   locator_table  block=%#x node-id=%d\n", d.block, d.nodeID)

	if err := registry.Function.Register(d.block, uint8(uformat.FunctionEndDT46)); err != nil {
		return fmt.Errorf("register function_table: %w", err)
	}
	fmt.Printf("  [6]   function_table block=%#x function=%#x\n", d.block, uint8(uformat.FunctionEndDT46))

	if err := registry.VRF.Register(d.block, d.argument, uint32(cfg.tableID), usidmap.EgressKindVeth); err != nil {
		return fmt.Errorf("register vrf_table: %w", err)
	}
	fmt.Printf("  [7]   vrf_table      block=%#x arg=%d -> table=%d egress_kind=veth\n", d.block, d.argument, cfg.tableID)

	fmt.Printf("\nup complete. Now send a real request through Envoy for this VPC's backend.\n")
	fmt.Printf("Re-run `status` afterwards: vrf_table's pkts/drops for arg=%d and drop_reasons\n", d.argument)
	fmt.Printf("tell you exactly which step a failure landed on.\n")
	return nil
}

// ensureVeth creates the pair if absent and returns the peer end's MAC,
// read while both ends are still in this namespace. Idempotent.
func ensureVeth(d derived) (net.HardwareAddr, error) {
	if _, err := netlink.LinkByName(d.hostIf); err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("look up %s: %w", d.hostIf, err)
		}
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: d.hostIf},
			PeerName:  d.peerIf,
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return nil, fmt.Errorf("add veth %s/%s: %w", d.hostIf, d.peerIf, err)
		}
	}

	// The peer may be here (freshly created) or already moved by a prior
	// run; look in both places.
	if peer, err := netlink.LinkByName(d.peerIf); err == nil {
		return peer.Attrs().HardwareAddr, nil
	}
	found, err := findPodNetns(d.vrfName)
	if err != nil || len(found) != 1 {
		return nil, fmt.Errorf("%s is neither in root netns nor locatable in a pod netns", d.peerIf)
	}
	var mac net.HardwareAddr
	if err := ns.WithNetNSPath(found[0].path, func(ns.NetNS) error {
		peer, lerr := netlink.LinkByName(d.peerIf)
		if lerr != nil {
			return lerr
		}
		mac = peer.Attrs().HardwareAddr
		return nil
	}); err != nil {
		return nil, fmt.Errorf("read %s mac in pod netns: %w", d.peerIf, err)
	}
	return mac, nil
}

// moveAndEnslave moves the peer end into the pod's namespace (a no-op if a
// prior run already did) and enslaves it into that VPC's VRF there.
func moveAndEnslave(netnsPath string, d derived) error {
	if peer, err := netlink.LinkByName(d.peerIf); err == nil {
		handle, oerr := ns.GetNS(netnsPath)
		if oerr != nil {
			return fmt.Errorf("open %s: %w", netnsPath, oerr)
		}
		defer func() { _ = handle.Close() }()
		if err := netlink.LinkSetNsFd(peer, int(handle.Fd())); err != nil {
			return fmt.Errorf("move %s into %s: %w", d.peerIf, netnsPath, err)
		}
	}

	return ns.WithNetNSPath(netnsPath, func(ns.NetNS) error {
		peer, err := netlink.LinkByName(d.peerIf)
		if err != nil {
			return fmt.Errorf("look up %s inside pod netns: %w", d.peerIf, err)
		}
		vrfLink, err := netlink.LinkByName(d.vrfName)
		if err != nil {
			return fmt.Errorf("look up %s inside pod netns: %w", d.vrfName, err)
		}
		if err := netlink.LinkSetMaster(peer, vrfLink); err != nil {
			return fmt.Errorf("enslave %s into %s: %w", d.peerIf, d.vrfName, err)
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return fmt.Errorf("set %s up: %w", d.peerIf, err)
		}
		return nil
	})
}

// ---------------------------------------------------------------------
// down
// ---------------------------------------------------------------------

func down(cfg config, d derived) error {
	fmt.Printf("=== plan ===\n")
	fmt.Printf("  1. vrf_table.Unregister(block=%#x, arg=%d)\n", d.block, d.argument)
	if d.gwAddr != nil {
		fmt.Printf("  2. remove neigh %s on %s, and route %s/128 from table %d\n", d.gwAddr, d.hostIf, d.gwAddr, cfg.tableID)
	}
	fmt.Printf("  3. delete veth %s (takes %s with it)\n", d.hostIf, d.peerIf)
	if cfg.purge {
		fmt.Printf("  4. remove locator_table(block=%#x, node-id=%d) and function_table(block=%#x, function=%#x)\n",
			d.block, d.nodeID, d.block, uint8(uformat.FunctionEndDT46))
	} else {
		fmt.Printf("  locator_table/function_table left in place; pass -purge-locator to remove them too\n")
	}
	fmt.Println()

	if !cfg.yes {
		fmt.Printf("dry run: pass -yes to apply\n")
		return nil
	}

	var errs []error

	// Unregister the map entry before the veth goes, so a decapsulated packet
	// can never be redirected at a freed ifindex.
	if registry, closer, err := usidmap.OpenPinnedRegistry(cfg.pinDir); err != nil {
		errs = append(errs, fmt.Errorf("open pinned registry: %w", err))
	} else {
		if err := registry.VRF.Unregister(d.block, d.argument); err != nil {
			errs = append(errs, fmt.Errorf("unregister vrf_table: %w", err))
		} else {
			fmt.Printf("  [1]   vrf_table entry removed\n")
		}
		_ = closer.Close()
	}

	if d.gwAddr != nil {
		if hostLink, err := netlink.LinkByName(d.hostIf); err == nil {
			if err := netlink.NeighDel(&netlink.Neigh{
				LinkIndex: hostLink.Attrs().Index,
				Family:    netlink.FAMILY_V6,
				IP:        d.gwAddr,
			}); err != nil && !errors.Is(err, syscall.ENOENT) {
				errs = append(errs, fmt.Errorf("delete neighbor: %w", err))
			}
		}
		if err := netlink.RouteDel(&netlink.Route{
			Dst:   &net.IPNet{IP: d.gwAddr, Mask: net.CIDRMask(128, 128)},
			Table: int(cfg.tableID),
		}); err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, fmt.Errorf("delete route: %w", err))
		}
		fmt.Printf("  [2]   neigh/route removed (absent is not an error)\n")
	}

	if hostLink, err := netlink.LinkByName(d.hostIf); err == nil {
		if err := netlink.LinkDel(hostLink); err != nil {
			errs = append(errs, fmt.Errorf("delete veth %s: %w", d.hostIf, err))
		} else {
			fmt.Printf("  [3]   veth %s deleted\n", d.hostIf)
		}
	} else {
		fmt.Printf("  [3]   veth %s already absent\n", d.hostIf)
	}

	if cfg.purge {
		if registry, closer, err := usidmap.OpenPinnedRegistry(cfg.pinDir); err != nil {
			errs = append(errs, fmt.Errorf("open pinned registry for purge: %w", err))
		} else {
			if err := registry.Locator.Unregister(d.block, d.nodeID); err != nil {
				errs = append(errs, fmt.Errorf("unregister locator_table: %w", err))
			}
			if err := registry.Function.Unregister(d.block, uint8(uformat.FunctionEndDT46)); err != nil {
				errs = append(errs, fmt.Errorf("unregister function_table: %w", err))
			}
			_ = closer.Close()
			fmt.Printf("  [4]   locator_table/function_table entries removed\n")
		}
	}

	return errors.Join(errs...)
}

// ---------------------------------------------------------------------
// probe
// ---------------------------------------------------------------------

// probe opens a TCP connection from inside the Envoy pod's network namespace,
// bound to that VPC's VRF device, the exact socket shape the extension server
// configures on Envoy's upstream clusters. What comes back classifies the
// return path:
//
//   - Connected, or refused: the return path works. Both require a packet to
//     have travelled backend, VRF, encapsulation, fabric, this node,
//     decapsulation, veth, socket. A reset proves it as well as a handshake.
//   - Timeout: nothing came back. Either the forward path never reached the
//     backend or the reply was lost returning. The map counters and drop
//     reasons `status` prints disambiguate which.
//
// Raw syscalls rather than a dialer: the socket must be created on the same OS
// thread currently attached to the pod's namespace, and Go's netpoll offers no
// guarantee about which thread performs the underlying socket call. A send
// timeout bounds the blocking connect.
func probe(cfg config, d derived) error {
	if cfg.backend == "" {
		return errors.New("-backend is required for probe")
	}
	backend := net.ParseIP(cfg.backend)
	if backend == nil || backend.To4() != nil {
		return fmt.Errorf("-backend %q is not an IPv6 address", cfg.backend)
	}

	var ports []int
	for _, p := range strings.Split(cfg.ports, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return fmt.Errorf("parse -ports %q: %w", cfg.ports, err)
		}
		ports = append(ports, n)
	}

	netnsPath := cfg.netnsPath
	if netnsPath == "" {
		found, err := findPodNetns(d.vrfName)
		if err != nil {
			return fmt.Errorf("discover pod netns: %w", err)
		}
		if len(found) != 1 {
			return fmt.Errorf("%d namespaces hold %s; pass -netns to pick one", len(found), d.vrfName)
		}
		netnsPath = found[0].path
	}

	fmt.Printf("=== probe ===\n")
	fmt.Printf("  from netns  %s\n", netnsPath)
	fmt.Printf("  bound to    %s (SO_BINDTODEVICE, as #856 configures Envoy)\n", d.vrfName)
	fmt.Printf("  to          %s ports %v, %s timeout each\n\n", backend, ports, cfg.timeout)

	return ns.WithNetNSPath(netnsPath, func(ns.NetNS) error {
		for _, port := range ports {
			verdict, src, err := connectOnce(d.vrfName, backend, port, cfg.timeout)
			line := fmt.Sprintf("  port %-5d %s", port, verdict)
			if src != "" {
				line += fmt.Sprintf("  (source %s)", src)
			}
			if err != nil {
				line += fmt.Sprintf("  [%v]", err)
			}
			fmt.Println(line)
		}
		return nil
	})
}

// connectOnce performs one VRF-bound connect and classifies the result.
func connectOnce(vrfName string, backend net.IP, port int, timeout time.Duration) (verdict, src string, err error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return "SOCKET FAILED", "", err
	}
	defer func() { _ = syscall.Close(fd) }()

	// Binding to the VRF master is what sends this socket's route lookup into
	// that VPC's table, and what makes a reply arriving on a VRF-enslaved link
	// match this socket at all.
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrfName); err != nil {
		return "SO_BINDTODEVICE FAILED", "", err
	}
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv); err != nil {
		return "SO_SNDTIMEO FAILED", "", err
	}

	sa := &syscall.SockaddrInet6{Port: port}
	copy(sa.Addr[:], backend.To16())

	cerr := syscall.Connect(fd, sa)
	if name, gerr := syscall.Getsockname(fd); gerr == nil {
		if in6, ok := name.(*syscall.SockaddrInet6); ok {
			ip := net.IP(in6.Addr[:])
			if !ip.IsUnspecified() {
				src = ip.String()
			}
		}
	}

	switch {
	case cerr == nil:
		return "CONNECTED       -> return path WORKS", src, nil
	case errors.Is(cerr, syscall.ECONNREFUSED):
		return "REFUSED (RST)   -> return path WORKS (a RST traversed it)", src, nil
	case errors.Is(cerr, syscall.ECONNRESET):
		return "RESET           -> return path WORKS (a RST traversed it)", src, nil
	case errors.Is(cerr, syscall.EINPROGRESS), errors.Is(cerr, syscall.EAGAIN), errors.Is(cerr, syscall.ETIMEDOUT):
		return "TIMEOUT         -> nothing came back", src, nil
	case errors.Is(cerr, syscall.ENETUNREACH), errors.Is(cerr, syscall.EHOSTUNREACH):
		return "UNREACHABLE     -> forward path broken, not the return path", src, cerr
	default:
		return "ERROR", src, cerr
	}
}

// ---------------------------------------------------------------------
// egress-route
// ---------------------------------------------------------------------

// egressRoute answers the one question separating "the backend never replied"
// from "the backend replied but its node had nowhere to send the reply": does
// egress_route_table hold an entry for this address in this VRF's table, and if
// so toward which SID?
//
// Run it on a backend node with the gateway address and that node's own tenant
// VRF table id. A hit means the router imported the sidecar's advertisement and
// usid_egress will encapsulate replies toward the gateway node. A miss means
// the reply leaves unencapsulated, or not at all, and no amount of decap state
// on the gateway node can help.
func egressRoute(cfg config, _ derived) error {
	if cfg.addr == "" || cfg.egressTable == 0 {
		return errors.New("-addr and -egress-table are both required for egress-route")
	}
	ip := net.ParseIP(cfg.addr)
	if ip == nil {
		return fmt.Errorf("parse -addr %q", cfg.addr)
	}
	prefix := &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}

	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(cfg.pinDir)
	if err != nil {
		return fmt.Errorf("open pinned egress_route_table: %w", err)
	}
	defer func() { _ = closer.Close() }()

	fmt.Printf("=== egress_route_table lookup ===\n")
	fmt.Printf("  table %d, prefix %s\n", cfg.egressTable, prefix)

	sid, ok, err := table.Lookup(uint32(cfg.egressTable), prefix)
	if err != nil {
		return fmt.Errorf("lookup: %w", err)
	}
	if !ok {
		fmt.Printf("  MISS -- this VRF has no egress route for %s.\n", ip)
		fmt.Printf("  A reply to that address is NOT SRv6-encapsulated from this node.\n")
		return nil
	}
	if sid == nil || sid.IsUnspecified() {
		fmt.Printf("  HIT, local pass-through (no SID): not encapsulated.\n")
		return nil
	}
	fmt.Printf("  HIT -> SID %s\n", sid)
	if f, derr := uformat.Decode(mustAddr(sid)); derr == nil {
		fmt.Printf("  decoded: block=%#x node-id=%d function=%#x argument=%d\n",
			f.Block, f.NodeID, f.Function, f.Argument)
	}
	return nil
}

func mustAddr(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip.To16())
	return a
}

// ---------------------------------------------------------------------
// inject
// ---------------------------------------------------------------------

// inject sends one genuine encapsulated packet at a gateway node's uplink,
// addressed to that node's return SID and carrying an inner TCP SYN from a VPC
// backend address to the gateway address.
//
// This is what isolates the decap path. Every other way of generating the reply
// depends on a tenant workload actually replying:
//
//   - Probing the backend from Envoy needs the backend to answer, and a
//     unikernel behind a tap may not.
//   - Probing the gateway address from the backend node's own root-namespace
//     VRF does not work either, and the reason is instructive: usid_egress
//     attaches to the ingress hook of a tenant's tap or veth, where a tenant's
//     outbound traffic arrives from the workload, so a packet the host itself
//     originates into that VRF never traverses it and leaves through the VRF's
//     NAT66 default instead.
//
// So the encapsulation is done here, by the kernel: a raw IPv6 socket with
// protocol 41 makes the kernel build the outer header, with a source address
// chosen from the host's own routing, which is what keeps it past source
// filtering. Byte for byte what a backend node's usid_egress would produce.
func inject(cfg config, d derived) error {
	innerSrc := net.ParseIP(cfg.innerSrc)
	if innerSrc == nil {
		return fmt.Errorf("-inner-src %q is not an IP", cfg.innerSrc)
	}
	if d.gwAddr == nil {
		return errors.New("-gw-addr is required for inject (it is the inner destination)")
	}

	inner := buildInnerSYN(innerSrc, d.gwAddr, uint16(cfg.innerSport), uint16(cfg.innerDport))

	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, 41) // 41 = IPv6-in-IPv6
	if err != nil {
		return fmt.Errorf("open raw socket (need CAP_NET_RAW): %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	outer := d.returnSID
	label := "this node's derived return SID"
	if cfg.sidOverride != "" {
		a, perr := netip.ParseAddr(cfg.sidOverride)
		if perr != nil {
			return fmt.Errorf("parse -sid %q: %w", cfg.sidOverride, perr)
		}
		outer, label = a, "override"
	}
	var sa syscall.SockaddrInet6
	copy(sa.Addr[:], outer.AsSlice())

	fmt.Printf("=== inject ===\n")
	fmt.Printf("  outer dst  %s   (%s)\n", outer, label)
	fmt.Printf("  outer nh   41 (IPv6-in-IPv6), outer src chosen by the kernel\n")
	fmt.Printf("  inner      [%s]:%d -> [%s]:%d  TCP SYN, %d bytes\n",
		innerSrc, cfg.innerSport, d.gwAddr, cfg.innerDport, len(inner))
	fmt.Printf("  count      %d\n\n", cfg.count)

	for range cfg.count {
		if err := syscall.Sendto(fd, inner, 0, &sa); err != nil {
			return fmt.Errorf("sendto %s: %w", outer, err)
		}
	}
	fmt.Printf("  sent %d packet(s).\n", cfg.count)
	fmt.Printf("  Now check the GATEWAY node's vrf_table entry for arg=%d:\n", d.argument)
	fmt.Printf("    pkts up, drops 0  -> decap + redirect succeeded; the return path WORKS\n")
	fmt.Printf("    pkts up, drops up -> claimed then dropped; drop_reasons names which step\n")
	fmt.Printf("    pkts unchanged    -> never reached step 6 (locator/function miss, or never arrived)\n")
	return nil
}

// buildInnerSYN builds a 60-byte inner packet: a 40-byte IPv6 header plus a
// 20-byte TCP SYN, with the checksum computed over the pseudo-header.
// usid_ingress requires the inner packet's version nibble to be 4 or 6 and
// reads its addresses for the FIB lookup, so it must be genuinely well formed
// rather than a stub payload.
func buildInnerSYN(src, dst net.IP, sport, dport uint16) []byte {
	const tcpLen = 20
	pkt := make([]byte, 40+tcpLen)

	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], tcpLen)
	pkt[6] = 6  // next header: TCP
	pkt[7] = 64 // hop limit
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())

	tcp := pkt[40:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 0x13572468) // seq
	tcp[12] = 5 << 4                                 // data offset 5 words
	tcp[13] = 0x02                                   // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)    // window

	// RFC 2460 pseudo-header: src, dst, upper-layer length, next header.
	ph := make([]byte, 40, 40+len(tcp))
	copy(ph[0:16], src.To16())
	copy(ph[16:32], dst.To16())
	binary.BigEndian.PutUint32(ph[32:36], tcpLen)
	ph[39] = 6
	binary.BigEndian.PutUint16(tcp[16:18], checksum(append(ph, tcp...)))
	return pkt
}

// checksum is the standard 16-bit one's-complement sum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ---------------------------------------------------------------------
// filters
// ---------------------------------------------------------------------

// filters lists the clsact ingress filter chain on an interface, in the order
// the kernel evaluates it.
//
// A correct program with correct maps still does nothing if it never runs. It
// attaches direct-action at a fixed priority to the same hook a cluster CNI
// uses, and returns TC_ACT_UNSPEC on every fail-open path so a filter at a
// later priority still sees the packet. That reasoning holds only while it sits
// earlier in the chain and is still present: in direct-action mode an earlier
// filter returning TC_ACT_OK ends the chain, and a filter installed at the same
// priority by another agent replaces rather than stacks.
func filters(cfg config, _ derived) error {
	if cfg.iface == "" {
		return errors.New("-iface is required for filters")
	}
	link, err := netlink.LinkByName(cfg.iface)
	if err != nil {
		return fmt.Errorf("look up %s: %w", cfg.iface, err)
	}

	for _, hook := range []struct {
		name   string
		handle uint32
	}{
		{"ingress", netlink.HANDLE_MIN_INGRESS},
		{"egress", netlink.HANDLE_MIN_EGRESS},
	} {
		fl, ferr := netlink.FilterList(link, hook.handle)
		fmt.Printf("=== %s %s filters ===\n", cfg.iface, hook.name)
		if ferr != nil {
			fmt.Printf("  ERROR: %v\n", ferr)
			continue
		}
		if len(fl) == 0 {
			fmt.Printf("  (none)\n")
			continue
		}
		sort.SliceStable(fl, func(i, j int) bool {
			return fl[i].Attrs().Priority < fl[j].Attrs().Priority
		})
		for _, f := range fl {
			a := f.Attrs()
			desc := f.Type()
			if bf, ok := f.(*netlink.BpfFilter); ok {
				da := ""
				if bf.DirectAction {
					da = " direct-action"
				}
				desc = fmt.Sprintf("bpf%s name=%q id=%d", da, bf.Name, bf.Id)
			}
			fmt.Printf("  pref/prio %-6d handle %#x  %s\n", a.Priority, a.Handle, desc)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// verify-maps
// ---------------------------------------------------------------------

// verifyMaps checks the assumption every other action rests on: that the maps
// reachable through bpffs pins are the same kernel objects the attached program
// reads.
//
// They can diverge. Loading pins each map and reuses an existing pin as-is, but
// a schema-incompatible reload replaces the program's maps, and anything still
// holding, or newly opening, the old pin then reads and writes an orphan no
// attached program consults. The symptom is what it looks like from outside:
// registrations that appear to succeed, a program demonstrably attached and
// receiving packets, and counters that never move.
func verifyMaps(cfg config, _ derived) error {
	if cfg.progID == 0 {
		return errors.New("-prog-id is required (take it from the filters output)")
	}
	attached, err := ebpf.NewProgramFromID(ebpf.ProgramID(cfg.progID))
	if err != nil {
		return fmt.Errorf("open program id %d: %w", cfg.progID, err)
	}
	defer func() { _ = attached.Close() }()

	info, err := attached.Info()
	if err != nil {
		return fmt.Errorf("program info: %w", err)
	}
	progMaps, ok := info.MapIDs()
	if !ok {
		return errors.New("kernel did not report this program's map ids")
	}
	inUse := make(map[ebpf.MapID]bool, len(progMaps))
	for _, id := range progMaps {
		inUse[id] = true
	}

	name, _ := info.Name, info.Type
	fmt.Printf("=== attached program ===\n")
	fmt.Printf("  id=%d name=%q maps=%v\n\n", cfg.progID, name, progMaps)

	fmt.Printf("=== pinned maps under %s ===\n", cfg.pinDir)
	mismatch := false
	for _, mapName := range []string{"locator_table", "function_table", "vrf_table", "drop_reasons"} {
		m, merr := ebpf.LoadPinnedMap(filepath.Join(cfg.pinDir, mapName), nil)
		if merr != nil {
			fmt.Printf("  %-15s ERROR: %v\n", mapName, merr)
			continue
		}
		mi, ierr := m.Info()
		if ierr != nil {
			fmt.Printf("  %-15s ERROR: %v\n", mapName, ierr)
			_ = m.Close()
			continue
		}
		id, _ := mi.ID()
		verdict := "ORPHANED -- the attached program does not use this map"
		if inUse[id] {
			verdict = "in use by the attached program"
		} else {
			mismatch = true
		}
		fmt.Printf("  %-15s id=%-5d %s\n", mapName, id, verdict)
		_ = m.Close()
	}
	if mismatch {
		fmt.Printf("\n  At least one pinned map is not the one the program reads: every\n")
		fmt.Printf("  registration written through that pin is invisible to the datapath.\n")
	}
	return nil
}

// ---------------------------------------------------------------------
// attach-iface / detach-iface
// ---------------------------------------------------------------------

// attachIface attaches an already-loaded usid_ingress, by program id from the
// filters output, to an additional interface, through the same path production
// uses.
//
// It exists to test one failure: interface resolution picks the interfaces
// carrying the IPv6 default route and then skips WireGuard links, because a
// mesh can install a default route of its own and this node's source address
// would then be a mesh address unreachable off-node. On a cluster where that
// same WireGuard interface carries inter-node traffic, including the BGP
// sessions and every encapsulated packet, the skip removes the only interface
// the datapath needed.
func attachIface(cfg config, _ derived) error {
	if cfg.progID == 0 || cfg.iface == "" {
		return errors.New("-prog-id and -iface are both required")
	}
	attached, err := ebpf.NewProgramFromID(ebpf.ProgramID(cfg.progID))
	if err != nil {
		return fmt.Errorf("open program id %d: %w", cfg.progID, err)
	}
	defer func() { _ = attached.Close() }()

	if err := attach.Attach(attached, []string{cfg.iface}); err != nil {
		return fmt.Errorf("attach program %d to %s: %w", cfg.progID, cfg.iface, err)
	}
	fmt.Printf("attached program %d to %s ingress\n", cfg.progID, cfg.iface)
	return nil
}

// detachIface removes what attachIface added.
func detachIface(cfg config, _ derived) error {
	if cfg.iface == "" {
		return errors.New("-iface is required")
	}
	if err := attach.Detach([]string{cfg.iface}); err != nil {
		return fmt.Errorf("detach %s: %w", cfg.iface, err)
	}
	fmt.Printf("detached from %s\n", cfg.iface)
	return nil
}
