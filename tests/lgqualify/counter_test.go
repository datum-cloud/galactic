// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// chain is the iptables chain, jumped to first from OUTPUT in every dfw
// node's network namespace, whose rules count ICMP echo requests (ping and
// traceroute probes alike) sent toward each watched destination.
const chain = "LG-QUALIFY"

// sampleEvery is the counter's sampling period: the precision of every
// "packets stopped by" measurement.
const sampleEvery = 200 * time.Millisecond

// sample is the cumulative packet count per destination, summed over the
// dfw nodes and per node, at one moment.
type sample struct {
	At      time.Time                   `json:"at"`
	Count   map[string]int64            `json:"count"`
	PerNode map[string]map[string]int64 `json:"perNode"`
}

// counter samples the chain's counters on every router.
type counter struct {
	mu      sync.Mutex
	samples []sample
	stop    chan struct{}
	done    chan struct{}
}

func iptablesFor(dst string) (string, string) {
	if netip.MustParseAddr(dst).Is4() {
		return iptables, "-p icmp --icmp-type echo-request"
	}
	return ip6tables, "-p ipv6-icmp --icmpv6-type echo-request"
}

// installChain creates the chain and its OUTPUT jump on every router,
// replacing any left by an earlier run.
func installChain() error {
	for _, node := range routers {
		for _, ipt := range []string{iptables, ip6tables} {
			script := fmt.Sprintf(`%[1]s -w -D OUTPUT -j %[2]s 2>/dev/null
%[1]s -w -F %[2]s 2>/dev/null
%[1]s -w -X %[2]s 2>/dev/null
%[1]s -w -N %[2]s && %[1]s -w -I OUTPUT 1 -j %[2]s`, ipt, chain)
			if _, err := nodeExec(node, "sh", "-c", script); err != nil {
				return err
			}
		}
	}
	return nil
}

// removeChain removes the chain and its jump from every router.
func removeChain() error {
	var errs []string
	for _, node := range routers {
		for _, ipt := range []string{iptables, ip6tables} {
			script := fmt.Sprintf(`%[1]s -w -D OUTPUT -j %[2]s; %[1]s -w -F %[2]s; %[1]s -w -X %[2]s`, ipt, chain)
			if _, err := nodeExec(node, "sh", "-c", script); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("remove %s: %s", chain, strings.Join(errs, "; "))
	}
	return nil
}

// watch adds counting rules for dsts on every router.
func watch(dsts ...string) error {
	for _, node := range routers {
		for _, dst := range dsts {
			ipt, match := iptablesFor(dst)
			script := fmt.Sprintf("%[1]s -w -C %[2]s -d %[3]s %[4]s 2>/dev/null || %[1]s -w -A %[2]s -d %[3]s %[4]s",
				ipt, chain, dst, match)
			if _, err := nodeExec(node, "sh", "-c", script); err != nil {
				return err
			}
		}
	}
	return nil
}

// readCounts returns the cumulative echo requests per destination, summed
// over the routers and per router.
func readCounts() (map[string]int64, map[string]map[string]int64, error) {
	type res struct {
		out string
		err error
	}
	results := make([]res, len(routers))
	var wg sync.WaitGroup
	for i, node := range routers {
		wg.Go(func() {
			out, err := nodeExec(node, "sh", "-c", fmt.Sprintf("iptables -w -nvx -L %[1]s; ip6tables -w -nvx -L %[1]s", chain))
			results[i] = res{out, err}
		})
	}
	wg.Wait()
	total := map[string]int64{}
	perNode := map[string]map[string]int64{}
	for i, r := range results {
		if r.err != nil {
			return nil, nil, r.err
		}
		perNode[routers[i]] = map[string]int64{}
		for line := range strings.SplitSeq(r.out, "\n") {
			f := strings.Fields(line)
			// pkts bytes target prot opt in out source destination ...; the
			// IPv6 listing omits opt, so take the field that parses as an
			// address after the source.
			if len(f) < 8 {
				continue
			}
			pkts, err := strconv.ParseInt(f[0], 10, 64)
			if err != nil {
				continue
			}
			var addrs []string
			for _, x := range f[2:] {
				if a, err := netip.ParsePrefix(x); err == nil {
					addrs = append(addrs, a.Addr().String())
				} else if a, err := netip.ParseAddr(x); err == nil {
					addrs = append(addrs, a.String())
				}
			}
			if len(addrs) < 2 {
				continue
			}
			total[addrs[1]] += pkts
			perNode[routers[i]][addrs[1]] += pkts
		}
	}
	return total, perNode, nil
}

// startCounter samples every sampleEvery until stopped.
func startCounter() *counter {
	c := &counter{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		t := time.NewTicker(sampleEvery)
		defer t.Stop()
		for {
			if counts, perNode, err := readCounts(); err == nil {
				c.mu.Lock()
				c.samples = append(c.samples, sample{At: time.Now(), Count: counts, PerNode: perNode})
				c.mu.Unlock()
			}
			select {
			case <-c.stop:
				return
			case <-t.C:
			}
		}
	}()
	return c
}

// close stops sampling and returns every sample.
func (c *counter) close() []sample {
	close(c.stop)
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.samples
}

// lastIncrease returns the time of the first sample at which dst's count
// reached its final value, i.e. when its packets stopped, and that value.
// The true stop lies within sampleEvery before it.
func lastIncrease(samples []sample, dst string) (time.Time, int64) {
	if len(samples) == 0 {
		return time.Time{}, 0
	}
	final := samples[len(samples)-1].Count[dst]
	for _, s := range samples {
		if s.Count[dst] == final {
			return s.At, final
		}
	}
	return time.Time{}, final
}

// between returns dst's packets counted between from and to.
func between(samples []sample, dst string, from, to time.Time) int64 {
	var first, last int64
	for _, s := range samples {
		if s.At.After(to) {
			break
		}
		if s.At.Before(from) {
			first = s.Count[dst]
		}
		last = s.Count[dst]
	}
	return max(0, last-first)
}

// nodeTotal returns node's final count toward dst.
func nodeTotal(samples []sample, node, dst string) int64 {
	if len(samples) == 0 {
		return 0
	}
	return samples[len(samples)-1].PerNode[node][dst]
}

// worstWindow checks every window of the series for dsts' summed counts
// against B + r(T + 32) and returns the window with the largest count
// minus its bound (positive is a violation).
func worstWindow(
	samples []sample, dsts []string, burst, rate float64,
) (excess float64, from, to time.Time, count int64) {
	excess = -1e18
	sum := func(s sample) int64 {
		var n int64
		for _, d := range dsts {
			n += s.Count[d]
		}
		return n
	}
	for i := range samples {
		for j := i + 1; j < len(samples); j++ {
			// Packets counted in (samples[i].At, samples[j].At], an interval
			// no longer than the samples' spacing plus one sampling period.
			n := sum(samples[j]) - sum(samples[i])
			T := samples[j].At.Sub(samples[i].At).Seconds() + sampleEvery.Seconds()
			if e := float64(n) - (burst + rate*(T+32)); e > excess {
				excess, from, to, count = e, samples[i].At, samples[j].At, n
			}
		}
	}
	return excess, from, to, count
}
