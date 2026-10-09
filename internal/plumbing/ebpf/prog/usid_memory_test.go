// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/loadcaps"
)

// galacticCNIProcessAllowance is the memory galactic-cni's run daemon needs
// besides its eBPF maps: the Go runtime, its clients and caches, and the
// verifier's work while it loads the programs.
const galacticCNIProcessAllowance = 40 << 20

// TestUsid_MapMemoryFitsGalacticCNILimit checks that the container creating
// the datapath's maps can afford them. The kernel charges map memory to the
// creating process's memory cgroup, so a node creating its maps for the first
// time fails with ENOMEM once they outgrow the container's limit (#808). A
// node reusing pinned maps does not, which hides the failure until a new node
// joins or an upgrade adds a map.
func TestUsid_MapMemoryFitsGalacticCNILimit(t *testing.T) {
	requireRoot(t)

	manifest := filepath.Join("..", "..", "..", "..", "config", "galactic-cni", "daemonset.yaml")
	limit, err := loadcaps.ContainerMemoryLimit(manifest, "credential-refresh")
	if err != nil {
		t.Fatal(err)
	}

	spec, err := LoadUsid()
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	var maps int64
	for name, m := range coll.Maps {
		n, err := mapMemlock(m)
		if err != nil {
			t.Fatalf("map %s: %v", name, err)
		}
		maps += n
	}

	need := maps + galacticCNIProcessAllowance
	t.Logf("maps allocate %d MiB; with the process allowance the container needs %d MiB; its limit is %d MiB",
		maps>>20, need>>20, limit>>20)
	if need > limit {
		t.Errorf("galactic-cni's credential-refresh container needs %d MiB "+
			"(%d MiB of eBPF maps plus %d MiB for the process), but %s limits it to %d MiB; raise the limit",
			need>>20, maps>>20, galacticCNIProcessAllowance>>20, manifest, limit>>20)
	}
}

// mapMemlock returns the size the kernel reports for m in its fdinfo. That
// is the kernel's estimate of the map, not the memory cgroup's charge.
func mapMemlock(m *ebpf.Map) (int64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		v, ok := strings.CutPrefix(s.Text(), "memlock:")
		if ok {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("no memlock in fdinfo")
}
