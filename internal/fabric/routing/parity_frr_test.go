// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build frr

package routing_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// gateScript loads each original configuration into the pinned FRR's
// daemons and asks frr-reload.py what turning the configuration FRR then
// displays into the compiled one would change. That is the first
// activation's diff, so it must be empty.
const gateScript = `#!/bin/sh
# For every <name>.conf in /orig: load it into fresh daemons, capture the
# running configuration FRR displays, and ask frr-reload.py what turning it
# into /out/<name>.conf would change. Any line to add or delete fails.
sed -i 's/^bgpd=no/bgpd=yes/; s/^staticd=no/staticd=yes/' /etc/frr/daemons
sed -i 's/^bgpd_options="\(.*\)"/bgpd_options="\1 -M bmp"/' /etc/frr/daemons
touch /etc/frr/vtysh.conf
status=0
for f in /orig/*.conf; do
  n=$(basename "$f")
  /usr/lib/frr/frrinit.sh stop >/dev/null 2>&1
  cp "$f" /etc/frr/frr.conf
  /usr/lib/frr/frrinit.sh start >/tmp/init.log 2>&1 || { echo "START-FAIL $n"; tail -20 /tmp/init.log; status=1; continue; }
  i=0; until vtysh -c "show running-config" >/tmp/running.conf 2>/dev/null && grep -q "^router bgp" /tmp/running.conf; do
    i=$((i+1)); [ $i -gt 20 ] && break; sleep 0.5
  done
  # The container's own hostname shows up here, not the node's.
  sed -i '1,/^Current configuration:/d; /^frr version /d; /^hostname /d' /tmp/running.conf
  out=$(python3 /usr/lib/frr/frr-reload.py --test --input /tmp/running.conf "/out/$n" 2>&1) || { echo "ERROR $n"; echo "$out"; status=1; continue; }
  delta=$(printf '%s\n' "$out" | sed -n '/^Lines To \(Delete\|Add\)/,$p' | grep -vE '^(Lines To (Delete|Add)|=+)?$' | grep -v '^hostname ')
  if [ -n "$delta" ]; then echo "DIFF $n"; printf '%s\n' "$delta"; status=1; else echo "SAME $n"; fi
done
exit $status
`

// TestImportCompileParityFRR: for every configuration, the compiled form
// changes nothing in what the pinned FRR runs after loading the original.
// It needs Docker and runs with -tags frr.
func TestImportCompileParityFRR(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	files := parityFiles(t)
	work := t.TempDir()
	origDir, outDir := filepath.Join(work, "orig"), filepath.Join(work, "out")
	for _, d := range []string{origDir, outDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		original, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		res := compileFile(t, f.path, string(original))
		if err := os.WriteFile(filepath.Join(origDir, f.key+".conf"), original, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outDir, f.key+".conf"), []byte(res.Config), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(work, "gate.sh")
	if err := os.WriteFile(script, []byte(gateScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("docker", "run", "--rm", "--privileged",
		"-v", origDir+":/orig:ro", "-v", outDir+":/out:ro", "-v", script+":/gate.sh:ro",
		"--entrypoint", "/gate.sh", frrImage(t))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if same := strings.Count(out.String(), "SAME "); err != nil || same != len(files) {
		t.Fatalf("%d of %d configurations unchanged by activation (err %v):\n%s",
			same, len(files), err, strings.TrimSpace(out.String()))
	}
}

// frrImage is the FRR build fabric-router runs, read from its Dockerfile.
func frrImage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "containers", "fabric-router", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ARG FRR_VERSION=(\S+)$`).FindSubmatch(data)
	if m == nil {
		t.Fatal("containers/fabric-router/Dockerfile has no ARG FRR_VERSION")
	}
	return "quay.io/frrouting/frr:" + string(m[1])
}
