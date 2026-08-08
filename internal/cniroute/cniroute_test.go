// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
)

func TestMain(m *testing.M) {
	InitCNIConfig()
	os.Exit(m.Run())
}

const (
	testVPC           = "abc"
	testAttachment    = "def"
	testContainerID   = "test-container"
	testInvalidBase62 = "abc-def"
	testMac           = "aa:bb:cc:dd:ee:ff"
	testIfName        = "eth0"

	// testPrevResult is a valid CNI v1.0.0 result used in prevResult tests.
	testPrevResult = `{"cniVersion":"1.0.0",` +
		`"interfaces":[{"name":"` + testIfName + `","mac":"` + testMac + `",` +
		`"sandbox":"/proc/1/ns/net"}],` +
		`"ips":[{"version":"6","address":"fd00:1::1/64"}]}`
)

// confJSON builds a minimal galactic-route CNI config document for tests.
func confJSON(vpc, vpcAttachment, prevResult string) string {
	prevResultField := ""
	if prevResult != "" {
		prevResultField = `,"prevResult":` + prevResult
	}
	return fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-route",`+
			`"vpc":%q,"vpcattachment":%q%s}`,
		vpc, vpcAttachment, prevResultField,
	)
}

// assertCNIError verifies that err is a *types.Error with the expected Code
// and that its Msg contains wantMsg (substring match). Pass wantMsg == "" to
// skip the message check.
func assertCNIError(t *testing.T, err error, wantCode uint, wantMsg string) {
	t.Helper()
	var cniErr *types.Error
	if !errors.As(err, &cniErr) {
		t.Fatalf("expected *types.Error, got %T: %v", err, err)
	}
	if cniErr.Code != wantCode {
		t.Fatalf("expected code %d, got %d (Msg: %q)", wantCode, cniErr.Code, cniErr.Msg)
	}
	if wantMsg != "" && !strings.Contains(cniErr.Msg, wantMsg) {
		t.Fatalf("expected Msg to contain %q, got %q", wantMsg, cniErr.Msg)
	}
}

// ---- parseConf -------------------------------------------------------------

func TestParseConfInvalidJSON(t *testing.T) {
	_, err := parseConf([]byte("not valid json"))
	assertCNIError(t, err, 7, errInvalidCNIConfig)
}

func TestParseConfMissingVPC(t *testing.T) {
	_, err := parseConf([]byte(confJSON("", testAttachment, "")))
	assertCNIError(t, err, 7, errVPCRequired)
}

func TestParseConfInvalidVPC(t *testing.T) {
	_, err := parseConf([]byte(confJSON(testInvalidBase62, testAttachment, "")))
	assertCNIError(t, err, 7, "invalid base62 value for field 'vpc'")
}

func TestParseConfMissingVPCAttachment(t *testing.T) {
	_, err := parseConf([]byte(confJSON(testVPC, "", "")))
	assertCNIError(t, err, 7, errVPCAttachmentRequired)
}

func TestParseConfInvalidVPCAttachment(t *testing.T) {
	_, err := parseConf([]byte(confJSON(testVPC, testInvalidBase62, "")))
	assertCNIError(t, err, 7, "invalid base62 value for field 'vpcattachment'")
}

func TestParseConfValid(t *testing.T) {
	conf, err := parseConf([]byte(confJSON(testVPC, testAttachment, "")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.VPC != testVPC || conf.VPCAttachment != testAttachment {
		t.Errorf("got vpc=%q vpcAttachment=%q, want %q/%q", conf.VPC, conf.VPCAttachment, testVPC, testAttachment)
	}
}

func TestParseConfWithTerminations(t *testing.T) {
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-route",`+
			`"vpc":%q,"vpcattachment":%q,`+
			`"terminations":[{"network":"fd00:2::/64","via":"fd00:1::1"}]}`,
		testVPC, testAttachment,
	)
	parsed, err := parseConf([]byte(conf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parsed.Terminations) != 1 {
		t.Fatalf("got %d terminations, want 1", len(parsed.Terminations))
	}
	if parsed.Terminations[0].Network != "fd00:2::/64" || parsed.Terminations[0].Via != "fd00:1::1" {
		t.Errorf("got termination %+v, want network=fd00:2::/64 via=fd00:1::1", parsed.Terminations[0])
	}
}

func TestParseConfPrevResultNeverValidatedAtParseTime(t *testing.T) {
	// types.PluginConf.PrevResult has json tag "-" and is never populated by
	// plain json.Unmarshal (a pre-existing quirk of that library — see
	// internal/cnibgp/prevresult.go's own doc comment). parseConf's
	// validatePrevResult check therefore never fires here regardless of
	// what "prevResult" contains; cmdAdd's own parsePrevResult (reading
	// RawPrevResult instead) is what actually validates prevResult content.
	conf, err := parseConf([]byte(confJSON(testVPC, testAttachment, `{"cniVersion":"garbage"}`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.PrevResult != nil {
		t.Error("PrevResult should remain nil after plain json.Unmarshal (see RawPrevResult instead)")
	}
	if conf.RawPrevResult == nil {
		t.Error("RawPrevResult should be populated")
	}
}

// ---- isValidBase62 ---------------------------------------------------------

func TestIsValidBase62(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"valid alnum", "aB3", true},
		{"hyphen", "abc-def", false},
		{"unicode", "abc€", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidBase62(tt.in); got != tt.want {
				t.Errorf("isValidBase62(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// ---- sanitizeForError -------------------------------------------------------

func TestSanitizeForError(t *testing.T) {
	if got := sanitizeForError("printable-value"); got != "printable-value" {
		t.Errorf("got %q, want unchanged", got)
	}
	if got := sanitizeForError("bad\x00value"); got != sanitizeForErrorBinary {
		t.Errorf("got %q, want %q", got, sanitizeForErrorBinary)
	}
}

// ---- parseStatusConf --------------------------------------------------------

func TestParseStatusConfInvalidJSON(t *testing.T) {
	err := parseStatusConf([]byte("not valid json"))
	assertCNIError(t, err, 7, errInvalidCNIConfig)
}

func TestParseStatusConfMissingCNIVersion(t *testing.T) {
	err := parseStatusConf([]byte(`{"type":"galactic-route"}`))
	assertCNIError(t, err, 7, "cniVersion is required")
}

func TestParseStatusConfMissingType(t *testing.T) {
	err := parseStatusConf([]byte(`{"cniVersion":"1.0.0"}`))
	assertCNIError(t, err, 7, "type is required")
}

func TestParseStatusConfValid(t *testing.T) {
	if err := parseStatusConf([]byte(`{"cniVersion":"1.0.0","type":"galactic-route"}`)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---- cmdAdd -----------------------------------------------------------------

func TestCmdAddInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte("not valid json")}
	err := cmdAdd(args)
	assertCNIError(t, err, 7, errInvalidCNIConfig)
}

func TestCmdAddNoPrevResult(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(confJSON(testVPC, testAttachment, "")),
	}
	err := cmdAdd(args)
	assertCNIError(t, err, 6, "must be chained after a master plugin")
}

func TestCmdAddInvalidPrevResult(t *testing.T) {
	// A prevResult that unmarshals but isn't a parseable versioned CNI
	// result. Caught by cmdAdd's own parsePrevResult, reading RawPrevResult
	// — parseConf's validatePrevResult(conf.PrevResult) never sees this at
	// all, since that field is never populated (see
	// TestParseConfPrevResultNeverValidatedAtParseTime).
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(confJSON(testVPC, testAttachment, `{"cniVersion":"garbage"}`)),
	}
	err := cmdAdd(args)
	assertCNIError(t, err, 6, "parse prevResult")
}

func TestCmdAddNoTerminationsPassesThroughPrevResult(t *testing.T) {
	// With no terminations to install, cmdAdd never touches route.Add at
	// all — it should succeed and simply echo prevResult back.
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(confJSON(testVPC, testAttachment, testPrevResult)),
	}
	if err := cmdAdd(args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- parsePrevResult --------------------------------------------------------

func TestParsePrevResultNil(t *testing.T) {
	_, err := parsePrevResult(nil)
	if err == nil {
		t.Fatal("expected error for nil prevResult")
	}
}

func TestParsePrevResultValid(t *testing.T) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(testPrevResult), &raw); err != nil {
		t.Fatalf("unmarshal test fixture: %v", err)
	}
	result, err := parsePrevResult(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ---- cmdDel -----------------------------------------------------------------

func TestCmdDelIdempotent(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(confJSON(testVPC, testAttachment, "")),
	}
	if err := cmdDel(args); err != nil {
		t.Errorf("cmdDel should never return an error, got: %v", err)
	}
}

func TestCmdDelIdempotentInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte("not valid json")}
	if err := cmdDel(args); err != nil {
		t.Errorf("cmdDel should never return an error even for unparseable config, got: %v", err)
	}
}

// ---- cmdCheck ---------------------------------------------------------------

func TestCmdCheckInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte("not valid json")}
	err := cmdCheck(args)
	assertCNIError(t, err, 7, errInvalidCNIConfig)
}

func TestCmdCheckMissingRoute(t *testing.T) {
	// The VRF this termination's route should live in doesn't exist on the
	// test host, so checkTerminationRoutes fails at the vrf.TableID lookup —
	// the same "missing resources" shape internal/cni's own CHECK tests use.
	conf := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-route",`+
			`"vpc":%q,"vpcattachment":%q,`+
			`"terminations":[{"network":"fd00:2::/64","via":"fd00:1::1"}]}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}
	if err := cmdCheck(args); err == nil {
		t.Fatal("expected error for missing VRF/route state")
	}
}

func TestCmdCheckNoTerminationsStillRequiresVRF(t *testing.T) {
	// checkTerminationRoutes resolves the VRF table ID up front, before
	// its per-termination loop — with zero terminations to check, an
	// absent VRF still surfaces as an error rather than being skipped, the
	// same order the original code (internal/cni/ops_check.go, before this
	// split) already used.
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(confJSON(testVPC, testAttachment, "")),
	}
	if err := cmdCheck(args); err == nil {
		t.Fatal("expected error: VRF for this vpc/vpcAttachment does not exist on the test host")
	}
}

// ---- checkTerminationRoutes -------------------------------------------------

func TestCheckTerminationRoutesInvalidGateway(t *testing.T) {
	err := checkTerminationRoutes(testVPC, testAttachment, []Termination{{Network: "fd00:2::/64", Via: "not-an-ip"}})
	if err == nil {
		t.Fatal("expected error for invalid gateway")
	}
}

func TestCheckTerminationRoutesRequiresVRFEvenWithNone(t *testing.T) {
	// vrf.TableID resolves before the (empty) per-termination loop runs, so
	// a missing VRF still surfaces as an error here too.
	if err := checkTerminationRoutes(testVPC, testAttachment, nil); err == nil {
		t.Fatal("expected error: VRF for this vpc/vpcAttachment does not exist on the test host")
	}
}

// ---- cmdStatus --------------------------------------------------------------

func TestCmdStatusInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{StdinData: []byte("not valid json")}
	err := cmdStatus(args)
	assertCNIError(t, err, 7, errInvalidCNIConfig)
}

func TestCmdStatusReady(t *testing.T) {
	args := &skel.CmdArgs{StdinData: []byte(`{"cniVersion":"1.0.0","type":"galactic-route"}`)}
	if err := cmdStatus(args); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---- resourceTracker --------------------------------------------------------

func TestResourceTrackerCleanupZeroValue(t *testing.T) {
	tracker := &resourceTracker{}
	tracker.cleanup() // should not panic; empty added slice, nothing to delete
}

func TestResourceTrackerCleanupUnaddedRoute(t *testing.T) {
	// A route that was never actually added (e.g. route.Add failed before
	// tracker.added recorded it) should never be attempted here — this
	// tracker only ever unwinds what it itself recorded as added.
	tracker := &resourceTracker{vpc: testVPC, vpcAttachment: testAttachment, dev: testIfName}
	tracker.cleanup() // no entries in added; should not panic or attempt anything
}
