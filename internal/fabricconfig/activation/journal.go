// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package activation

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RecordType is the stage a journal record marks.
type RecordType string

const (
	// RecordAccepted marks an activation accepted for apply.
	RecordAccepted RecordType = "Accepted"
	// RecordApplied marks a reload that returned without error.
	RecordApplied RecordType = "Applied"
	// RecordApplyFailed marks a reload that failed or timed out.
	RecordApplyFailed RecordType = "ApplyFailed"
	// RecordCommitted marks an activation observed healthy and
	// checkpointed.
	RecordCommitted RecordType = "Committed"
	// RecordRecovered marks a recovery to the recorded target.
	RecordRecovered RecordType = "Recovered"
	// RecordSource marks a change of configuration source.
	RecordSource RecordType = "Source"
	// RecordRebind marks an operator-approved rebind to a new deployment.
	RecordRebind RecordType = "Rebind"
)

// Activation identifies one promotion of one revision on one node.
type Activation struct {
	ClusterID      string `json:"clusterID"`
	NodeUID        string `json:"nodeUID"`
	DeploymentUID  string `json:"deploymentUID"`
	Epoch          int64  `json:"epoch"`
	Revision       string `json:"revision"`
	DependencyHash string `json:"dependencyDigest"`
}

// Recovery is what an activation may fall back to, recorded with it.
type Recovery struct {
	TargetRevision string `json:"targetRevision,omitempty"`
	TargetDigest   string `json:"targetDigest,omitempty"`
	// RevokedPrefixes may not be originated by the target.
	RevokedPrefixes []string `json:"revokedPrefixes,omitempty"`
	// RevokedCredentials are Secret UIDs the target may not use.
	RevokedCredentials []string `json:"revokedCredentials,omitempty"`
	Retired            bool     `json:"retired,omitempty"`
}

// Record is one journal entry.
type Record struct {
	Seq        int64      `json:"seq"`
	Type       RecordType `json:"type"`
	Time       time.Time  `json:"time"`
	Activation Activation `json:"activation"`
	// PreviousGood is the last committed revision when the activation was
	// accepted.
	PreviousGood string    `json:"previousGood,omitempty"`
	Recovery     *Recovery `json:"recovery,omitempty"`
	// Source is the configuration source a Source record switches to.
	Source string `json:"source,omitempty"`
	// Detail explains a failure.
	Detail string `json:"detail,omitempty"`
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrCorrupt reports a damaged journal line before the last one; the agent
// stops accepting activations until an operator rebinds it.
var ErrCorrupt = errors.New("journal is corrupt")

// Journal is an append-only, fsynced log of activation stages. Each line is
// "<crc32c hex> <json>"; a torn final line, from a crash mid-write, is
// dropped on open, while damage anywhere earlier is ErrCorrupt.
type Journal struct {
	path    string
	records []Record
	now     func() time.Time
	// broken is set when a failed append could not be undone; every later
	// append fails with it.
	broken error
}

// OpenJournal reads the journal at path, creating its directory if needed.
func OpenJournal(path string, now func() time.Time) (*Journal, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	j := &Journal{path: path, now: now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(data, []byte("\n"))
	complete := bytes.HasSuffix(data, []byte("\n"))
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		// Only an unterminated final line can be a torn write; a complete
		// line that fails its checksum was damaged after it was written.
		torn := i == len(lines)-1 && !complete
		rec, err := decode(line)
		if err != nil {
			if torn {
				// The stage it records never completed, so drop it and
				// rewrite the file without it.
				if err := j.rewrite(); err != nil {
					return nil, err
				}
				break
			}
			return nil, fmt.Errorf("%w: line %d: %w", ErrCorrupt, i+1, err)
		}
		j.records = append(j.records, rec)
	}
	if len(data) > 0 && !complete {
		// The last record survived but its newline did not: rewrite so
		// the next append starts on a fresh line.
		if err := j.rewrite(); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func decode(line []byte) (Record, error) {
	sum, payload, ok := bytes.Cut(line, []byte(" "))
	if !ok {
		return Record{}, errors.New("no checksum")
	}
	want, err := strconv.ParseUint(string(sum), 16, 32)
	if err != nil {
		return Record{}, fmt.Errorf("checksum: %w", err)
	}
	if crc32.Checksum(payload, crcTable) != uint32(want) {
		return Record{}, errors.New("checksum mismatch")
	}
	var rec Record
	if err := json.Unmarshal(payload, &rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func encode(rec Record) ([]byte, error) {
	payload, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%08x %s\n", crc32.Checksum(payload, crcTable), payload)), nil
}

// Append writes rec, numbered and timed, and fsyncs it before returning. A
// failed append is cut back off the file, so it can never fuse with the
// next record; if that fails too, the journal refuses further appends.
func (j *Journal) Append(rec Record) (Record, error) {
	if j.broken != nil {
		return Record{}, j.broken
	}
	rec.Seq = int64(len(j.records)) + 1
	if last, ok := j.Last(); ok {
		rec.Seq = last.Seq + 1
	}
	rec.Time = j.now().UTC()
	line, err := encode(rec)
	if err != nil {
		return Record{}, err
	}
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Record{}, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return Record{}, err
	}
	if err := writeSynced(f, line); err != nil {
		if terr := f.Truncate(info.Size()); terr != nil {
			j.broken = fmt.Errorf("journal append failed and could not be undone: %w", errors.Join(err, terr))
		} else if serr := f.Sync(); serr != nil {
			j.broken = fmt.Errorf("journal append failed and could not be undone: %w", errors.Join(err, serr))
		}
		_ = f.Close()
		return Record{}, err
	}
	// The record is durable in the file from here, so memory follows it
	// even if what remains fails; a failure then stops further appends.
	j.records = append(j.records, rec)
	if err := f.Close(); err != nil {
		j.broken = fmt.Errorf("journal close failed after a durable append: %w", err)
		return Record{}, err
	}
	if err := syncDir(filepath.Dir(j.path)); err != nil {
		j.broken = fmt.Errorf("journal directory sync failed after a durable append: %w", err)
		return Record{}, err
	}
	return rec, nil
}

func writeSynced(f *os.File, line []byte) error {
	if _, err := f.Write(line); err != nil {
		return err
	}
	return f.Sync()
}

// rewrite replaces the file with the records read so far.
func (j *Journal) rewrite() error {
	var buf bytes.Buffer
	for _, rec := range j.records {
		line, err := encode(rec)
		if err != nil {
			return err
		}
		buf.Write(line)
	}
	return writeAtomic(j.path, buf.Bytes())
}

// Records returns every record, oldest first.
func (j *Journal) Records() []Record { return append([]Record(nil), j.records...) }

// Last returns the newest record.
func (j *Journal) Last() (Record, bool) {
	if len(j.records) == 0 {
		return Record{}, false
	}
	return j.records[len(j.records)-1], true
}

// HighWater is the highest epoch accepted for a deployment UID.
func (j *Journal) HighWater(deploymentUID string) (int64, bool) {
	var high int64
	found := false
	for _, rec := range j.records {
		if rec.Type == RecordAccepted && rec.Activation.DeploymentUID == deploymentUID &&
			(!found || rec.Activation.Epoch > high) {
			high, found = rec.Activation.Epoch, true
		}
	}
	return high, found
}

// LastForEpoch returns the newest record for one deployment UID and epoch.
func (j *Journal) LastForEpoch(deploymentUID string, epoch int64) (Record, bool) {
	for i := len(j.records) - 1; i >= 0; i-- {
		rec := j.records[i]
		if rec.Activation.DeploymentUID == deploymentUID && rec.Activation.Epoch == epoch &&
			rec.Type != RecordSource && rec.Type != RecordRebind {
			return rec, true
		}
	}
	return Record{}, false
}

// Failed reports whether an epoch was ever journaled as failed; a failed
// epoch is never retried.
func (j *Journal) Failed(deploymentUID string, epoch int64) bool {
	for _, rec := range j.records {
		if rec.Activation.DeploymentUID == deploymentUID && rec.Activation.Epoch == epoch &&
			(rec.Type == RecordApplyFailed || rec.Type == RecordRecovered) {
			return true
		}
	}
	return false
}

// Accepted returns the Accepted record of one deployment UID and epoch.
func (j *Journal) Accepted(deploymentUID string, epoch int64) (Record, bool) {
	for _, rec := range j.records {
		if rec.Type == RecordAccepted && rec.Activation.DeploymentUID == deploymentUID && rec.Activation.Epoch == epoch {
			return rec, true
		}
	}
	return Record{}, false
}

// NeedsRecovery reports whether an epoch failed and its recovery never
// finished: its last record is ApplyFailed.
func (j *Journal) NeedsRecovery(deploymentUID string, epoch int64) bool {
	rec, ok := j.LastForEpoch(deploymentUID, epoch)
	return ok && rec.Type == RecordApplyFailed
}

// LatestRecovery is the recovery journaled with the newest accepted
// activation.
func (j *Journal) LatestRecovery() (Recovery, bool) {
	for i := len(j.records) - 1; i >= 0; i-- {
		if rec := j.records[i]; rec.Type == RecordAccepted && rec.Recovery != nil {
			return *rec.Recovery, true
		}
	}
	return Recovery{}, false
}

// EpochStage is one epoch's newest journaled stage.
type EpochStage struct {
	Epoch    int64
	Revision string
	Stage    RecordType
	Recovery *Recovery
	Detail   string
}

// Epochs reports the newest stage of up to n of a deployment's epochs,
// newest first.
func (j *Journal) Epochs(deploymentUID string, n int) []EpochStage {
	var out []EpochStage
	seen := map[int64]int{}
	for i := len(j.records) - 1; i >= 0; i-- {
		rec := j.records[i]
		if rec.Activation.DeploymentUID != deploymentUID || rec.Type == RecordSource || rec.Type == RecordRebind {
			continue
		}
		if k, ok := seen[rec.Activation.Epoch]; ok {
			if out[k].Recovery == nil {
				out[k].Recovery = rec.Recovery
			}
			continue
		}
		if len(out) == n {
			continue
		}
		seen[rec.Activation.Epoch] = len(out)
		out = append(out, EpochStage{
			Epoch: rec.Activation.Epoch, Revision: rec.Activation.Revision, Stage: rec.Type,
			Recovery: rec.Recovery, Detail: rec.Detail,
		})
	}
	slices.SortFunc(out, func(a, b EpochStage) int { return cmp.Compare(b.Epoch, a.Epoch) })
	return out
}

// Rebind binds the journal to deployment to, after an operator confirmed
// that from, the deployment it is bound to, is gone.
func (j *Journal) Rebind(from, to string) error {
	if bound := j.BoundDeployment(); bound != from {
		return fmt.Errorf("%w: journal bound to %q, rebind names %q", ErrRecoveryConflict, bound, from)
	}
	_, err := j.Append(Record{Type: RecordRebind, Activation: Activation{DeploymentUID: to}})
	return err
}

// SetSource journals a change of configuration source.
func (j *Journal) SetSource(source string) error {
	if j.Source() == source {
		return nil
	}
	_, err := j.Append(Record{Type: RecordSource, Source: source})
	return err
}

// BoundDeployment is the deployment UID the journal last accepted for, or
// last rebound to.
func (j *Journal) BoundDeployment() string {
	for i := len(j.records) - 1; i >= 0; i-- {
		rec := j.records[i]
		if rec.Type == RecordAccepted || rec.Type == RecordRebind {
			return rec.Activation.DeploymentUID
		}
	}
	return ""
}

// Source is the configuration source the journal last recorded.
func (j *Journal) Source() string {
	for i := len(j.records) - 1; i >= 0; i-- {
		if j.records[i].Type == RecordSource {
			return j.records[i].Source
		}
	}
	return ""
}

// LatestTime is the newest time any record carries, the agent's guard
// against a clock that moved backwards.
func (j *Journal) LatestTime() time.Time {
	var latest time.Time
	for _, rec := range j.records {
		if rec.Time.After(latest) {
			latest = rec.Time
		}
	}
	return latest
}

func (r RecordType) String() string { return string(r) }

// describe renders a record for an error message.
func (r Record) describe() string {
	return strings.Join([]string{string(r.Type), r.Activation.Revision, strconv.FormatInt(r.Activation.Epoch, 10)}, "/")
}
