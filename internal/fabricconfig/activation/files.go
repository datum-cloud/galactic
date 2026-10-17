// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package activation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// writeAtomic replaces path with data: a temporary file is written and
// fsynced, renamed over path, and the directory fsynced, so a crash leaves
// either the old file or the new one.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		cleanup()
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Identity binds the state directory to one machine, Node and cluster. A
// copied directory, or a replacement node reusing a name, fails the check
// and takes the bootstrap path instead of trusting the checkpoint.
type Identity struct {
	NodeUID   string `json:"nodeUID"`
	MachineID string `json:"machineID"`
	ClusterID string `json:"clusterID"`
	Nonce     string `json:"nonce"`
}

// ErrIdentityMismatch reports state from another machine, Node or cluster.
var ErrIdentityMismatch = errors.New("state directory belongs to another node")

// BindIdentity returns the identity recorded in dir, writing it from want
// (with a fresh nonce) the first time. An empty NodeUID or ClusterID in
// want, as when the API is unreachable, matches anything; the machine ID
// always has to match.
func BindIdentity(dir string, want Identity) (Identity, error) {
	path := filepath.Join(dir, "identity.json")
	if want.MachineID == "" {
		return Identity{}, fmt.Errorf("%w: no machine ID", ErrIdentityMismatch)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if want.NodeUID == "" || want.ClusterID == "" {
			return Identity{}, fmt.Errorf("%w: no identity recorded and none known", ErrIdentityMismatch)
		}
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return Identity{}, err
		}
		want.Nonce = hex.EncodeToString(nonce)
		out, err := json.Marshal(want)
		if err != nil {
			return Identity{}, err
		}
		return want, writeAtomic(path, out)
	}
	if err != nil {
		return Identity{}, err
	}
	var got Identity
	if err := json.Unmarshal(data, &got); err != nil {
		return Identity{}, fmt.Errorf("%w: unreadable identity: %w", ErrIdentityMismatch, err)
	}
	switch {
	case got.MachineID != want.MachineID:
		return got, fmt.Errorf("%w: machine %s, recorded %s", ErrIdentityMismatch, want.MachineID, got.MachineID)
	case want.NodeUID != "" && got.NodeUID != want.NodeUID:
		return got, fmt.Errorf("%w: Node %s, recorded %s", ErrIdentityMismatch, want.NodeUID, got.NodeUID)
	case want.ClusterID != "" && got.ClusterID != want.ClusterID:
		return got, fmt.Errorf("%w: cluster %s, recorded %s", ErrIdentityMismatch, want.ClusterID, got.ClusterID)
	}
	return got, nil
}

// readIdentity reads the identity recorded in dir.
func readIdentity(dir string) (Identity, error) {
	data, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrIdentityMismatch, err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return Identity{}, fmt.Errorf("%w: unreadable identity: %w", ErrIdentityMismatch, err)
	}
	return id, nil
}

// ReadMachineID reads a machine ID file such as /etc/machine-id.
func ReadMachineID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return id, nil
}

// Checkpoint is the last committed activation, enough to restore it at
// boot without the API.
type Checkpoint struct {
	Activation   Activation `json:"activation"`
	Config       string     `json:"config"`
	ConfigDigest string     `json:"configDigest"`
	Recovery     *Recovery  `json:"recovery,omitempty"`
	// Nonce is the state directory's identity nonce, so a checkpoint
	// copied into another state directory does not restore.
	Nonce string `json:"nonce"`
	// Originates and CredentialUIDs let boot refuse a checkpoint that a
	// later recovery revoked.
	Originates          []string  `json:"originates,omitempty"`
	CredentialUIDs      []string  `json:"credentialUIDs,omitempty"`
	SemanticsVersion    string    `json:"semanticsVersion"`
	FRRVersion          string    `json:"frrVersion"`
	BootAuthorizedUntil time.Time `json:"bootAuthorizedUntil"`
	// RequiresAPI marks a configuration with credentials that cannot be
	// restored offline.
	RequiresAPI bool `json:"requiresAPI,omitempty"`
	// Sum is the SHA-256 over every other field.
	Sum string `json:"sum"`
}

// ErrCheckpointInvalid reports a missing field or a sum that does not
// match.
var ErrCheckpointInvalid = errors.New("checkpoint is invalid")

func (c Checkpoint) sum() (string, error) {
	c.Sum = ""
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:]), nil
}

// WriteCheckpoint stores c atomically in dir.
func WriteCheckpoint(dir string, c Checkpoint) error {
	sum, err := c.sum()
	if err != nil {
		return err
	}
	c.Sum = sum
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "checkpoint.json"), data)
}

// ReadCheckpoint loads and verifies the checkpoint in dir. It returns
// os.ErrNotExist when there is none.
func ReadCheckpoint(dir string) (Checkpoint, error) {
	data, err := os.ReadFile(filepath.Join(dir, "checkpoint.json"))
	if err != nil {
		return Checkpoint{}, err
	}
	var c Checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %w", ErrCheckpointInvalid, err)
	}
	want, err := c.sum()
	if err != nil {
		return Checkpoint{}, err
	}
	if c.Sum != want {
		return Checkpoint{}, fmt.Errorf("%w: sum %s, content %s", ErrCheckpointInvalid, c.Sum, want)
	}
	cfg := sha256.Sum256([]byte(c.Config))
	if hex.EncodeToString(cfg[:]) != c.ConfigDigest {
		return Checkpoint{}, fmt.Errorf("%w: configuration digest", ErrCheckpointInvalid)
	}
	return c, nil
}
