// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const fileMode = 0o644

// candidateName is the file a new frr.conf is staged in, inside the
// configuration directory, while it is validated and applied.
const candidateName = ".frr.conf.candidate"

// writeFile atomically replaces dir/name with contents: it writes a temporary
// file in dir and renames it over the target, so a reader never sees a
// partially written file.
func writeFile(dir, name, contents string) error {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", name, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.WriteString(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename %s into place: %w", name, err)
	}
	return nil
}

// readFile returns dir/name's contents, or an empty string with no error when
// it does not exist.
func readFile(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	return string(b), nil
}

// seedDefaults copies every regular file in defaultsDir into dir, skipping
// names in skip. A missing defaultsDir is not an error.
func seedDefaults(defaultsDir, dir string, skip map[string]string) error {
	entries, err := os.ReadDir(defaultsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read defaults directory %s: %w", defaultsDir, err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if _, overridden := skip[e.Name()]; overridden {
			continue
		}
		contents, err := readFile(defaultsDir, e.Name())
		if err != nil {
			return err
		}
		if err := writeFile(dir, e.Name(), contents); err != nil {
			return err
		}
	}
	return nil
}
