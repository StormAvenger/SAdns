// Package store persists SAdns scan history, settings and secrets on the local
// filesystem. It needs no database server and no third-party modules.
//
// Layout (all under one data directory):
//
//	config/settings.json        preferences and schedule configuration
//	config/schedule-state.json  last/next run bookkeeping for Auto Run
//	history/index.json          one summary row per stored scan (versioned)
//	history/reports/<id>.json.gz full report for each scan
//	secrets/                    credentials (owned by the auth layer)
//
// Measurements, preferences and secrets live in separate directories so they
// can be backed up, wiped or permissioned independently. Every write goes to a
// temporary file in the same directory, is fsynced, then atomically renamed
// over the target, so a crash or power loss leaves either the old or the new
// file — never a torn one. Files are created 0600 and directories 0700.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Permissions for everything the store creates. Scan reports contain local
// addresses, hostnames and resolver details, so they are private by default.
const (
	dirPerm  = 0o700
	filePerm = 0o600
)

// writeAtomic replaces path with data. The temporary file lives in the same
// directory so the final rename never crosses filesystems.
func writeAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(filePerm); err != nil && runtime.GOOS != "windows" {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir makes the rename durable. Directory fsync is unsupported on
// Windows (and some filesystems); failure there is not an error.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// writeJSONAtomic marshals v with indentation and writes it atomically.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'))
}

// readJSON loads path into v. A missing file returns os.ErrNotExist.
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// cleanTemps removes temporary files left by an interrupted write.
func cleanTemps(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") && strings.Contains(n, ".tmp-") {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
}

// ErrNotFound is returned for unknown scan IDs.
var ErrNotFound = errors.New("not found")
