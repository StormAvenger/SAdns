package store

import (
	"os"
	"path/filepath"
	"runtime"
)

// Store ties together history, settings and the secrets directory under one
// data directory.
type Store struct {
	Dir     string
	History *History
	cfg     *configStore
	// LoadWarning is set when settings could not be read and defaults were used.
	LoadWarning error
}

// Open creates or opens a data directory.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dir, dirPerm) // best effort: a pre-created volume may belong to someone else
	}
	for _, sub := range []string{"config", "history", "secrets"} {
		p := filepath.Join(dir, sub)
		if err := os.MkdirAll(p, dirPerm); err != nil {
			return nil, err
		}
		if runtime.GOOS != "windows" {
			_ = os.Chmod(p, dirPerm) // tighten directories created by older versions or other tools
		}
	}
	cfg := &configStore{dir: filepath.Join(dir, "config")}
	cleanTemps(cfg.dir)
	cleanTemps(filepath.Join(dir, "secrets"))
	set, warn := cfg.loadSettings()
	h, err := openHistory(filepath.Join(dir, "history"), set.Retain)
	if err != nil {
		return nil, err
	}
	return &Store{Dir: dir, History: h, cfg: cfg, LoadWarning: warn}, nil
}

// SecretsDir is where credentials are kept (0700).
func (s *Store) SecretsDir() string { return filepath.Join(s.Dir, "secrets") }

// Settings returns the current settings (defaults if never saved).
func (s *Store) Settings() Settings {
	set, _ := s.cfg.loadSettings()
	return set
}

// SaveSettings validates and persists settings, applying the retention
// count to history immediately.
func (s *Store) SaveSettings(set Settings) error {
	if err := s.cfg.saveSettings(set); err != nil {
		return err
	}
	return s.History.SetRetain(set.Retain)
}

// ScheduleState returns Auto Run bookkeeping.
func (s *Store) ScheduleState() ScheduleState { return s.cfg.loadState() }

// SaveScheduleState persists Auto Run bookkeeping.
func (s *Store) SaveScheduleState(st ScheduleState) error { return s.cfg.saveState(st) }

// WriteSecret atomically writes a 0600 file in the secrets directory.
func (s *Store) WriteSecret(name string, data []byte) error {
	return writeAtomic(filepath.Join(s.SecretsDir(), filepath.Base(name)), data)
}

// ReadSecret reads a file from the secrets directory.
func (s *Store) ReadSecret(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.SecretsDir(), filepath.Base(name)))
}

// DefaultDir is the per-user data directory for desktop use:
// %AppData%\SAdns, ~/Library/Application Support/SAdns, or
// $XDG_CONFIG_HOME/sadns (~/.config/sadns). SADNS_DATA_DIR overrides it.
func DefaultDir() (string, error) {
	if d := os.Getenv("SADNS_DATA_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	name := "sadns"
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		name = "SAdns"
	}
	return filepath.Join(base, name), nil
}
