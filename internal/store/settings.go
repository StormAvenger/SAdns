package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SettingsVersion is the on-disk version of config/settings.json.
const SettingsVersion = 1

// Interval limits for Auto Run. Five minutes keeps a misconfigured schedule
// from hammering resolvers; 30 days is a practical upper bound.
const (
	MinIntervalMinutes     = 5
	MaxIntervalMinutes     = 30 * 24 * 60
	DefaultIntervalMinutes = 60
)

// ScanPrefs are the user's saved scan choices. Manual runs from the UI send
// their own options; scheduled runs use these.
type ScanPrefs struct {
	Providers   []string `json:"providers,omitempty"`
	NoProviders bool     `json:"no_providers,omitempty"`
	URLs        []string `json:"urls,omitempty"`
	Extra       []string `json:"extra_resolvers,omitempty"`
	Traceroute  bool     `json:"traceroute"`
	Encrypted   bool     `json:"encrypted"`
	IPv4        bool     `json:"ipv4"`
	IPv6        bool     `json:"ipv6"`
	LowData     bool     `json:"low_data"` // manual scans; off by default (Standard / High Data)
}

// Schedule is the Auto Run configuration.
type Schedule struct {
	Enabled         bool   `json:"enabled"`
	Paused          bool   `json:"paused"`
	IntervalMinutes int    `json:"interval_minutes"`
	Unit            string `json:"unit"` // minutes, hours, days — display only
	Mode            string `json:"mode"` // quick, full
	LowData         bool   `json:"low_data"`
	IncludeURLs     bool   `json:"include_custom_urls"`
	IncludeResolver bool   `json:"include_resolver_selection"`
}

// Settings is everything in config/settings.json.
type Settings struct {
	Version  int       `json:"version"`
	Schedule Schedule  `json:"schedule"`
	Retain   int       `json:"history_retain"`
	Scan     ScanPrefs `json:"scan_preferences"`
}

// DefaultSettings: Auto Run off, hourly, Quick, Standard data, keep 100.
func DefaultSettings() Settings {
	return Settings{
		Version: SettingsVersion,
		Schedule: Schedule{IntervalMinutes: DefaultIntervalMinutes, Unit: "minutes", Mode: "quick",
			IncludeURLs: true, IncludeResolver: true},
		Retain: DefaultRetain,
		Scan:   ScanPrefs{Traceroute: true, Encrypted: true, IPv4: true, IPv6: true},
	}
}

// Validate checks and normalises s in place.
func (s *Settings) Validate() error {
	sc := &s.Schedule
	if sc.IntervalMinutes < MinIntervalMinutes || sc.IntervalMinutes > MaxIntervalMinutes {
		return fmt.Errorf("interval must be between %d minutes and %d days", MinIntervalMinutes, MaxIntervalMinutes/1440)
	}
	switch sc.Unit {
	case "minutes", "hours", "days":
	case "":
		sc.Unit = "minutes"
	default:
		return errors.New("unit must be minutes, hours or days")
	}
	switch sc.Mode {
	case "quick", "full":
	case "":
		sc.Mode = "quick"
	default:
		return errors.New("mode must be quick or full")
	}
	if s.Retain < MinRetain || s.Retain > MaxRetain {
		return fmt.Errorf("history retention must be between %d and %d scans", MinRetain, MaxRetain)
	}
	if len(s.Scan.URLs) > 16 || len(s.Scan.Extra) > 16 || len(s.Scan.Providers) > 32 {
		return errors.New("too many saved websites, resolvers or providers (max 16/16/32)")
	}
	for _, list := range [][]string{s.Scan.URLs, s.Scan.Extra, s.Scan.Providers} {
		for _, v := range list {
			if len(v) > 512 || strings.ContainsAny(v, "\r\n\x00") {
				return errors.New("invalid saved value")
			}
		}
	}
	if !s.Scan.IPv4 && !s.Scan.IPv6 {
		return errors.New("at least one of IPv4 and IPv6 must be enabled")
	}
	s.Version = SettingsVersion
	return nil
}

// Interval returns the Auto Run interval.
func (sc Schedule) Interval() time.Duration { return time.Duration(sc.IntervalMinutes) * time.Minute }

// ScheduleState is Auto Run bookkeeping, kept apart from user preferences.
type ScheduleState struct {
	LastRunAt      time.Time `json:"last_run_at,omitempty"`
	LastFinishedAt time.Time `json:"last_finished_at,omitempty"`
	LastDuration   float64   `json:"last_duration_sec,omitempty"`
	LastResult     string    `json:"last_result,omitempty"` // verdict, "cancelled", "failed", "skipped: …"
	LastTrigger    string    `json:"last_trigger,omitempty"`
	LastScanID     string    `json:"last_scan_id,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	NextRunAt      time.Time `json:"next_run_at,omitempty"`
	Skipped        int       `json:"skipped_total"`
	LastSkippedAt  time.Time `json:"last_skipped_at,omitempty"`
	LastSkipReason string    `json:"last_skip_reason,omitempty"`
	MissedAt       time.Time `json:"missed_at,omitempty"` // a run was due while SAdns was not running
	Failures       int       `json:"consecutive_failures"`
}

type configStore struct {
	dir string
	mu  sync.Mutex
}

func (c *configStore) settingsPath() string { return filepath.Join(c.dir, "settings.json") }
func (c *configStore) statePath() string    { return filepath.Join(c.dir, "schedule-state.json") }

func (c *configStore) loadSettings() (Settings, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := DefaultSettings()
	err := readJSON(c.settingsPath(), &s)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultSettings(), nil
	}
	if err != nil {
		// Unreadable settings must not stop the service: fall back to defaults
		// (Auto Run off) and keep the broken file for the user to inspect.
		_ = os.Rename(c.settingsPath(), c.settingsPath()+".corrupt-"+time.Now().UTC().Format("20060102-150405"))
		return DefaultSettings(), fmt.Errorf("settings unreadable, defaults restored: %w", err)
	}
	if s.Version > SettingsVersion {
		return DefaultSettings(), fmt.Errorf("settings version %d is newer than this build supports", s.Version)
	}
	if verr := s.Validate(); verr != nil {
		d := DefaultSettings()
		return d, fmt.Errorf("settings invalid (%v), defaults restored", verr)
	}
	return s, nil
}

func (c *configStore) saveSettings(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeJSONAtomic(c.settingsPath(), s)
}

func (c *configStore) loadState() ScheduleState {
	c.mu.Lock()
	defer c.mu.Unlock()
	var st ScheduleState
	_ = readJSON(c.statePath(), &st)
	return st
}

func (c *configStore) saveState(st ScheduleState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeJSONAtomic(c.statePath(), st)
}
