package service

import (
	"context"
	"errors"
	"time"

	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/store"
)

// ScheduleView is the Auto Run state shown to clients. It is read-only:
// changes go through UpdateSchedule, Pause, Resume and RunNow.
type ScheduleView struct {
	store.Schedule
	Retain             int                 `json:"history_retain"`
	State              store.ScheduleState `json:"state"`
	Status             string              `json:"status"` // disabled, paused, scheduled, running
	Running            bool                `json:"scan_running"`
	ServerTimezone     string              `json:"server_timezone"`
	MinIntervalMinutes int                 `json:"min_interval_minutes"`
}

// ScheduleView returns the current Auto Run configuration and state.
func (s *Service) ScheduleView() ScheduleView {
	set := s.st.Settings()
	s.mu.Lock()
	st := s.state
	running := s.cur != nil
	s.mu.Unlock()
	v := ScheduleView{Schedule: set.Schedule, Retain: set.Retain, State: st, Running: running, MinIntervalMinutes: store.MinIntervalMinutes}
	v.ServerTimezone = time.Local.String()
	if v.ServerTimezone == "Local" || v.ServerTimezone == "" {
		v.ServerTimezone, _ = time.Now().Zone()
	}
	switch {
	case !set.Schedule.Enabled:
		v.Status = "disabled"
		v.State.NextRunAt = time.Time{}
	case set.Schedule.Paused:
		v.Status = "paused"
		v.State.NextRunAt = time.Time{}
	default:
		v.Status = "scheduled"
	}
	if running {
		v.Status = "running"
	}
	return v
}

func (s *Service) interval(sc store.Schedule) time.Duration {
	return time.Duration(sc.IntervalMinutes) * s.opt.Minute
}

func (s *Service) setNext(t time.Time) {
	s.mu.Lock()
	s.state.NextRunAt = t
	s.mu.Unlock()
	s.persist()
}

// persist writes the schedule state. saveMu orders snapshot+write pairs so
// an older snapshot can never overwrite a newer one.
func (s *Service) persist() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	if err := s.st.SaveScheduleState(st); err != nil {
		s.opt.Logf("Could not save schedule state: %v", err)
	}
}

func (s *Service) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// UpdateSchedule validates and stores a new Auto Run configuration. Changing
// it restarts the countdown from now.
func (s *Service) UpdateSchedule(sc store.Schedule, retain int) (ScheduleView, error) {
	set := s.st.Settings()
	set.Schedule = sc
	if retain > 0 {
		set.Retain = retain
	}
	if err := s.st.SaveSettings(set); err != nil {
		return ScheduleView{}, err
	}
	s.resetNext(set.Schedule)
	s.poke()
	s.Notify("schedule")
	return s.ScheduleView(), nil
}

func (s *Service) resetNext(sc store.Schedule) {
	if sc.Enabled && !sc.Paused {
		s.setNext(s.opt.Now().Add(s.interval(sc)))
	} else {
		s.setNext(time.Time{})
	}
}

// Pause keeps Auto Run configured but stops it from firing.
func (s *Service) Pause() (ScheduleView, error) { return s.setPaused(true) }

// Resume restarts the countdown from now.
func (s *Service) Resume() (ScheduleView, error) { return s.setPaused(false) }

func (s *Service) setPaused(p bool) (ScheduleView, error) {
	set := s.st.Settings()
	if !set.Schedule.Enabled {
		return ScheduleView{}, errors.New("auto run is disabled")
	}
	set.Schedule.Paused = p
	if err := s.st.SaveSettings(set); err != nil {
		return ScheduleView{}, err
	}
	s.resetNext(set.Schedule)
	s.poke()
	s.Notify("schedule")
	return s.ScheduleView(), nil
}

// RunNow starts a scan with the Auto Run settings immediately. It does not
// move the next scheduled time.
func (s *Service) RunNow() (ScanInfo, error) {
	return s.Start(store.TriggerRunNow, s.ScheduledConfig())
}

// ScheduledConfig builds the scan configuration Auto Run uses: the service
// defaults, the schedule's depth and data mode, and — when the schedule says
// so — the saved website and resolver selections.
func (s *Service) ScheduledConfig() probe.Config {
	set := s.st.Settings()
	cfg := s.opt.Defaults
	cfg.Quick = set.Schedule.Mode == "quick"
	if cfg.Quick && cfg.Samples > 3 {
		cfg.Samples = 3
	}
	cfg.LowData = set.Schedule.LowData
	p := set.Scan
	cfg.Traceroute, cfg.Encrypted, cfg.IPv4, cfg.IPv6 = p.Traceroute, p.Encrypted, p.IPv4, p.IPv6
	cfg.URLs = nil
	if set.Schedule.IncludeURLs {
		for _, u := range p.URLs {
			if n, err := probe.NormalizeURL(u); err == nil {
				cfg.URLs = append(cfg.URLs, n)
			}
		}
	}
	if set.Schedule.IncludeResolver {
		cfg.Providers, cfg.NoProviders = p.Providers, p.NoProviders
		cfg.Extra = append([]string(nil), p.Extra...)
	}
	return cfg
}

// initNext decides the first fire time after start. A run that came due
// while SAdns was stopped runs once, shortly after start — never one per
// missed interval.
func (s *Service) initNext() {
	sc := s.st.Settings().Schedule
	now := s.opt.Now()
	s.mu.Lock()
	next := s.state.NextRunAt
	s.mu.Unlock()
	switch {
	case !sc.Enabled || sc.Paused:
		s.setNext(time.Time{})
	case next.IsZero():
		s.setNext(now.Add(s.interval(sc)))
	case !next.After(now):
		s.mu.Lock()
		s.state.MissedAt = next
		s.mu.Unlock()
		s.setNext(now.Add(s.opt.StartupDelay))
		s.opt.Logf("Auto Run: a scheduled scan was missed while SAdns was stopped; running one catch-up scan in %s", s.opt.StartupDelay)
	case next.After(now.Add(s.interval(sc))):
		s.setNext(now.Add(s.interval(sc))) // interval was shortened
	}
}

// Run drives Auto Run until ctx is cancelled or the service shuts down.
func (s *Service) Run(ctx context.Context) {
	s.initNext()
	for {
		s.mu.Lock()
		next := s.state.NextRunAt
		s.mu.Unlock()
		wait := s.opt.Tick
		if !next.IsZero() {
			if d := next.Sub(s.opt.Now()); d < wait {
				wait = d
			}
		}
		if wait < 0 {
			wait = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.base.Done():
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
			continue
		case <-t.C:
		}
		s.mu.Lock()
		next = s.state.NextRunAt
		s.mu.Unlock()
		if next.IsZero() || s.opt.Now().Before(next) {
			continue
		}
		s.fire()
	}
}

func (s *Service) fire() {
	sc := s.st.Settings().Schedule
	if !sc.Enabled || sc.Paused {
		s.setNext(time.Time{})
		return
	}
	now := s.opt.Now()
	// Next time is anchored to this slot so a slow scan does not drift the
	// schedule; if the slot is already past, count from now.
	s.mu.Lock()
	slot := s.state.NextRunAt
	s.mu.Unlock()
	next := slot.Add(s.interval(sc))
	if !next.After(now) {
		next = now.Add(s.interval(sc))
	}
	// Record the next slot before starting, so a crash mid-scan does not
	// re-run this slot on restart.
	s.setNext(next)
	_, err := s.Start(store.TriggerScheduled, s.ScheduledConfig())
	if err != nil {
		reason := err.Error()
		if errors.Is(err, ErrBusy) {
			reason = "another scan was already running"
		}
		s.mu.Lock()
		s.state.Skipped++
		s.state.LastSkippedAt = now
		s.state.LastSkipReason = reason
		s.mu.Unlock()
		s.opt.Logf("Auto Run: skipped (%s)", reason)
		s.persist()
	}
	s.Notify("schedule")
}
