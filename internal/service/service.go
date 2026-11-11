// Package service owns scan execution for the UI, the API and Auto Run. It
// guarantees at most one scan at a time, persists every finished (or
// partial) scan to history, and runs the scheduler independently of any
// browser being open.
package service

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/analyze"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/store"
)

// Limits that keep a run bounded.
const (
	DefaultMaxRun = 10 * time.Minute
	maxEvents     = 5000
)

// ErrBusy is returned when a scan is requested while another is running.
var ErrBusy = errors.New("a scan is already in progress")

// Runner executes one scan. The default runs the probe engine and analyzer;
// tests substitute a fake.
type Runner func(ctx context.Context, cfg probe.Config, emit func(probe.Event)) *model.Report

// Event is a progress or state notification streamed to clients.
type Event struct {
	probe.Event
	Scan     *ScanInfo     `json:"scan,omitempty"`
	Entry    *store.Entry  `json:"entry,omitempty"`
	Schedule *ScheduleView `json:"schedule,omitempty"`
	Errors   []string      `json:"errors,omitempty"`
}

// ScanInfo describes the running (or last) scan.
type ScanInfo struct {
	Trigger   string    `json:"trigger"`
	StartedAt time.Time `json:"started_at"`
	Mode      string    `json:"mode"`
	LowData   bool      `json:"low_data"`
	Progress  float64   `json:"progress"`
	Phase     string    `json:"phase,omitempty"`
}

// Options configures a Service.
type Options struct {
	Store    *store.Store
	Defaults probe.Config
	Tool     model.ToolInfo
	Vantage  func(*model.Report) // annotates reports with where they were measured from (optional)
	Runner   Runner              // nil: real engine
	MaxRun   time.Duration
	Logf     func(format string, a ...any)

	// Scheduler timing. Minute is the length of one schedule "minute"
	// (time.Minute in production; tests shrink it). StartupDelay is how long
	// after start a single overdue scheduled scan runs. Tick bounds how long
	// the scheduler sleeps before re-checking the wall clock, so suspend/resume
	// and clock changes are noticed.
	Minute       time.Duration
	StartupDelay time.Duration
	Tick         time.Duration
	Now          func() time.Time
}

// Service is safe for concurrent use.
type Service struct {
	opt  Options
	st   *store.Store
	base context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup
	wake chan struct{}

	saveMu    sync.Mutex
	mu        sync.Mutex
	cur       *ScanInfo
	cancelRun context.CancelFunc
	userStop  bool
	events    []Event
	subs      map[chan Event]struct{}
	last      *model.Report
	lastEntry *store.Entry
	state     store.ScheduleState
}

// New creates a service. Call Run to start the scheduler and Shutdown to stop.
func New(opt Options) *Service {
	if opt.MaxRun <= 0 {
		opt.MaxRun = DefaultMaxRun
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Minute <= 0 {
		opt.Minute = time.Minute
	}
	if opt.StartupDelay <= 0 {
		opt.StartupDelay = 30 * time.Second
	}
	if opt.Tick <= 0 {
		opt.Tick = 30 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Runner == nil {
		opt.Runner = func(ctx context.Context, cfg probe.Config, emit func(probe.Event)) *model.Report {
			rep := probe.New(cfg, emit).Run(ctx)
			return rep
		}
	}
	base, stop := context.WithCancel(context.Background())
	s := &Service{opt: opt, st: opt.Store, base: base, stop: stop, wake: make(chan struct{}, 1), subs: map[chan Event]struct{}{}}
	s.state = s.st.ScheduleState()
	// Show the most recent stored scan on the dashboard after a restart.
	if list := s.st.History.List(); len(list) > 0 {
		e := list[0]
		s.lastEntry = &e
	}
	return s
}

// Store exposes the underlying store.
func (s *Service) Store() *store.Store { return s.st }

// Defaults returns the base scan configuration.
func (s *Service) Defaults() probe.Config { return s.opt.Defaults }

// Start begins a scan in the background. It returns ErrBusy if one is running.
func (s *Service) Start(trigger string, cfg probe.Config) (ScanInfo, error) {
	s.mu.Lock()
	if s.base.Err() != nil {
		s.mu.Unlock()
		return ScanInfo{}, errors.New("service is shutting down")
	}
	if s.cur != nil {
		s.mu.Unlock()
		return ScanInfo{}, ErrBusy
	}
	info := &ScanInfo{Trigger: trigger, StartedAt: s.opt.Now(), Mode: "full", LowData: cfg.LowData}
	if cfg.Quick {
		info.Mode = "quick"
	}
	runCtx, cancel := context.WithTimeout(s.base, s.opt.MaxRun)
	s.cur = info
	s.cancelRun = cancel
	s.userStop = false
	s.events = nil
	s.wg.Add(1)
	cp := *info
	s.mu.Unlock()

	s.publish(Event{Event: probe.Event{Type: "start", Message: "Scan started (" + trigger + ")"}, Scan: &cp})
	go s.execute(runCtx, cancel, trigger, cfg)
	return cp, nil
}

// Cancel stops the running scan. Partial results are still saved.
func (s *Service) Cancel() bool {
	s.mu.Lock()
	c := s.cancelRun
	if c != nil {
		s.userStop = true
	}
	s.mu.Unlock()
	if c != nil {
		c()
	}
	return c != nil
}

// Current returns the running scan, or nil.
func (s *Service) Current() *ScanInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	cp := *s.cur
	return &cp
}

// Last returns the most recent report produced in this process (nil after a
// restart; use History for older scans) and the newest history entry.
func (s *Service) Last() (*model.Report, *store.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, s.lastEntry
}

func (s *Service) execute(ctx context.Context, cancel context.CancelFunc, trigger string, cfg probe.Config) {
	defer s.wg.Done()
	defer cancel()
	start := s.opt.Now()
	emit := func(ev probe.Event) {
		s.mu.Lock()
		if s.cur != nil && (ev.Type == "phase" || ev.Type == "log") {
			s.cur.Progress = ev.Progress
			if ev.Phase != "" {
				s.cur.Phase = ev.Phase
			}
		}
		s.mu.Unlock()
		if ev.Type == "done" {
			return // the service sends its own done event after saving
		}
		s.publish(Event{Event: ev})
	}
	rep, runErr := s.safeRun(ctx, cfg, emit)
	status, errMsg := store.StatusComplete, ""
	s.mu.Lock()
	userStop := s.userStop
	s.mu.Unlock()
	switch {
	case runErr != nil:
		status, errMsg = store.StatusFailed, runErr.Error()
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		status, errMsg = store.StatusFailed, fmt.Sprintf("timed out after %s; partial results", s.opt.MaxRun)
	case rep != nil && rep.Cancelled && userStop:
		status = store.StatusCancelled
	case rep != nil && rep.Cancelled:
		status, errMsg = store.StatusCancelled, "stopped by shutdown; partial results"
	}

	var entry *store.Entry
	var saveErr error
	if rep != nil {
		e, err := s.st.History.Save(rep, store.SaveMeta{Trigger: trigger, Status: status, Error: errMsg})
		if err != nil {
			saveErr = err
			s.opt.Logf("Could not save scan to history: %v", err)
		} else {
			entry = &e
		}
	}

	finished := s.opt.Now()
	s.mu.Lock()
	st := &s.state
	st.LastRunAt, st.LastFinishedAt = start, finished
	st.LastDuration = finished.Sub(start).Seconds()
	st.LastTrigger = trigger
	st.LastError = errMsg
	switch {
	case status == store.StatusFailed:
		st.LastResult = "failed"
	case status == store.StatusCancelled:
		st.LastResult = "cancelled"
	case rep != nil:
		st.LastResult = rep.Summary.Verdict
	}
	if entry != nil {
		st.LastScanID = entry.ID
	}
	if trigger == store.TriggerScheduled || trigger == store.TriggerRunNow {
		if status == store.StatusFailed {
			st.Failures++
		} else {
			st.Failures = 0
		}
	}
	if rep != nil {
		s.last = rep
	}
	if entry != nil {
		s.lastEntry = entry
	}
	s.cur = nil
	s.cancelRun = nil
	s.mu.Unlock()
	s.persist()

	msg := fmt.Sprintf("Finished in %.1f s", finished.Sub(start).Seconds())
	switch status {
	case store.StatusCancelled:
		msg = "Scan cancelled — partial results saved"
	case store.StatusFailed:
		msg = "Scan failed: " + errMsg
	}
	ev := Event{Event: probe.Event{Type: "done", Progress: 1, Message: msg, Report: rep}, Entry: entry}
	if saveErr != nil {
		ev.Errors = append(ev.Errors, "not saved to history: "+saveErr.Error())
	}
	sv := s.ScheduleView()
	ev.Schedule = &sv
	s.publish(ev)
	if rep != nil {
		s.opt.Logf("Scan finished (%s): %s — %d fail, %d warn, %d info, %d pass", trigger, status, rep.Summary.Fail, rep.Summary.Warn, rep.Summary.Info, rep.Summary.Pass)
	} else {
		s.opt.Logf("Scan finished (%s): %s %s", trigger, status, errMsg)
	}
}

// safeRun executes the runner and analyzer, converting a panic into an error
// so one bad scan cannot take the long-running service down.
func (s *Service) safeRun(ctx context.Context, cfg probe.Config, emit func(probe.Event)) (rep *model.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.opt.Logf("scan panic: %v\n%s", r, debug.Stack())
			rep, err = nil, fmt.Errorf("internal error: %v", r)
		}
	}()
	rep = s.opt.Runner(ctx, cfg, emit)
	if rep == nil {
		return nil, errors.New("scan produced no report")
	}
	rep.Tool = s.opt.Tool
	if s.opt.Vantage != nil {
		s.opt.Vantage(rep)
	}
	analyze.Run(rep)
	return rep, nil
}

func (s *Service) publish(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := ev
	if ev.Type == "done" {
		stored.Report = nil // replayed from s.last
	}
	switch ev.Type {
	case "schedule", "history":
		// state notifications are not part of the scan log
	default:
		if len(s.events) < maxEvents || ev.Type == "done" {
			s.events = append(s.events, stored)
		}
	}
	for ch := range s.subs {
		select {
		case ch <- ev:
		default: // slow client; it catches up from the replay on reconnect
		}
	}
	if ev.Type == "phase" {
		s.opt.Logf("  %s", ev.Message)
	}
}

// Subscribe returns the current scan's events so far (with the report
// attached to a replayed "done"), a live channel, and an unsubscribe func.
func (s *Service) Subscribe() ([]Event, <-chan Event, func()) {
	ch := make(chan Event, 256)
	s.mu.Lock()
	hist := append([]Event(nil), s.events...)
	for i := range hist {
		if hist[i].Type == "done" {
			hist[i].Report = s.last
		}
	}
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return hist, ch, func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}
}

// Notify broadcasts a state change (history edited, schedule changed).
func (s *Service) Notify(kind string) {
	ev := Event{Event: probe.Event{Type: kind}}
	if kind == "schedule" {
		sv := s.ScheduleView()
		ev.Schedule = &sv
	}
	s.publish(ev)
}

// Shutdown cancels a running scan, waits up to timeout for its partial
// results to be saved, and stops the scheduler.
func (s *Service) Shutdown(timeout time.Duration) {
	s.mu.Lock()
	s.stop()
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		s.opt.Logf("Shutdown: scan did not stop within %s", timeout)
	}
}
