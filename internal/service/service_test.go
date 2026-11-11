package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/store"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

// fake is a controllable scan runner.
type fake struct {
	mu     sync.Mutex
	calls  int32
	block  chan struct{} // if non-nil, scans wait for it (or ctx)
	panic  bool
	cfgs   []probe.Config
	starts []time.Time
}

func (f *fake) run(ctx context.Context, cfg probe.Config, emit func(probe.Event)) *model.Report {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	f.cfgs = append(f.cfgs, cfg)
	f.starts = append(f.starts, time.Now())
	blk, pn := f.block, f.panic
	f.mu.Unlock()
	if pn {
		panic("boom")
	}
	emit(probe.Event{Type: "phase", Phase: "dns", Message: "testing", Progress: 0.5})
	r := &model.Report{Schema: "sadns/report/v1", StartedAt: time.Now(), System: &sysinfo.Info{Hostname: "t"},
		Options: model.Options{Quick: cfg.Quick, LowData: cfg.LowData}}
	if blk != nil {
		select {
		case <-blk:
		case <-ctx.Done():
			r.Cancelled = true
		}
	}
	r.FinishedAt = time.Now()
	return r
}

func (f *fake) n() int { return int(atomic.LoadInt32(&f.calls)) }

func newSvc(t *testing.T, dir string, f *fake, mod func(*Options)) *Service {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Store: st, Defaults: probe.DefaultConfig(), Runner: f.run,
		Minute: 20 * time.Millisecond, StartupDelay: 40 * time.Millisecond, Tick: 5 * time.Millisecond}
	if mod != nil {
		mod(&o)
	}
	s := New(o)
	t.Cleanup(func() { s.Shutdown(2 * time.Second) })
	return s
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func idle(s *Service) func() bool { return func() bool { return s.Current() == nil } }

func TestManualScanSavedWithTriggerAndEvents(t *testing.T) {
	f := &fake{}
	s := newSvc(t, t.TempDir(), f, nil)
	hist, ch, unsub := s.Subscribe()
	defer unsub()
	if len(hist) != 0 {
		t.Fatalf("history before any scan: %d", len(hist))
	}
	if _, err := s.Start(store.TriggerManual, probe.Config{Quick: true}); err != nil {
		t.Fatal(err)
	}
	var sawStart, sawPhase bool
	var done Event
	timeout := time.After(3 * time.Second)
loop:
	for {
		select {
		case ev := <-ch:
			switch ev.Type {
			case "start":
				sawStart = ev.Scan != nil && ev.Scan.Trigger == store.TriggerManual && ev.Scan.Mode == "quick"
			case "phase":
				sawPhase = true
			case "done":
				done = ev
				break loop
			}
		case <-timeout:
			t.Fatal("no done event")
		}
	}
	if !sawStart || !sawPhase {
		t.Errorf("start=%v phase=%v", sawStart, sawPhase)
	}
	if done.Report == nil || done.Entry == nil || done.Entry.Trigger != store.TriggerManual || done.Entry.Status != store.StatusComplete {
		t.Fatalf("done event %+v", done)
	}
	// Late subscriber gets a replay including the report.
	h2, _, u2 := s.Subscribe()
	defer u2()
	if len(h2) == 0 || h2[len(h2)-1].Type != "done" || h2[len(h2)-1].Report == nil {
		t.Fatalf("replay %+v", h2)
	}
	if l := s.Store().History.List(); len(l) != 1 {
		t.Fatalf("history %d", len(l))
	}
	st := s.ScheduleView().State
	if st.LastTrigger != store.TriggerManual || st.LastScanID == "" || st.LastFinishedAt.IsZero() {
		t.Errorf("state %+v", st)
	}
}

func TestNoOverlapAndCancelSavesPartial(t *testing.T) {
	f := &fake{block: make(chan struct{})}
	s := newSvc(t, t.TempDir(), f, nil)
	if _, err := s.Start(store.TriggerManual, probe.Config{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "scan running", time.Second, func() bool { return f.n() == 1 })
	if _, err := s.Start(store.TriggerManual, probe.Config{}); err != ErrBusy {
		t.Fatalf("second scan: %v", err)
	}
	if _, err := s.RunNow(); err != ErrBusy {
		t.Fatalf("run-now during scan: %v", err)
	}
	if !s.Cancel() {
		t.Fatal("cancel reported nothing running")
	}
	waitFor(t, "idle", 2*time.Second, idle(s))
	l := s.Store().History.List()
	if len(l) != 1 || l[0].Status != store.StatusCancelled {
		t.Fatalf("partial not saved as cancelled: %+v", l)
	}
	if s.Cancel() {
		t.Error("cancel with nothing running returned true")
	}
	if f.n() != 1 {
		t.Errorf("runner called %d times", f.n())
	}
}

func TestPanicRecoveryAndTimeout(t *testing.T) {
	f := &fake{panic: true}
	s := newSvc(t, t.TempDir(), f, func(o *Options) { o.MaxRun = 50 * time.Millisecond })
	if _, err := s.Start(store.TriggerManual, probe.Config{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle after panic", 2*time.Second, idle(s))
	st := s.ScheduleView().State
	if st.LastResult != "failed" || st.LastError == "" {
		t.Fatalf("panic not recorded: %+v", st)
	}
	// The service keeps working; a scan that exceeds MaxRun is saved as failed/partial.
	f.mu.Lock()
	f.panic = false
	f.block = make(chan struct{})
	f.mu.Unlock()
	if _, err := s.Start(store.TriggerManual, probe.Config{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle after timeout", 2*time.Second, idle(s))
	l := s.Store().History.List()
	if len(l) != 1 || l[0].Status != store.StatusFailed || l[0].Error == "" {
		t.Fatalf("timeout entry %+v", l)
	}
}

func enable(t *testing.T, s *Service, minutes int, mode string) {
	t.Helper()
	sc := s.Store().Settings().Schedule
	sc.Enabled, sc.IntervalMinutes, sc.Mode = true, minutes, mode
	if _, err := s.UpdateSchedule(sc, 0); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerFiresAtShortIntervals(t *testing.T) {
	f := &fake{}
	s := newSvc(t, t.TempDir(), f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	enable(t, s, 5, "full") // 5 "minutes" = 100 ms here
	waitFor(t, "3 scheduled scans", 3*time.Second, func() bool { return len(s.Store().History.List()) >= 3 })
	cancel()
	for _, e := range s.Store().History.List() {
		if e.Trigger != store.TriggerScheduled || e.Mode != "full" {
			t.Errorf("entry %+v", e)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 1; i < len(f.starts); i++ {
		if gap := f.starts[i].Sub(f.starts[i-1]); gap < 80*time.Millisecond {
			t.Errorf("scans %d and %d only %v apart", i-1, i, gap)
		}
	}
	v := s.ScheduleView()
	if v.State.NextRunAt.IsZero() || v.Status == "disabled" {
		t.Errorf("view %+v", v)
	}
}

func TestScheduledRunSkippedDuringManualScan(t *testing.T) {
	f := &fake{block: make(chan struct{})}
	s := newSvc(t, t.TempDir(), f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	if _, err := s.Start(store.TriggerManual, probe.Config{}); err != nil {
		t.Fatal(err)
	}
	enable(t, s, 5, "quick")
	waitFor(t, "a skipped run", 2*time.Second, func() bool { return s.ScheduleView().State.Skipped >= 1 })
	close(f.block)
	waitFor(t, "idle", time.Second, idle(s))
	st := s.ScheduleView().State
	if st.LastSkipReason == "" || st.LastSkippedAt.IsZero() {
		t.Errorf("skip not recorded: %+v", st)
	}
	// The schedule keeps going after the manual scan ends.
	waitFor(t, "scheduled scan after manual", 2*time.Second, func() bool {
		for _, e := range s.Store().History.List() {
			if e.Trigger == store.TriggerScheduled {
				return true
			}
		}
		return false
	})
}

func TestPauseResumeAndDisable(t *testing.T) {
	f := &fake{}
	s := newSvc(t, t.TempDir(), f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	if _, err := s.Pause(); err == nil {
		t.Error("pause while disabled should fail")
	}
	enable(t, s, 5, "quick")
	if v, err := s.Pause(); err != nil || v.Status != "paused" || !v.State.NextRunAt.IsZero() {
		t.Fatalf("pause: %v %+v", err, v)
	}
	n := f.n()
	time.Sleep(300 * time.Millisecond)
	if f.n() != n {
		t.Fatalf("scans ran while paused: %d → %d", n, f.n())
	}
	if v, err := s.Resume(); err != nil || v.Status != "scheduled" {
		t.Fatalf("resume: %v %+v", err, v)
	}
	waitFor(t, "scan after resume", 2*time.Second, func() bool { return f.n() > n })
	sc := s.Store().Settings().Schedule
	sc.Enabled = false
	if v, _ := s.UpdateSchedule(sc, 0); v.Status != "disabled" && v.Status != "running" {
		t.Fatalf("disable: %+v", v)
	}
	waitFor(t, "idle", time.Second, idle(s))
	n = f.n()
	time.Sleep(300 * time.Millisecond)
	if f.n() != n {
		t.Fatal("scans ran while disabled")
	}
}

func TestRunNowUsesScheduleSettings(t *testing.T) {
	f := &fake{}
	s := newSvc(t, t.TempDir(), f, nil)
	set := s.Store().Settings()
	set.Schedule.Mode, set.Schedule.LowData = "full", true
	set.Schedule.IncludeURLs, set.Schedule.IncludeResolver = false, true
	set.Scan.URLs = []string{"example.com"}
	set.Scan.Extra = []string{"9.9.9.9"}
	set.Scan.IPv6 = false
	if err := s.Store().SaveSettings(set); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunNow(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", 2*time.Second, idle(s))
	f.mu.Lock()
	cfg := f.cfgs[0]
	f.mu.Unlock()
	if cfg.Quick || !cfg.LowData || len(cfg.URLs) != 0 || len(cfg.Extra) != 1 || cfg.IPv6 {
		t.Fatalf("config %+v", cfg)
	}
	if e := s.Store().History.List()[0]; e.Trigger != store.TriggerRunNow || e.DataMode != "low-data" {
		t.Errorf("entry %+v", e)
	}
}

// A restart must not replay every interval that elapsed while stopped: one
// catch-up scan, then the normal cadence.
func TestRestartRunsOneCatchUpOnly(t *testing.T) {
	dir := t.TempDir()
	f := &fake{}
	s1 := newSvc(t, dir, f, nil)
	sc := s1.Store().Settings().Schedule
	sc.Enabled, sc.IntervalMinutes = true, 500 // 10 s in test time: will not fire during the test
	if _, err := s1.UpdateSchedule(sc, 0); err != nil {
		t.Fatal(err)
	}
	s1.Shutdown(time.Second)
	// Simulate a long downtime: the stored next-run is far in the past
	// (100 intervals missed).
	st, _ := store.Open(dir)
	state := st.ScheduleState()
	state.NextRunAt = time.Now().Add(-100 * 10 * time.Second)
	_ = st.SaveScheduleState(state)

	f2 := &fake{}
	s2 := newSvc(t, dir, f2, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s2.Run(ctx)
	waitFor(t, "catch-up scan", 2*time.Second, func() bool { return f2.n() >= 1 })
	time.Sleep(300 * time.Millisecond)
	if n := f2.n(); n != 1 {
		t.Fatalf("expected exactly 1 catch-up scan, got %d", n)
	}
	v := s2.ScheduleView()
	if v.State.MissedAt.IsZero() {
		t.Error("missed run not recorded")
	}
	if until := time.Until(v.State.NextRunAt); until < 8*time.Second {
		t.Errorf("next run should be ~one interval away, is %v", until)
	}
}

// A future next-run survives a restart unchanged (no reset, no early fire).
func TestRestartKeepsFutureNextRun(t *testing.T) {
	dir := t.TempDir()
	s1 := newSvc(t, dir, &fake{}, nil)
	sc := s1.Store().Settings().Schedule
	sc.Enabled, sc.IntervalMinutes = true, 500
	_, _ = s1.UpdateSchedule(sc, 0)
	want := s1.ScheduleView().State.NextRunAt
	s1.Shutdown(time.Second)

	f := &fake{}
	s2 := newSvc(t, dir, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s2.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	if got := s2.ScheduleView().State.NextRunAt; !got.Equal(want) {
		t.Errorf("next run changed across restart: %v → %v", want, got)
	}
	if f.n() != 0 {
		t.Error("scan fired early after restart")
	}
}

func TestShutdownDuringScanSavesPartial(t *testing.T) {
	dir := t.TempDir()
	f := &fake{block: make(chan struct{})}
	s := newSvc(t, dir, f, nil)
	if _, err := s.Start(store.TriggerScheduled, probe.Config{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", time.Second, func() bool { return f.n() == 1 })
	s.Shutdown(2 * time.Second)
	if _, err := s.Start(store.TriggerManual, probe.Config{}); err == nil {
		t.Error("scan accepted after shutdown")
	}
	st, _ := store.Open(dir)
	l := st.History.List()
	if len(l) != 1 || l[0].Status != store.StatusCancelled || l[0].Error == "" {
		t.Fatalf("partial on shutdown: %+v", l)
	}
}

func TestHistoryVisibleAfterRestart(t *testing.T) {
	dir := t.TempDir()
	s1 := newSvc(t, dir, &fake{}, nil)
	_, _ = s1.Start(store.TriggerManual, probe.Config{})
	waitFor(t, "idle", time.Second, idle(s1))
	s1.Shutdown(time.Second)
	s2 := newSvc(t, dir, &fake{}, nil)
	if _, e := s2.Last(); e == nil {
		t.Fatal("last scan not visible after restart")
	}
}
