package store

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

func rep(t time.Time, verdict string) *model.Report {
	return &model.Report{
		Schema: "sadns/report/v1", StartedAt: t, FinishedAt: t.Add(40 * time.Second), DurationSec: 40,
		System:  &sysinfo.Info{Hostname: "box"},
		Summary: model.Summary{Verdict: verdict, Headline: "h", Warn: 2, Pass: 10, Layers: []model.Layer{{Key: "dns", Status: "pass"}, {Key: "lan", Status: "unknown"}}},
		Options: model.Options{Quick: true},
		Connectivity: model.Connectivity{
			IPv4: model.FamilyConn{Working: true, Probes: []model.Probe{{OK: true}}},
			IPv6: model.FamilyConn{Probes: []model.Probe{{OK: false}}},
		},
		Resolvers: []model.ResolverResult{
			{Role: "public", Addr: "1.1.1.1", Latency: model.Latency{Received: 5, MedianMS: 9}},
			{Role: "system", Primary: true, Addr: "192.168.1.1", Latency: model.Latency{Received: 5, MedianMS: 3.5, LossPct: 0, JitterMS: 0.4}},
		},
		Network: model.NetHealth{Pings: []model.Ping{
			{Label: "Default gateway (IPv4) — LAN / Wi-Fi quality", Sent: 10, Received: 10, AvgMS: 1.2},
			{Label: "Internet (IPv4) — Cloudflare anycast", Sent: 10, Received: 9, AvgMS: 14, LossPct: 10},
		}},
		Web:      []model.WebTiming{{OK: true, Runs: 2, TotalMS: 200}, {OK: true, Runs: 2, TotalMS: 400}, {OK: false, Runs: 2}},
		Findings: []model.Finding{{ID: "A", Severity: model.Warn, Title: "a"}, {ID: "B", Severity: model.Fail, Title: "b"}},
	}
}

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSaveLoadAndMetrics(t *testing.T) {
	s := open(t, t.TempDir())
	now := time.Now().Truncate(time.Second)
	e, err := s.History.Save(rep(now, "degraded"), SaveMeta{Trigger: TriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(e.ID) || e.Trigger != TriggerManual || e.Mode != "quick" || e.Status != StatusComplete || e.Host != "box" {
		t.Fatalf("entry %+v", e)
	}
	m := e.Metrics
	if !m.DNSOK || m.DNSMedianMS != 3.5 || m.DNSResolver != "192.168.1.1" {
		t.Errorf("dns metrics %+v", m)
	}
	if !m.GatewayOK || m.GatewayRTTMS != 1.2 || !m.InternetOK || m.InternetLoss != 10 {
		t.Errorf("ping metrics %+v", m)
	}
	if m.IPv4 != "working" || m.IPv6 != "broken" || m.WebOK != 2 || m.WebFailed != 1 || m.WebAvgMS != 300 {
		t.Errorf("family/web metrics %+v", m)
	}
	if e.Layers["dns"] != "pass" || e.Layers["lan"] != "unknown" {
		t.Errorf("layers %v", e.Layers)
	}
	got, err := s.History.Load(e.ID)
	if err != nil || got.Summary.Verdict != "degraded" || !got.StartedAt.Equal(now) {
		t.Fatalf("load: %v %+v", err, got)
	}
	if _, err := s.History.Load("../../etc/passwd"); err != ErrNotFound {
		t.Errorf("traversal id: %v", err)
	}
	if _, err := s.History.Load("20200101-000000-abcdef"); err != ErrNotFound {
		t.Errorf("unknown id: %v", err)
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "data")
	s := open(t, dir)
	e, _ := s.History.Save(rep(time.Now(), "healthy"), SaveMeta{Trigger: TriggerManual})
	if err := s.WriteSecret("auth.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, filepath.Join(dir, "history"), filepath.Join(dir, "secrets"), filepath.Join(dir, "config")} {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o700 {
			t.Errorf("%s perm %v", p, st.Mode().Perm())
		}
	}
	for _, p := range []string{s.History.reportPath(e.ID), s.History.indexPath(), filepath.Join(dir, "secrets", "auth.json")} {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s perm %v", p, st.Mode().Perm())
		}
	}
}

func TestRetentionPinsAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	set := s.Settings()
	set.Retain = 3
	if err := s.SaveSettings(set); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	var ids []string
	for i := 0; i < 5; i++ {
		e, err := s.History.Save(rep(base.Add(time.Duration(i)*time.Minute), "healthy"), SaveMeta{Trigger: TriggerScheduled})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
		if i == 0 {
			if _, err := s.History.SetPinned(e.ID, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	list := s.History.List()
	if len(list) != 4 {
		t.Fatalf("want 3 unpinned + 1 pinned kept, got %d", len(list))
	}
	// Oldest (pinned) survives and does not count; the oldest unpinned (ids[1]) is gone.
	want := map[string]bool{ids[0]: true, ids[2]: true, ids[3]: true, ids[4]: true}
	for _, e := range list {
		if !want[e.ID] {
			t.Errorf("unexpected survivor %s", e.ID)
		}
	}
	if list[0].ID != ids[4] {
		t.Errorf("not newest-first: %v", list[0].ID)
	}
	for _, id := range ids[1:2] {
		if _, err := os.Stat(s.History.reportPath(id)); !os.IsNotExist(err) {
			t.Errorf("report %s not deleted", id)
		}
	}

	// Restart: everything, including the pin and retention, persists.
	s2 := open(t, dir)
	l2 := s2.History.List()
	if len(l2) != 4 || s2.History.Retain() != 3 {
		t.Fatalf("after reopen: %d entries, retain %d", len(l2), s2.History.Retain())
	}
	pinned := 0
	for _, e := range l2 {
		if e.Pinned {
			pinned++
		}
	}
	if pinned != 1 {
		t.Errorf("pins after reopen: %d", pinned)
	}

	// Clear keeps pinned by default.
	n, err := s2.History.Clear(false)
	if err != nil || n != 3 || len(s2.History.List()) != 1 {
		t.Fatalf("clear: n=%d err=%v left=%d", n, err, len(s2.History.List()))
	}
	if err := s2.History.Delete(ids[0]); err != nil || len(s2.History.List()) != 0 {
		t.Fatalf("delete pinned: %v", err)
	}
	if err := s2.History.Delete(ids[0]); err != ErrNotFound {
		t.Errorf("double delete: %v", err)
	}
}

func TestPinnedDoNotCountAndUnpin(t *testing.T) {
	s := open(t, t.TempDir())
	_ = s.History.SetRetain(1)
	a, _ := s.History.Save(rep(time.Now().Add(-3*time.Minute), "healthy"), SaveMeta{})
	if _, err := s.History.SetPinned(a.ID, true); err != nil {
		t.Fatal(err)
	}
	b, _ := s.History.Save(rep(time.Now().Add(-2*time.Minute), "healthy"), SaveMeta{})
	c, _ := s.History.Save(rep(time.Now(), "healthy"), SaveMeta{})
	// Limit 1 applies to unpinned scans: a (pinned) and c (newest) remain.
	if l := s.History.List(); len(l) != 2 {
		t.Fatalf("got %d", len(l))
	}
	if _, err := s.History.Get(b.ID); err != ErrNotFound {
		t.Error("older unpinned scan should have been removed")
	}
	if _, err := s.History.Get(c.ID); err != nil {
		t.Error("newest scan must never be discarded because of pins")
	}
	// Unpinning applies retention right away: a is now the oldest unpinned.
	if _, err := s.History.SetPinned(a.ID, false); err != ErrNotFound {
		t.Errorf("unpinned over-limit entry should age out: %v", err)
	}
}

func TestRecoveryCorruptIndexOrphansAndTemps(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	e1, _ := s.History.Save(rep(time.Now().Add(-time.Minute), "healthy"), SaveMeta{Trigger: TriggerManual})
	e2, _ := s.History.Save(rep(time.Now(), "degraded"), SaveMeta{Trigger: TriggerManual})
	hdir := filepath.Join(dir, "history")
	// Interrupted write leftovers.
	_ = os.WriteFile(filepath.Join(hdir, ".index.json.tmp-123"), []byte("x"), 0o600)
	// Corrupt index.
	if err := os.WriteFile(filepath.Join(hdir, "index.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := open(t, dir)
	if l := s2.History.List(); len(l) != 2 || l[0].ID != e2.ID {
		t.Fatalf("rebuild: %+v", l)
	}
	if _, err := os.Stat(filepath.Join(hdir, ".index.json.tmp-123")); !os.IsNotExist(err) {
		t.Error("temp file not cleaned")
	}
	m, _ := filepath.Glob(filepath.Join(hdir, "index.json.corrupt-*"))
	if len(m) != 1 {
		t.Errorf("corrupt index not preserved: %v", m)
	}
	// Index row whose report vanished is dropped; orphan report is adopted.
	_ = os.Remove(s2.History.reportPath(e1.ID))
	s3 := open(t, dir)
	if l := s3.History.List(); len(l) != 1 || l[0].ID != e2.ID {
		t.Fatalf("reconcile: %+v", l)
	}
}

func TestNewerIndexVersionRefused(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "history"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "history", "index.json"), []byte(`{"version":99,"entries":[]}`), 0o600)
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("want version error, got %v", err)
	}
}

func TestSettingsDefaultsValidationAndCorruption(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	d := s.Settings()
	if d.Schedule.Enabled || d.Schedule.IntervalMinutes != 60 || d.Schedule.Mode != "quick" || d.Schedule.LowData || d.Retain != 100 {
		t.Fatalf("defaults %+v", d)
	}
	bad := d
	bad.Schedule.IntervalMinutes = 1
	if err := s.SaveSettings(bad); err == nil {
		t.Error("1-minute interval accepted")
	}
	bad = d
	bad.Retain = 0
	if err := s.SaveSettings(bad); err == nil {
		t.Error("retain 0 accepted")
	}
	bad = d
	bad.Scan.IPv4, bad.Scan.IPv6 = false, false
	if err := s.SaveSettings(bad); err == nil {
		t.Error("no families accepted")
	}
	bad = d
	bad.Scan.URLs = []string{"https://x\nInjected: 1"}
	if err := s.SaveSettings(bad); err == nil {
		t.Error("newline in saved URL accepted")
	}
	good := d
	good.Schedule.Enabled, good.Schedule.IntervalMinutes, good.Schedule.Unit = true, 180, "hours"
	if err := s.SaveSettings(good); err != nil {
		t.Fatal(err)
	}
	if got := open(t, dir).Settings(); !got.Schedule.Enabled || got.Schedule.IntervalMinutes != 180 {
		t.Fatalf("persist %+v", got.Schedule)
	}
	_ = os.WriteFile(filepath.Join(dir, "config", "settings.json"), []byte("garbage"), 0o600)
	s2 := open(t, dir)
	if s2.LoadWarning == nil || s2.Settings().Schedule.Enabled {
		t.Fatalf("corrupt settings should fall back to defaults with a warning")
	}
}

func TestDecodeReportValidation(t *testing.T) {
	if _, err := DecodeReport(strings.NewReader(`{"hello":1}`), false); err == nil {
		t.Error("non-report accepted")
	}
	if _, err := DecodeReport(strings.NewReader(`{"schema":"sadns/report/v1"}`), false); err == nil {
		t.Error("report without start time accepted")
	}
	if _, err := DecodeReport(strings.NewReader(`{"schema":"sadns/report/v1","started_at":"2026-01-01T00:00:00Z"}`), false); err != nil {
		t.Error(err)
	}
	// Gzip bomb-ish: > limit after decompression.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"schema":"sadns/report/v1","x":"`))
	_, _ = zw.Write(bytes.Repeat([]byte("a"), maxReportBytes+10))
	_ = zw.Close()
	if _, err := DecodeReport(&buf, true); err == nil {
		t.Error("oversized report accepted")
	}
}

func TestCompare(t *testing.T) {
	ra, rb := rep(time.Now().Add(-time.Hour), "degraded"), rep(time.Now(), "healthy")
	rb.Findings = []model.Finding{{ID: "A", Severity: model.Fail, Title: "a"}, {ID: "C", Severity: model.Warn, Title: "c"}}
	rb.Resolvers[1].Latency.MedianMS = 5.5
	rb.Options.Quick = false
	ea, eb := Summarize(ra), Summarize(rb)
	c := Compare(ea, eb, ra, rb)
	var dns *MetricDelta
	for i := range c.Metrics {
		if c.Metrics[i].Key == "dns_median_ms" {
			dns = &c.Metrics[i]
		}
	}
	if dns == nil || dns.Delta != 2 || dns.Missing {
		t.Fatalf("dns delta %+v", dns)
	}
	kinds := map[string]string{}
	for _, f := range c.Findings {
		kinds[f.ID] = f.Change
	}
	if kinds["A"] != "changed" || kinds["B"] != "resolved" || kinds["C"] != "new" {
		t.Errorf("finding changes %v", kinds)
	}
	if len(c.Notes) == 0 {
		t.Error("expected a depth-mismatch note")
	}
	// Unmeasured metrics are marked missing, not zero deltas.
	rb.Network.Pings = nil
	c = Compare(ea, Summarize(rb), ra, rb)
	for _, m := range c.Metrics {
		if m.Key == "gateway_rtt_ms" && !m.Missing {
			t.Error("gateway metric should be missing")
		}
	}
}

func TestApplyEnv(t *testing.T) {
	set := DefaultSettings()
	env := map[string]string{"SADNS_SCHEDULE_ENABLED": "true", "SADNS_SCHEDULE_INTERVAL": "6h", "SADNS_SCHEDULE_MODE": "Full", "SADNS_SCHEDULE_LOW_DATA": "yes", "SADNS_HISTORY_RETAIN": "250"}
	used, err := ApplyEnv(&set, func(k string) string { return env[k] })
	if err != nil || len(used) != 5 {
		t.Fatalf("%v %v", used, err)
	}
	if !set.Schedule.Enabled || set.Schedule.IntervalMinutes != 360 || set.Schedule.Unit != "hours" || set.Schedule.Mode != "full" || !set.Schedule.LowData || set.Retain != 250 {
		t.Fatalf("%+v", set)
	}
	for k, v := range map[string]string{"SADNS_SCHEDULE_INTERVAL": "2m", "SADNS_SCHEDULE_ENABLED": "maybe", "SADNS_SCHEDULE_MODE": "deep", "SADNS_HISTORY_RETAIN": "0"} {
		s := DefaultSettings()
		if _, err := ApplyEnv(&s, func(x string) string {
			if x == k {
				return v
			}
			return ""
		}); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
	if n, u, err := ParseInterval("1d"); err != nil || n != 1440 || u != "days" {
		t.Error("1d")
	}
	if n, _, err := ParseInterval("45"); err != nil || n != 45 {
		t.Error("45")
	}
}
