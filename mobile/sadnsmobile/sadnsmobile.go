// Package sadnsmobile is a small, gomobile-compatible binding of the SAdns
// engine for a future Android (or iOS) client. It exposes only types gomobile
// can bind (string, bool, int, error and simple interfaces) and exchanges
// everything else as JSON in the same schema as the HTTP API, so a Kotlin app
// and the web UI share one contract (docs/schema/report.schema.json).
//
// Build an Android library (not done in CI; see docs/ANDROID.md):
//
//	gomobile bind -target=android -androidapi 24 ./mobile/sadnsmobile
//
// The engine runs entirely on the device: quick scans work offline-first with
// no server. Platform data Go cannot read on Android (Wi-Fi details, the
// active network's DNS servers) is supplied by the app via SetSystemDNS.
package sadnsmobile

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/report"
	"github.com/StormAvenger/SAdns/internal/service"
	"github.com/StormAvenger/SAdns/internal/store"
)

// SchemaVersion is the report schema this binding produces.
const SchemaVersion = "sadns/report/v1"

// APIVersion matches the HTTP API's /api/v1/info api_version.
const APIVersion = 1

// EventListener receives scan events as JSON (same shape as /api/v1/events).
type EventListener interface {
	OnEvent(eventJSON string)
}

// Scanner owns a history store and runs one scan at a time.
type Scanner struct {
	svc   *service.Service
	extra []string
}

// NewScanner opens (or creates) history in dataDir, e.g. the app's
// Context.getFilesDir().
func NewScanner(dataDir string, version string) (*Scanner, error) {
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, err
	}
	cfg := probe.DefaultConfig()
	cfg.Traceroute = false // no traceroute binary on stock Android
	svc := service.New(service.Options{Store: st, Defaults: cfg,
		Tool:    model.ToolInfo{Name: "SAdns", Version: version, Repo: "https://github.com/StormAvenger/SAdns"},
		Vantage: func(r *model.Report) { r.Vantage = model.Vantage{Mode: "mobile", Detection: "mobile binding"} }})
	return &Scanner{svc: svc}, nil
}

// DefaultRequestJSON is a quick, Low-Data-off request suitable for a first scan.
func DefaultRequestJSON() string {
	b, _ := json.Marshal(service.ScanRequest{Quick: true, Encrypted: true, IPv4: true, IPv6: true})
	return string(b)
}

// SetSystemDNS records the active network's DNS servers as reported by
// Android's LinkProperties.getDnsServers(), comma-separated. They are tested
// as extra resolvers, because Go cannot read them on Android.
func (s *Scanner) SetSystemDNS(csv string) {
	s.extra = nil
	for _, a := range strings.Split(csv, ",") {
		if a = strings.TrimSpace(a); a != "" {
			s.extra = append(s.extra, a)
		}
	}
}

// Start begins a scan described by requestJSON (service.ScanRequest).
// Events are delivered to l on a background goroutine.
func (s *Scanner) Start(requestJSON string, l EventListener) error {
	var req service.ScanRequest
	dec := json.NewDecoder(strings.NewReader(requestJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return errors.New("invalid request: " + err.Error())
	}
	req.Extra = append(req.Extra, s.extra...)
	var (
		ch    <-chan service.Event
		unsub = func() {}
	)
	if l != nil {
		_, ch, unsub = s.svc.Subscribe()
	}
	if _, err := s.svc.Start(store.TriggerManual, service.ConfigFrom(s.svc.Defaults(), req)); err != nil {
		unsub()
		return err
	}
	if l != nil {
		go func() {
			defer unsub()
			for ev := range ch {
				if b, err := json.Marshal(ev); err == nil {
					l.OnEvent(string(b))
				}
				if ev.Type == "done" {
					return
				}
			}
		}()
	}
	return nil
}

// Cancel stops the running scan; partial results are saved.
func (s *Scanner) Cancel() bool { return s.svc.Cancel() }

// Running reports whether a scan is in progress.
func (s *Scanner) Running() bool { return s.svc.Current() != nil }

// HistoryJSON returns the stored scans, newest first, as a JSON array.
func (s *Scanner) HistoryJSON() string {
	list := s.svc.Store().History.List()
	if list == nil {
		list = []store.Entry{}
	}
	b, _ := json.Marshal(list)
	return string(b)
}

// Report returns a stored report (empty id: newest) as "json" or "md" at a
// privacy level (full, technical, public).
func (s *Scanner) Report(id, format, privacy string) (string, error) {
	h := s.svc.Store().History
	if id == "" {
		l := h.List()
		if len(l) == 0 {
			return "", errors.New("no scans yet")
		}
		id = l[0].ID
	}
	rep, err := h.Load(id)
	if err != nil {
		return "", err
	}
	cp := *rep
	rd := report.NewRedactor(rep, privacy)
	cp.Privacy = rd.Level()
	if format == "json" {
		b, err := report.JSON(&cp)
		if err != nil {
			return "", err
		}
		return rd.Apply(string(b)), nil
	}
	return rd.Apply(report.Markdown(&cp)), nil
}

// SetPinned pins or unpins a stored scan.
func (s *Scanner) SetPinned(id string, pinned bool) error {
	_, err := s.svc.Store().History.SetPinned(id, pinned)
	return err
}

// Delete removes a stored scan.
func (s *Scanner) Delete(id string) error { return s.svc.Store().History.Delete(id) }

// Close cancels any scan, waits briefly for partial results to be saved.
func (s *Scanner) Close() { s.svc.Shutdown(5 * time.Second) }
