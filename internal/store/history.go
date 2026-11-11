package store

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
)

// IndexVersion is the on-disk version of history/index.json. Bump it and add
// a step to migrateIndex when the Entry layout changes incompatibly.
const IndexVersion = 1

// Defaults and hard limits for retention.
const (
	DefaultRetain = 100
	MinRetain     = 1
	MaxRetain     = 5000
	MaxPinned     = 500
	// maxReportBytes bounds a single decompressed report (imports included).
	maxReportBytes = 32 << 20
)

// Triggers record why a scan ran.
const (
	TriggerManual    = "manual"    // started from the UI or API
	TriggerScheduled = "scheduled" // Auto Run interval elapsed
	TriggerRunNow    = "run-now"   // Auto Run "Run now" button
	TriggerCLI       = "cli"       // one-shot `sadns run`
	TriggerImported  = "imported"  // report produced elsewhere and uploaded
)

// Status values for a stored scan.
const (
	StatusComplete  = "complete"
	StatusCancelled = "cancelled"
	StatusFailed    = "failed"
)

// Metrics are the per-scan numbers used for the history list and trend
// graphs. Zero values with the matching *OK flag false mean "not measured";
// they are never plotted as zero.
type Metrics struct {
	DNSMedianMS   float64 `json:"dns_median_ms,omitempty"` // primary system resolver, cached-query median
	DNSLossPct    float64 `json:"dns_loss_pct,omitempty"`
	DNSJitterMS   float64 `json:"dns_jitter_ms,omitempty"`
	DNSOK         bool    `json:"dns_measured"`
	DNSResolver   string  `json:"dns_resolver,omitempty"`
	GatewayRTTMS  float64 `json:"gateway_rtt_ms,omitempty"`
	GatewayLoss   float64 `json:"gateway_loss_pct,omitempty"`
	GatewayJitter float64 `json:"gateway_jitter_ms,omitempty"`
	GatewayOK     bool    `json:"gateway_measured"`
	InternetRTTMS float64 `json:"internet_rtt_ms,omitempty"`
	InternetLoss  float64 `json:"internet_loss_pct,omitempty"`
	InternetJit   float64 `json:"internet_jitter_ms,omitempty"`
	InternetOK    bool    `json:"internet_measured"`
	IPv4          string  `json:"ipv4"` // working, broken, disabled, unknown
	IPv6          string  `json:"ipv6"`
	WebAvgMS      float64 `json:"web_avg_ms,omitempty"` // mean total time of successful website loads
	WebOK         int     `json:"web_ok"`
	WebFailed     int     `json:"web_failed"`
}

// Entry is one row of the history index.
type Entry struct {
	ID          string            `json:"id"`
	StartedAt   time.Time         `json:"started_at"`
	FinishedAt  time.Time         `json:"finished_at"`
	DurationSec float64           `json:"duration_sec"`
	Trigger     string            `json:"trigger"`
	Mode        string            `json:"mode"`      // quick, full
	DataMode    string            `json:"data_mode"` // standard, low-data
	Status      string            `json:"status"`    // complete, cancelled, failed
	Error       string            `json:"error,omitempty"`
	Verdict     string            `json:"verdict"`
	Headline    string            `json:"headline"`
	Pass        int               `json:"pass"`
	Info        int               `json:"info"`
	Warn        int               `json:"warn"`
	Fail        int               `json:"fail"`
	Layers      map[string]string `json:"layers,omitempty"`
	Vantage     string            `json:"vantage,omitempty"`
	Pinned      bool              `json:"pinned"`
	Source      string            `json:"source"` // local, imported
	Host        string            `json:"host,omitempty"`
	ToolVersion string            `json:"tool_version,omitempty"`
	SizeBytes   int64             `json:"size_bytes"`
	Metrics     Metrics           `json:"metrics"`
}

type indexFile struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// History is the persistent scan history. It is safe for concurrent use.
type History struct {
	dir    string // .../history
	mu     sync.Mutex
	idx    []Entry // newest first
	retain int
}

var idRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$`)

// ValidID reports whether id has the shape the store generates. Callers use
// it before building paths from user input.
func ValidID(id string) bool { return idRe.MatchString(id) }

func newID(t time.Time) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return t.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

func openHistory(dir string, retain int) (*History, error) {
	h := &History{dir: dir, retain: clampRetain(retain)}
	if err := os.MkdirAll(h.reportsDir(), dirPerm); err != nil {
		return nil, err
	}
	cleanTemps(dir)
	cleanTemps(h.reportsDir())
	var f indexFile
	err := readJSON(h.indexPath(), &f)
	switch {
	case err == nil:
		if f.Version > IndexVersion {
			return nil, fmt.Errorf("history index version %d is newer than this build supports (%d); upgrade SAdns", f.Version, IndexVersion)
		}
		h.idx = migrateIndex(f)
		h.reconcile()
	case errors.Is(err, os.ErrNotExist):
		// First run, or index lost: rebuild from any reports on disk.
		if err := h.rebuild(); err != nil {
			return nil, err
		}
	default:
		// Corrupt index: keep a copy for inspection and rebuild from reports.
		_ = os.Rename(h.indexPath(), h.indexPath()+".corrupt-"+time.Now().UTC().Format("20060102-150405"))
		if err := h.rebuild(); err != nil {
			return nil, err
		}
	}
	h.sort()
	return h, h.saveIndex()
}

func migrateIndex(f indexFile) []Entry {
	// Version 0 (absent) and 1 share a layout; future migrations go here.
	for i := range f.Entries {
		if f.Entries[i].Source == "" {
			f.Entries[i].Source = "local"
		}
	}
	return f.Entries
}

func (h *History) indexPath() string  { return filepath.Join(h.dir, "index.json") }
func (h *History) reportsDir() string { return filepath.Join(h.dir, "reports") }
func (h *History) reportPath(id string) string {
	return filepath.Join(h.reportsDir(), id+".json.gz")
}

// reconcile drops index rows whose report file is gone and adopts report
// files missing from the index (e.g. a crash between the two writes).
func (h *History) reconcile() {
	have := map[string]bool{}
	kept := h.idx[:0]
	for _, e := range h.idx {
		if !ValidID(e.ID) {
			continue
		}
		if _, err := os.Stat(h.reportPath(e.ID)); err != nil {
			continue
		}
		have[e.ID] = true
		kept = append(kept, e)
	}
	h.idx = kept
	ents, _ := os.ReadDir(h.reportsDir())
	for _, d := range ents {
		id := strings.TrimSuffix(d.Name(), ".json.gz")
		if !ValidID(id) || have[id] {
			continue
		}
		if e, ok := h.entryFromFile(id); ok {
			h.idx = append(h.idx, e)
		}
	}
}

func (h *History) rebuild() error {
	h.idx = nil
	h.reconcile()
	return nil
}

func (h *History) entryFromFile(id string) (Entry, bool) {
	rep, err := h.readReport(id)
	if err != nil {
		return Entry{}, false
	}
	e := Summarize(rep)
	e.ID = id
	e.Trigger = "unknown"
	e.Source = "local"
	if st, err := os.Stat(h.reportPath(id)); err == nil {
		e.SizeBytes = st.Size()
	}
	return e, true
}

func (h *History) sort() {
	sort.SliceStable(h.idx, func(i, j int) bool { return h.idx[i].StartedAt.After(h.idx[j].StartedAt) })
}

func (h *History) saveIndex() error {
	return writeJSONAtomic(h.indexPath(), indexFile{Version: IndexVersion, Entries: h.idx})
}

func clampRetain(n int) int {
	if n <= 0 {
		return DefaultRetain
	}
	if n < MinRetain {
		return MinRetain
	}
	if n > MaxRetain {
		return MaxRetain
	}
	return n
}

// SaveMeta describes how a scan was produced.
type SaveMeta struct {
	Trigger string
	Status  string // empty: derived from the report
	Error   string
	Source  string // empty: local
}

// Save stores rep and returns its index entry, then applies retention.
func (h *History) Save(rep *model.Report, meta SaveMeta) (Entry, error) {
	if rep == nil {
		return Entry{}, errors.New("nil report")
	}
	e := Summarize(rep)
	e.ID = newID(rep.StartedAt)
	e.Trigger = meta.Trigger
	if meta.Status != "" {
		e.Status = meta.Status
	}
	e.Error = meta.Error
	e.Source = meta.Source
	if e.Source == "" {
		e.Source = "local"
	}
	data, err := compressReport(rep)
	if err != nil {
		return Entry{}, err
	}
	e.SizeBytes = int64(len(data))

	h.mu.Lock()
	defer h.mu.Unlock()
	// Report first, index second: a crash in between leaves an orphan report
	// that reconcile() adopts on the next start, never an index row without data.
	if err := writeAtomic(h.reportPath(e.ID), data); err != nil {
		return Entry{}, err
	}
	h.idx = append(h.idx, e)
	h.sort()
	h.applyRetention()
	if err := h.saveIndex(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// applyRetention deletes the oldest unpinned scans until at most h.retain
// unpinned scans remain. Pinned scans do not count towards the limit and are
// never removed automatically, so pinning can never cause a new scan to be
// discarded. Caller holds h.mu.
func (h *History) applyRetention() {
	unpinned := 0
	for _, e := range h.idx {
		if !e.Pinned {
			unpinned++
		}
	}
	excess := unpinned - h.retain
	for i := len(h.idx) - 1; i >= 0 && excess > 0; i-- {
		if h.idx[i].Pinned {
			continue
		}
		_ = os.Remove(h.reportPath(h.idx[i].ID))
		h.idx = append(h.idx[:i], h.idx[i+1:]...)
		excess--
	}
}

// SetRetain changes the retention count and applies it immediately.
func (h *History) SetRetain(n int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.retain = clampRetain(n)
	h.applyRetention()
	return h.saveIndex()
}

// Retain returns the current retention count.
func (h *History) Retain() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.retain
}

// List returns a copy of the index, newest first.
func (h *History) List() []Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Entry(nil), h.idx...)
}

// Get returns one index entry.
func (h *History) Get(id string) (Entry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i := h.find(id); i >= 0 {
		return h.idx[i], nil
	}
	return Entry{}, ErrNotFound
}

func (h *History) find(id string) int {
	for i := range h.idx {
		if h.idx[i].ID == id {
			return i
		}
	}
	return -1
}

// Load returns the full stored report.
func (h *History) Load(id string) (*model.Report, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	h.mu.Lock()
	ok := h.find(id) >= 0
	h.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return h.readReport(id)
}

func (h *History) readReport(id string) (*model.Report, error) {
	f, err := os.Open(h.reportPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer f.Close()
	return DecodeReport(f, true)
}

// DecodeReport reads a JSON report, optionally gzip-compressed, with a size
// bound. It validates the schema family so arbitrary JSON is rejected.
func DecodeReport(r io.Reader, gz bool) (*model.Report, error) {
	if gz {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	}
	b, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxReportBytes {
		return nil, errors.New("report too large")
	}
	var rep model.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("not a SAdns report: %w", err)
	}
	if !strings.HasPrefix(rep.Schema, "sadns/report/") {
		return nil, errors.New("not a SAdns report (missing schema)")
	}
	if rep.StartedAt.IsZero() {
		return nil, errors.New("report has no start time")
	}
	return &rep, nil
}

func compressReport(rep *model.Report) ([]byte, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err := json.NewEncoder(zw).Encode(rep); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SetPinned pins or unpins a scan. Pinned scans survive retention and Clear.
func (h *History) SetPinned(id string, pinned bool) (Entry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.find(id)
	if i < 0 {
		return Entry{}, ErrNotFound
	}
	if pinned && !h.idx[i].Pinned {
		n := 0
		for _, e := range h.idx {
			if e.Pinned {
				n++
			}
		}
		if n >= MaxPinned {
			return Entry{}, fmt.Errorf("at most %d scans can be pinned", MaxPinned)
		}
	}
	h.idx[i].Pinned = pinned
	if !pinned {
		h.applyRetention()
	}
	if err := h.saveIndex(); err != nil {
		return Entry{}, err
	}
	if j := h.find(id); j >= 0 {
		return h.idx[j], nil
	}
	return Entry{}, ErrNotFound // unpinned and immediately aged out
}

// Delete removes one scan, pinned or not (explicit user action).
func (h *History) Delete(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.find(id)
	if i < 0 {
		return ErrNotFound
	}
	h.idx = append(h.idx[:i], h.idx[i+1:]...)
	if err := h.saveIndex(); err != nil {
		return err
	}
	if err := os.Remove(h.reportPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Clear removes all scans; pinned ones too only when includePinned is set.
// It returns how many were removed.
func (h *History) Clear(includePinned bool) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var kept []Entry
	var gone []string
	for _, e := range h.idx {
		if e.Pinned && !includePinned {
			kept = append(kept, e)
		} else {
			gone = append(gone, e.ID)
		}
	}
	h.idx = kept
	if err := h.saveIndex(); err != nil {
		return 0, err
	}
	for _, id := range gone {
		_ = os.Remove(h.reportPath(id))
	}
	return len(gone), nil
}

// Summarize derives an index entry (without ID/trigger) from a report.
func Summarize(rep *model.Report) Entry {
	e := Entry{
		StartedAt: rep.StartedAt, FinishedAt: rep.FinishedAt, DurationSec: rep.DurationSec,
		Mode: "full", DataMode: "standard", Status: StatusComplete,
		Verdict: rep.Summary.Verdict, Headline: rep.Summary.Headline,
		Pass: rep.Summary.Pass, Info: rep.Summary.Info, Warn: rep.Summary.Warn, Fail: rep.Summary.Fail,
		ToolVersion: rep.Tool.Version, Vantage: rep.Vantage.Mode,
	}
	if rep.Options.Quick {
		e.Mode = "quick"
	}
	if rep.Options.LowData {
		e.DataMode = "low-data"
	}
	if rep.Cancelled {
		e.Status = StatusCancelled
	}
	if rep.System != nil {
		e.Host = rep.System.Hostname
	}
	if len(rep.Summary.Layers) > 0 {
		e.Layers = map[string]string{}
		for _, l := range rep.Summary.Layers {
			e.Layers[l.Key] = l.Status
		}
	}
	e.Metrics = metrics(rep)
	return e
}

func famState(f model.FamilyConn) string {
	switch {
	case f.Disabled:
		return "disabled"
	case f.Working:
		return "working"
	case len(f.Probes) == 0:
		return "unknown"
	default:
		return "broken"
	}
}

func metrics(rep *model.Report) Metrics {
	m := Metrics{IPv4: famState(rep.Connectivity.IPv4), IPv6: famState(rep.Connectivity.IPv6)}
	// DNS: the primary system resolver that answered; fall back to any system one.
	pick := func(primary bool) *model.ResolverResult {
		for i := range rep.Resolvers {
			r := &rep.Resolvers[i]
			if r.Role == "system" && r.Latency.Received > 0 && (!primary || r.Primary) {
				return r
			}
		}
		return nil
	}
	r := pick(true)
	if r == nil {
		r = pick(false)
	}
	if r != nil {
		m.DNSOK = true
		m.DNSMedianMS, m.DNSLossPct, m.DNSJitterMS = r.Latency.MedianMS, r.Latency.LossPct, r.Latency.JitterMS
		m.DNSResolver = r.Addr
	}
	for _, p := range rep.Network.Pings {
		if p.Sent == 0 || (p.Error != "" && p.Received == 0 && p.LossPct == 0) {
			continue
		}
		switch {
		case strings.HasPrefix(p.Label, "Default gateway") && !m.GatewayOK:
			m.GatewayOK = true
			m.GatewayRTTMS, m.GatewayLoss, m.GatewayJitter = p.AvgMS, p.LossPct, p.JitterMS
		case strings.HasPrefix(p.Label, "Internet") && !m.InternetOK:
			m.InternetOK = true
			m.InternetRTTMS, m.InternetLoss, m.InternetJit = p.AvgMS, p.LossPct, p.JitterMS
		}
	}
	var sum float64
	for _, w := range rep.Web {
		if w.OK {
			m.WebOK++
			sum += w.TotalMS
		} else if w.Runs > 0 {
			m.WebFailed++
		}
	}
	if m.WebOK > 0 {
		m.WebAvgMS = sum / float64(m.WebOK)
	}
	return m
}
