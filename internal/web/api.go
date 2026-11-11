package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/auth"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/report"
	"github.com/StormAvenger/SAdns/internal/service"
	"github.com/StormAvenger/SAdns/internal/store"
)

// APIVersion is reported by /api/v1/info so clients (including a future
// mobile app) can check compatibility.
const APIVersion = 1

// Body limits.
const (
	maxJSONBody   = 64 << 10
	maxImportBody = 16 << 20
)

func (s *server) routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.handleHealth)
	m.HandleFunc("GET /{$}", s.handleIndex)
	m.HandleFunc("POST /api/v1/login", s.handleLogin)
	m.HandleFunc("POST /api/v1/logout", s.handleLogout)
	m.HandleFunc("GET /api/v1/info", s.handleInfo)

	m.HandleFunc("POST /api/v1/scans", s.handleStartScan)
	m.HandleFunc("GET /api/v1/scans/current", s.handleCurrent)
	m.HandleFunc("POST /api/v1/scans/current/cancel", s.handleCancel)
	m.HandleFunc("GET /api/v1/events", s.handleEvents)
	m.HandleFunc("GET /api/v1/report", s.handleReport)

	m.HandleFunc("GET /api/v1/history", s.handleHistory)
	m.HandleFunc("GET /api/v1/history/compare", s.handleCompare)
	m.HandleFunc("POST /api/v1/history/clear", s.handleClear)
	m.HandleFunc("POST /api/v1/history/import", s.handleImport)
	m.HandleFunc("GET /api/v1/history/{id}", s.handleEntry)
	m.HandleFunc("DELETE /api/v1/history/{id}", s.handleDelete)
	m.HandleFunc("POST /api/v1/history/{id}/pin", s.handlePin)
	m.HandleFunc("GET /api/v1/trends", s.handleTrends)

	m.HandleFunc("GET /api/v1/schedule", s.handleSchedule)
	m.HandleFunc("PUT /api/v1/schedule", s.handlePutSchedule)
	m.HandleFunc("POST /api/v1/schedule/{action}", s.handleScheduleAction)
	m.HandleFunc("GET /api/v1/preferences", s.handlePrefs)
	m.HandleFunc("PUT /api/v1/preferences", s.handlePutPrefs)

	m.HandleFunc("POST /api/v1/quit", s.handleQuit)
	return m
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// decode reads a size-limited JSON body and rejects unknown fields so typos
// in API clients fail loudly.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return false
	}
	return true
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", cspHeader)
	_, _ = w.Write(indexHTML)
}

func clientKey(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.opt.Mode != Server || s.opt.Auth == nil {
		jsonErr(w, http.StatusNotFound, "login is not used in this mode")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	sid, csrf, err := s.opt.Auth.Login(clientKey(r), req.Password)
	switch {
	case errors.Is(err, auth.ErrLocked):
		w.Header().Set("Retry-After", "300")
		jsonErr(w, http.StatusTooManyRequests, err.Error())
		s.opt.Logf("Login refused for %s: locked out after repeated failures", clientKey(r))
		return
	case err != nil:
		jsonErr(w, http.StatusUnauthorized, "incorrect password")
		s.opt.Logf("Failed login from %s", clientKey(r))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || s.opt.SecureCookies, MaxAge: int(s.opt.Auth.MaxTTL.Seconds())})
	s.opt.Logf("Login from %s", clientKey(r))
	writeJSON(w, map[string]string{"csrf": csrf})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sid, ok := r.Context().Value(sidKey{}).(string); ok && s.opt.Auth != nil {
		s.opt.Auth.Logout(sid)
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1,
		Secure: r.TLS != nil || s.opt.SecureCookies})
	writeJSON(w, map[string]bool{"ok": true})
}

// RunRequest is the body of POST /api/v1/scans.
type RunRequest struct {
	Quick     bool     `json:"quick"`
	Samples   int      `json:"samples"`
	TimeoutMS int      `json:"timeout_ms"`
	Providers []string `json:"providers"`
	// NoProviders must be set explicitly: an empty Providers list alone means
	// "default (all)", so clients send this when every provider is off.
	NoProviders bool     `json:"no_providers"`
	LowData     bool     `json:"low_data"`
	URLs        []string `json:"urls"`
	Extra       []string `json:"extra"`
	Traceroute  bool     `json:"traceroute"`
	Encrypted   bool     `json:"encrypted"`
	IPv4        bool     `json:"ipv4"`
	IPv6        bool     `json:"ipv6"`
}

type infoResp struct {
	APIVersion int                  `json:"api_version"`
	Mode       string               `json:"mode"` // desktop, server
	Auth       string               `json:"auth"` // token, password, none
	Tool       model.ToolInfo       `json:"tool"`
	CSRF       string               `json:"csrf"`
	OS         string               `json:"os"`
	Arch       string               `json:"arch"`
	Vantage    model.Vantage        `json:"vantage"`
	Providers  []probe.Provider     `json:"providers"`
	Defaults   RunRequest           `json:"defaults"`
	Prefs      store.ScanPrefs      `json:"preferences"`
	Current    *service.ScanInfo    `json:"current"`
	Last       *store.Entry         `json:"last"`
	Schedule   service.ScheduleView `json:"schedule"`
	DataDir    string               `json:"data_dir,omitempty"`
	Limits     map[string]int       `json:"limits"`
	Errors     []string             `json:"warnings,omitempty"`
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	d := s.svc.Defaults()
	csrf, _ := r.Context().Value(csrfKey{}).(string)
	_, last := s.svc.Last()
	resp := infoResp{
		APIVersion: APIVersion, Tool: s.opt.Tool, CSRF: csrf, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Vantage: s.opt.Vantage, Providers: probe.Providers,
		Defaults: RunRequest{Quick: d.Quick, Samples: d.Samples, TimeoutMS: int(d.Timeout.Milliseconds()), Providers: d.Providers, Extra: d.Extra,
			LowData: d.LowData, Traceroute: d.Traceroute, Encrypted: d.Encrypted, IPv4: d.IPv4, IPv6: d.IPv6},
		Prefs: s.svc.Store().Settings().Scan, Current: s.svc.Current(), Last: last, Schedule: s.svc.ScheduleView(),
		Limits: map[string]int{"max_urls": probe.MaxCustomURLs, "max_extra_resolvers": 16, "min_interval_minutes": store.MinIntervalMinutes,
			"max_retain": store.MaxRetain},
	}
	switch {
	case s.opt.Mode == Desktop:
		resp.Mode, resp.Auth = "desktop", "token"
		resp.DataDir = s.svc.Store().Dir
	case s.opt.NoAuth:
		resp.Mode, resp.Auth = "server", "none"
	default:
		resp.Mode, resp.Auth = "server", "password"
	}
	if s.svc.Store().LoadWarning != nil {
		resp.Errors = append(resp.Errors, s.svc.Store().LoadWarning.Error())
	}
	writeJSON(w, resp)
}

// configFrom validates a run request into an engine configuration.
func (s *server) configFrom(req RunRequest) probe.Config {
	cfg := s.svc.Defaults()
	cfg.Quick = req.Quick
	if req.Samples > 0 && req.Samples <= 50 {
		cfg.Samples = req.Samples
	}
	if cfg.Quick && req.Samples == 0 {
		cfg.Samples = 3
	}
	if req.TimeoutMS >= 200 && req.TimeoutMS <= 15000 {
		cfg.Timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	cfg.Providers = nil
	for i, p := range req.Providers {
		if i >= 32 {
			break
		}
		cfg.Providers = append(cfg.Providers, p)
	}
	cfg.NoProviders = req.NoProviders
	cfg.URLs = nil
	for i, u := range req.URLs {
		if i >= probe.MaxCustomURLs {
			break
		}
		if n, err := probe.NormalizeURL(u); err == nil {
			cfg.URLs = append(cfg.URLs, n)
		}
	}
	cfg.Extra = nil
	for i, x := range req.Extra {
		if i >= 16 {
			break // resource limit
		}
		if x = strings.TrimSpace(x); x != "" && len(x) <= 256 {
			cfg.Extra = append(cfg.Extra, x)
		}
	}
	cfg.Traceroute, cfg.Encrypted, cfg.IPv4, cfg.IPv6 = req.Traceroute, req.Encrypted, req.IPv4, req.IPv6
	cfg.LowData = req.LowData
	return cfg
}

func (s *server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req RunRequest
	if !decode(w, r, &req) {
		return
	}
	info, err := s.svc.Start(store.TriggerManual, s.configFrom(req))
	if errors.Is(err, service.ErrBusy) {
		jsonErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"started": true, "scan": info})
}

func (s *server) handleCurrent(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"current": s.svc.Current()})
}

func (s *server) handleCancel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"cancelled": s.svc.Cancel()})
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		jsonErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	hist, ch, unsub := s.svc.Subscribe()
	defer unsub()
	send := func(ev service.Event) bool {
		b, err := json.Marshal(ev)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	// Tell the client which replay follows so it can reset its view.
	if !send(service.Event{Event: probe.Event{Type: "hello"}, Scan: s.svc.Current()}) {
		return
	}
	for _, ev := range hist {
		if !send(ev) {
			return
		}
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if !send(ev) {
				return
			}
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
			s.touch()
		}
	}
}

// reportFor returns the report for ?id= (history) or, without an id, the
// most recent scan.
func (s *server) reportFor(w http.ResponseWriter, id string) (*model.Report, bool) {
	h := s.svc.Store().History
	if id == "" {
		rep, last := s.svc.Last()
		if rep != nil {
			return rep, true
		}
		if last == nil {
			jsonErr(w, http.StatusNotFound, "no report yet")
			return nil, false
		}
		id = last.ID
	}
	if !store.ValidID(id) {
		jsonErr(w, http.StatusBadRequest, "invalid id")
		return nil, false
	}
	rep, err := h.Load(id)
	if errors.Is(err, store.ErrNotFound) {
		jsonErr(w, http.StatusNotFound, "no such scan")
		return nil, false
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "could not read scan: "+err.Error())
		return nil, false
	}
	return rep, true
}

func (s *server) handleReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rep, ok := s.reportFor(w, q.Get("id"))
	if !ok {
		return
	}
	format := q.Get("format")
	ctype := "text/markdown; charset=utf-8"
	switch format {
	case "json":
		ctype = "application/json; charset=utf-8"
	case "", "md":
		format = "md"
	default:
		jsonErr(w, http.StatusBadRequest, "format must be md or json")
		return
	}
	level := report.ParsePrivacy(q.Get("privacy"))
	body := Render(rep, level, format)
	w.Header().Set("Content-Type", ctype)
	if q.Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+FileBase(rep)+"-"+level+"."+format+`"`)
	}
	_, _ = w.Write(body)
}

func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	h := s.svc.Store().History
	writeJSON(w, map[string]any{"entries": h.List(), "retain": h.Retain(), "max_pinned": store.MaxPinned})
}

func (s *server) handleEntry(w http.ResponseWriter, r *http.Request) {
	e, err := s.svc.Store().History.Get(r.PathValue("id"))
	if err != nil {
		jsonErr(w, http.StatusNotFound, "no such scan")
		return
	}
	writeJSON(w, e)
}

func (s *server) handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Store().History.Delete(r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			code = http.StatusNotFound
		}
		jsonErr(w, code, err.Error())
		return
	}
	s.svc.Notify("history")
	writeJSON(w, map[string]bool{"deleted": true})
}

func (s *server) handlePin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pinned bool `json:"pinned"`
	}
	if !decode(w, r, &req) {
		return
	}
	e, err := s.svc.Store().History.SetPinned(r.PathValue("id"), req.Pinned)
	if errors.Is(err, store.ErrNotFound) {
		jsonErr(w, http.StatusNotFound, "no such scan (it may have aged out after unpinning)")
		return
	}
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.svc.Notify("history")
	writeJSON(w, e)
}

func (s *server) handleClear(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IncludePinned bool `json:"include_pinned"`
	}
	if !decode(w, r, &req) {
		return
	}
	n, err := s.svc.Store().History.Clear(req.IncludePinned)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.svc.Notify("history")
	writeJSON(w, map[string]int{"removed": n})
}

func (s *server) handleCompare(w http.ResponseWriter, r *http.Request) {
	h := s.svc.Store().History
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	ea, errA := h.Get(a)
	eb, errB := h.Get(b)
	if errA != nil || errB != nil {
		jsonErr(w, http.StatusNotFound, "both a and b must be stored scan ids")
		return
	}
	if ea.StartedAt.After(eb.StartedAt) {
		ea, eb, a, b = eb, ea, b, a
	}
	ra, _ := h.Load(a)
	rb, _ := h.Load(b)
	writeJSON(w, store.Compare(ea, eb, ra, rb))
}

// handleImport stores a report produced elsewhere (another device, the CLI)
// so it can be browsed and compared. Its findings are kept as produced.
func (s *server) handleImport(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxImportBody)
	rep, err := store.DecodeReport(body, false)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonErr(w, http.StatusRequestEntityTooLarge, "report larger than 16 MiB")
			return
		}
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = io.Copy(io.Discard, body)
	e, err := s.svc.Store().History.Save(rep, store.SaveMeta{Trigger: store.TriggerImported, Source: "imported"})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.svc.Notify("history")
	writeJSON(w, e)
}

// TrendPoint is one scan's metrics, oldest first.
type TrendPoint struct {
	ID        string        `json:"id"`
	StartedAt time.Time     `json:"started_at"`
	Status    string        `json:"status"`
	Mode      string        `json:"mode"`
	Source    string        `json:"source"`
	Vantage   string        `json:"vantage,omitempty"`
	Warn      int           `json:"warn"`
	Fail      int           `json:"fail"`
	Metrics   store.Metrics `json:"metrics"`
}

func (s *server) handleTrends(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= store.MaxRetain+store.MaxPinned {
		limit = v
	}
	includeImported := r.URL.Query().Get("imported") == "1"
	list := s.svc.Store().History.List()
	var pts []TrendPoint
	for _, e := range list {
		if e.Source == "imported" && !includeImported {
			continue // other devices would mix vantage points into one line
		}
		pts = append(pts, TrendPoint{ID: e.ID, StartedAt: e.StartedAt, Status: e.Status, Mode: e.Mode, Source: e.Source, Vantage: e.Vantage, Warn: e.Warn, Fail: e.Fail, Metrics: e.Metrics})
		if len(pts) >= limit {
			break
		}
	}
	for i, j := 0, len(pts)-1; i < j; i, j = i+1, j-1 {
		pts[i], pts[j] = pts[j], pts[i]
	}
	writeJSON(w, map[string]any{"points": pts})
}

func (s *server) handleSchedule(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.svc.ScheduleView())
}

func (s *server) handlePutSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		store.Schedule
		Retain int `json:"history_retain"`
	}
	if !decode(w, r, &req) {
		return
	}
	v, err := s.svc.UpdateSchedule(req.Schedule, req.Retain)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, v)
}

func (s *server) handleScheduleAction(w http.ResponseWriter, r *http.Request) {
	var (
		v   service.ScheduleView
		err error
	)
	switch r.PathValue("action") {
	case "pause":
		v, err = s.svc.Pause()
	case "resume":
		v, err = s.svc.Resume()
	case "run-now":
		var info service.ScanInfo
		info, err = s.svc.RunNow()
		if errors.Is(err, service.ErrBusy) {
			jsonErr(w, http.StatusConflict, err.Error())
			return
		}
		if err == nil {
			w.WriteHeader(http.StatusAccepted)
			writeJSON(w, map[string]any{"started": true, "scan": info})
			return
		}
	default:
		jsonErr(w, http.StatusNotFound, "unknown action")
		return
	}
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, v)
}

func (s *server) handlePrefs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.svc.Store().Settings().Scan)
}

func (s *server) handlePutPrefs(w http.ResponseWriter, r *http.Request) {
	var p store.ScanPrefs
	if !decode(w, r, &p) {
		return
	}
	var urls []string
	for _, u := range p.URLs {
		n, err := probe.NormalizeURL(u)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, fmt.Sprintf("website %q: %v", u, err))
			return
		}
		urls = append(urls, n)
	}
	p.URLs = urls
	set := s.svc.Store().Settings()
	set.Scan = p
	if err := s.svc.Store().SaveSettings(set); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, set.Scan)
}

func (s *server) handleQuit(w http.ResponseWriter, r *http.Request) {
	if s.opt.Mode != Desktop || s.quit == nil {
		jsonErr(w, http.StatusNotFound, "quit is only available in the desktop app")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
	go func() { time.Sleep(200 * time.Millisecond); s.quit() }()
}
