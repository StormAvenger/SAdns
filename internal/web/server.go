// Package web serves the SAdns browser UI on a loopback-only port. The UI
// is a single embedded HTML file; all probing happens in this process.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/analyze"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/report"
)

//go:embed index.html
var indexHTML []byte

// Options configures the UI server.
type Options struct {
	Listen      string // default 127.0.0.1:0 (random port)
	OpenBrowser bool
	Defaults    probe.Config
	Tool        model.ToolInfo
	IdleTimeout time.Duration
	Logf        func(format string, a ...any)
}

type server struct {
	opt   Options
	token string
	host  string

	mu      sync.Mutex
	running bool
	events  []probe.Event
	subs    map[chan probe.Event]struct{}
	rep     *model.Report
	seen    time.Time
}

// Serve runs the UI until ctx is cancelled, the user clicks Quit, or the
// server has been idle for IdleTimeout.
func Serve(ctx context.Context, opt Options) error {
	if opt.Listen == "" {
		opt.Listen = "127.0.0.1:0"
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.IdleTimeout == 0 {
		opt.IdleTimeout = 2 * time.Hour
	}
	ln, err := net.Listen("tcp", opt.Listen)
	if err != nil {
		return err
	}
	var tb [16]byte
	_, _ = rand.Read(tb[:])
	s := &server{opt: opt, token: hex.EncodeToString(tb[:]), host: ln.Addr().String(), subs: map[chan probe.Event]struct{}{}, seen: time.Now()}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.guard(s.handleIndex, false))
	mux.HandleFunc("/api/info", s.guard(s.handleInfo, true))
	mux.HandleFunc("/api/run", s.guard(s.handleRun, true))
	mux.HandleFunc("/api/events", s.guard(s.handleEvents, true))
	mux.HandleFunc("/api/report.md", s.guard(s.handleMD, true))
	mux.HandleFunc("/api/report.json", s.guard(s.handleJSON, true))
	mux.HandleFunc("/api/quit", s.guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprintln(w, "bye")
		go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	}, true))

	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	url := fmt.Sprintf("http://%s/?token=%s", s.host, s.token)
	opt.Logf("SAdns UI running at %s", url)
	opt.Logf("(Keep this window open while you use the UI. Press Ctrl+C or click Quit in the page to stop.)")
	if opt.OpenBrowser {
		if err := openBrowser(url); err != nil {
			opt.Logf("Could not open a browser automatically (%v) — open the URL above manually.", err)
		}
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.mu.Lock()
				idle := !s.running && time.Since(s.seen) > opt.IdleTimeout
				s.mu.Unlock()
				if idle {
					opt.Logf("Idle for %s, shutting down.", opt.IdleTimeout)
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = hs.Shutdown(sctx)
	}()
	err = hs.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// guard enforces loopback Host headers (DNS-rebinding defence) and the
// per-launch token (blocks other local web pages from driving the API).
func (s *server) guard(h http.HandlerFunc, api bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		tok := r.URL.Query().Get("token")
		if tok == "" {
			tok = r.Header.Get("X-SAdns-Token")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			if !api && r.URL.Path == "/" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>SAdns</title><body style="font-family:system-ui;background:#0b0f14;color:#dde5ee;padding:3rem"><h2>SAdns</h2><p>This page needs the private link printed in the SAdns console window (it contains a one-time token).</p></body>`)
				return
			}
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		if api && r.Method == http.MethodPost && r.Header.Get("X-SAdns-Token") == "" {
			http.Error(w, "missing token header", http.StatusForbidden) // simple CSRF guard
			return
		}
		s.mu.Lock()
		s.seen = time.Now()
		s.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h(w, r)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	_, _ = w.Write(indexHTML)
}

type infoResp struct {
	Tool      model.ToolInfo   `json:"tool"`
	OS        string           `json:"os"`
	Arch      string           `json:"arch"`
	Providers []probe.Provider `json:"providers"`
	Defaults  runReq           `json:"defaults"`
	Running   bool             `json:"running"`
	HasReport bool             `json:"has_report"`
}

type runReq struct {
	Quick      bool     `json:"quick"`
	Samples    int      `json:"samples"`
	TimeoutMS  int      `json:"timeout_ms"`
	Providers  []string `json:"providers"`
	Extra      []string `json:"extra"`
	Traceroute bool     `json:"traceroute"`
	Encrypted  bool     `json:"encrypted"`
	IPv4       bool     `json:"ipv4"`
	IPv6       bool     `json:"ipv6"`
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	d := s.opt.Defaults
	s.mu.Lock()
	resp := infoResp{
		Tool: s.opt.Tool, OS: runtime.GOOS, Arch: runtime.GOARCH, Providers: probe.Providers,
		Defaults: runReq{Quick: d.Quick, Samples: d.Samples, TimeoutMS: int(d.Timeout.Milliseconds()), Providers: d.Providers, Extra: d.Extra,
			Traceroute: d.Traceroute, Encrypted: d.Encrypted, IPv4: d.IPv4, IPv6: d.IPv6},
		Running: s.running, HasReport: s.rep != nil,
	}
	s.mu.Unlock()
	writeJSON(w, resp)
}

func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req runReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := s.opt.Defaults
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
	cfg.Providers = req.Providers
	cfg.Extra = nil
	for _, x := range req.Extra {
		if x = strings.TrimSpace(x); x != "" {
			cfg.Extra = append(cfg.Extra, x)
		}
	}
	cfg.Traceroute, cfg.Encrypted, cfg.IPv4, cfg.IPv6 = req.Traceroute, req.Encrypted, req.IPv4, req.IPv6

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		http.Error(w, "a run is already in progress", http.StatusConflict)
		return
	}
	s.running = true
	s.events = nil
	s.rep = nil
	s.mu.Unlock()

	go func() {
		eng := probe.New(cfg, s.publish)
		rep := eng.Run(context.Background())
		rep.Tool = s.opt.Tool
		analyze.Run(rep)
		s.mu.Lock()
		s.rep = rep
		s.running = false
		s.mu.Unlock()
		s.publish(probe.Event{Type: "done", Progress: 1, Message: fmt.Sprintf("Finished in %.1f s", rep.DurationSec), Report: rep})
		s.opt.Logf("Run finished: %s — %d fail, %d warn, %d info, %d pass", rep.Summary.Verdict, rep.Summary.Fail, rep.Summary.Warn, rep.Summary.Info, rep.Summary.Pass)
	}()
	writeJSON(w, map[string]any{"started": true})
}

func (s *server) publish(ev probe.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := ev
	if ev.Type == "done" {
		stored.Report = nil // replayed separately from s.rep
	}
	s.events = append(s.events, stored)
	for ch := range s.subs {
		select {
		case ch <- ev:
		default: // slow client; it will catch up from history on reconnect
		}
	}
	if ev.Type == "phase" || ev.Type == "log" {
		s.opt.Logf("  %s", ev.Message)
	}
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	ch := make(chan probe.Event, 256)
	s.mu.Lock()
	history := append([]probe.Event(nil), s.events...)
	rep := s.rep
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()
	send := func(ev probe.Event) bool {
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
	for _, ev := range history {
		if ev.Type == "done" {
			ev.Report = rep
		}
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
		}
	}
}

func (s *server) current(w http.ResponseWriter) *model.Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rep == nil {
		http.Error(w, "no report yet", http.StatusNotFound)
	}
	return s.rep
}

func (s *server) handleMD(w http.ResponseWriter, r *http.Request) {
	rep := s.current(w)
	if rep == nil {
		return
	}
	body := Render(rep, r.URL.Query().Get("redact") == "1", "md")
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+FileBase(rep)+`.md"`)
	}
	_, _ = w.Write(body)
}

func (s *server) handleJSON(w http.ResponseWriter, r *http.Request) {
	rep := s.current(w)
	if rep == nil {
		return
	}
	body := Render(rep, r.URL.Query().Get("redact") == "1", "json")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+FileBase(rep)+`.json"`)
	}
	_, _ = w.Write(body)
}

// Render produces Markdown or JSON output, optionally redacted.
func Render(rep *model.Report, redact bool, format string) []byte {
	cp := *rep
	cp.Redacted = redact
	var out string
	if format == "json" {
		b, _ := report.JSON(&cp)
		out = string(b)
	} else {
		out = report.Markdown(&cp)
	}
	if redact {
		out = report.NewRedactor(rep).Apply(out)
	}
	return []byte(out)
}

// FileBase is the suggested report file name without extension.
func FileBase(rep *model.Report) string {
	return "sadns-report-" + rep.StartedAt.Format("20060102-150405")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
