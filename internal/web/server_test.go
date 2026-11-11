package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StormAvenger/SAdns/internal/auth"
	"github.com/StormAvenger/SAdns/internal/mockdns"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/service"
	"github.com/StormAvenger/SAdns/internal/store"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

func TestCheckLoopback(t *testing.T) {
	for in, ok := range map[string]bool{"127.0.0.1:0": true, "[::1]:8080": true, "localhost:9": true, ":8080": true,
		"0.0.0.0:8080": false, "192.168.1.5:80": false, "[::]:80": false, "example.com:80": false} {
		_, err := CheckLoopback(in)
		if (err == nil) != ok {
			t.Errorf("%s: err=%v", in, err)
		}
	}
}

// fakeRunner returns a small report immediately, or waits for release/ctx.
func fakeRunner(release chan struct{}) service.Runner {
	return func(ctx context.Context, cfg probe.Config, emit func(probe.Event)) *model.Report {
		emit(probe.Event{Type: "phase", Phase: "x", Message: "working", Progress: 0.3})
		r := &model.Report{Schema: "sadns/report/v1", StartedAt: time.Now(), System: &sysinfo.Info{Hostname: "h"}, Options: model.Options{Quick: cfg.Quick}}
		if release != nil {
			select {
			case <-release:
			case <-ctx.Done():
				r.Cancelled = true
			}
		}
		return r
	}
}

func newSvc(t *testing.T, runner service.Runner) *service.Service {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(service.Options{Store: st, Runner: runner,
		Defaults: probe.Config{Timeout: 300 * time.Millisecond, Samples: 1, IPv4: true, IPv6: true}})
	t.Cleanup(func() { svc.Shutdown(5 * time.Second) })
	return svc
}

type client struct {
	t      *testing.T
	h      http.Handler
	host   string
	cookie string
	csrf   string
}

func (c *client) do(method, url string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Host = c.host
	req.RemoteAddr = "192.0.2.10:5555"
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	if c.csrf != "" {
		req.Header.Set("X-SAdns-CSRF", c.csrf)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec
}

func (c *client) json(method, url string, body any, out any) int {
	c.t.Helper()
	b, _ := json.Marshal(body)
	if body == nil {
		b = nil
	}
	r := c.do(method, url, nil, string(b))
	if out != nil && r.Code < 300 {
		if err := json.Unmarshal(r.Body.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, url, err, r.Body)
		}
	}
	return r.Code
}

func desktop(t *testing.T, svc *service.Service) (*server, *client) {
	s, err := newServer(Options{Mode: Desktop, Service: svc}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	s.token = "secret-token"
	return s, &client{t: t, h: s.handler(), host: "127.0.0.1:1234"}
}

func TestDesktopGuard(t *testing.T) {
	_, c := desktop(t, newSvc(t, fakeRunner(nil)))
	if r := c.do("GET", "/", nil, ""); r.Code != 403 {
		t.Fatalf("no token: %d", r.Code)
	}
	r := c.do("GET", "/?token=secret-token", nil, "")
	sc := r.Header().Get("Set-Cookie")
	if r.Code != 200 || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Strict") {
		t.Fatalf("index: %d cookie=%q", r.Code, sc)
	}
	if r.Header().Get("Content-Security-Policy") != cspHeader || r.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
	c.cookie = "sadns_1234=secret-token"
	var info infoResp
	if code := c.json("GET", "/api/v1/info", nil, &info); code != 200 || info.Mode != "desktop" || info.CSRF != "secret-token" || info.APIVersion != 1 {
		t.Fatalf("info: %d %+v", code, info)
	}
	c.cookie = ""
	if r := c.do("GET", "/api/v1/info?token=secret-token", nil, ""); r.Code != 403 {
		t.Fatalf("API must not accept the token in the URL: %d", r.Code)
	}
	c.cookie = "sadns_1234=secret-token"
	if r := c.do("POST", "/api/v1/scans/current/cancel", nil, ""); r.Code != 403 {
		t.Fatalf("POST without CSRF header accepted: %d", r.Code)
	}
	c.csrf = "secret-token"
	if r := c.do("POST", "/api/v1/scans/current/cancel", nil, ""); r.Code != 200 {
		t.Fatalf("POST with CSRF: %d", r.Code)
	}
	if r := c.do("POST", "/api/v1/scans/current/cancel", map[string]string{"Origin": "http://evil.example"}, ""); r.Code != 403 {
		t.Fatalf("cross-origin POST accepted: %d", r.Code)
	}
	c.host = "evil.example:1234" // DNS rebinding attempt
	if r := c.do("GET", "/api/v1/info", nil, ""); r.Code != 403 {
		t.Fatalf("foreign Host accepted: %d", r.Code)
	}
	c.host = "127.0.0.1:1234"
	if r := c.do("POST", "/api/v1/login", nil, `{"password":"x"}`); r.Code != 404 {
		t.Fatalf("login in desktop mode: %d", r.Code)
	}
}

func TestCSPMatchesEmbeddedAssets(t *testing.T) {
	for _, tag := range [][2]string{{"<script>", "</script>"}, {"<style>", "</style>"}} {
		i, j := bytes.Index(indexHTML, []byte(tag[0])), bytes.Index(indexHTML, []byte(tag[1]))
		sum := sha256.Sum256(indexHTML[i+len(tag[0]) : j])
		if !strings.Contains(cspHeader, base64.StdEncoding.EncodeToString(sum[:])) {
			t.Fatalf("CSP missing hash for %s", tag[0])
		}
		if bytes.Count(indexHTML, []byte(tag[0])) != 1 {
			t.Fatalf("exactly one %s block is allowed under the hashed CSP", tag[0])
		}
	}
	if strings.Contains(cspHeader, "unsafe-inline") {
		t.Fatal("CSP still allows unsafe-inline")
	}
	if bytes.Contains(indexHTML, []byte(` style="`)) {
		t.Fatal("inline style attributes would be blocked by the CSP")
	}
}

const testPassword = "correct horse battery staple"

func serverMode(t *testing.T, svc *service.Service, mod func(*Options)) (*server, *client) {
	t.Helper()
	h, err := auth.NewHash(testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Mode: Server, Service: svc, Auth: auth.NewManager(h), AllowedHosts: []string{"sadns.home.arpa"}}
	if mod != nil {
		mod(&o)
	}
	s, err := newServer(o, "0.0.0.0:8053")
	if err != nil {
		t.Fatal(err)
	}
	return s, &client{t: t, h: s.handler(), host: "192.168.1.20:8053"}
}

func login(t *testing.T, c *client) {
	t.Helper()
	r := c.do("POST", "/api/v1/login", map[string]string{"Origin": "http://" + c.host}, `{"password":"`+testPassword+`"}`)
	if r.Code != 200 {
		t.Fatalf("login: %d %s", r.Code, r.Body)
	}
	var out struct{ CSRF string }
	_ = json.Unmarshal(r.Body.Bytes(), &out)
	ck := r.Result().Cookies()
	if len(ck) != 1 || !ck[0].HttpOnly || ck[0].SameSite != http.SameSiteStrictMode || out.CSRF == "" {
		t.Fatalf("session cookie %+v csrf=%q", ck, out.CSRF)
	}
	c.cookie = ck[0].Name + "=" + ck[0].Value
	c.csrf = out.CSRF
}

func TestServerModeRefusesUnsafeConfigs(t *testing.T) {
	svc := newSvc(t, fakeRunner(nil))
	if _, err := newServer(Options{Mode: Server, Service: svc}, "0.0.0.0:8053"); err == nil {
		t.Error("server mode without auth accepted")
	}
	if _, err := newServer(Options{Mode: Server, Service: svc, NoAuth: true}, "0.0.0.0:8053"); err == nil {
		t.Error("no-auth on all interfaces accepted")
	}
	if _, err := newServer(Options{Mode: Server, Service: svc, NoAuth: true}, "[::]:8053"); err == nil {
		t.Error("no-auth on all IPv6 interfaces accepted")
	}
	if _, err := newServer(Options{Mode: Server, Service: svc, NoAuth: true}, "127.0.0.1:8053"); err != nil {
		t.Errorf("explicit no-auth on loopback refused: %v", err)
	}
	if err := Serve(context.Background(), Options{Mode: Server, Service: svc, NoAuth: true, Listen: ":0"}); err == nil {
		t.Error("Serve with no-auth on :0 accepted")
	}
	if err := Serve(context.Background(), Options{Mode: Desktop, Service: svc, Listen: "0.0.0.0:0"}); err != ErrNotLoopback {
		t.Errorf("desktop on 0.0.0.0: %v", err)
	}
}

func TestServerAuthFlow(t *testing.T) {
	svc := newSvc(t, fakeRunner(nil))
	_, c := serverMode(t, svc, func(o *Options) { o.SecureCookies = true })
	// Public: page shell and health check. Nothing else.
	if r := c.do("GET", "/", nil, ""); r.Code != 200 || r.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("index: %d", r.Code)
	}
	if r := c.do("GET", "/healthz", map[string]string{}, ""); r.Code != 200 || strings.TrimSpace(r.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("healthz: %d %s", r.Code, r.Body)
	}
	for _, p := range []string{"/api/v1/info", "/api/v1/history", "/api/v1/report", "/api/v1/events", "/api/v1/schedule"} {
		if r := c.do("GET", p, nil, ""); r.Code != 401 {
			t.Errorf("%s without session: %d", p, r.Code)
		}
	}
	if r := c.do("POST", "/api/v1/login", nil, `{"password":"wrong password here"}`); r.Code != 401 {
		t.Fatalf("wrong password: %d", r.Code)
	}
	if r := c.do("POST", "/api/v1/login", map[string]string{"Origin": "http://evil.example"}, `{"password":"`+testPassword+`"}`); r.Code != 403 {
		t.Fatalf("cross-origin login: %d", r.Code)
	}
	if r := c.do("POST", "/api/v1/login", map[string]string{"Sec-Fetch-Site": "cross-site"}, `{"password":"`+testPassword+`"}`); r.Code != 403 {
		t.Fatalf("cross-site login: %d", r.Code)
	}
	r := c.do("POST", "/api/v1/login", nil, `{"password":"`+testPassword+`"}`)
	if !strings.Contains(r.Header().Get("Set-Cookie"), "Secure") {
		t.Errorf("Secure flag missing with SecureCookies: %s", r.Header().Get("Set-Cookie"))
	}
	login(t, c)
	var info infoResp
	if code := c.json("GET", "/api/v1/info", nil, &info); code != 200 || info.Auth != "password" || info.CSRF != c.csrf || info.DataDir != "" {
		t.Fatalf("info %d %+v", code, info)
	}
	csrf := c.csrf
	c.csrf = ""
	if r := c.do("POST", "/api/v1/scans", nil, `{"quick":true,"ipv4":true}`); r.Code != 403 {
		t.Fatalf("mutation without CSRF: %d", r.Code)
	}
	flip := "0"
	if csrf[0] == '0' {
		flip = "1"
	}
	c.csrf = flip + csrf[1:]
	if r := c.do("POST", "/api/v1/scans", nil, `{"quick":true,"ipv4":true}`); r.Code != 403 {
		t.Fatalf("mutation with wrong CSRF: %d", r.Code)
	}
	c.csrf = csrf
	if r := c.do("POST", "/api/v1/scans", nil, `{"quick":true,"ipv4":true,"bogus":1}`); r.Code != 400 {
		t.Fatalf("unknown field accepted: %d", r.Code)
	}
	if r := c.do("POST", "/api/v1/scans", nil, `{"quick":true,"ipv4":true}`); r.Code != 202 {
		t.Fatalf("start scan: %d %s", r.Code, r.Body)
	}
	if r := c.do("POST", "/api/v1/logout", nil, ""); r.Code != 200 {
		t.Fatalf("logout: %d", r.Code)
	}
	if r := c.do("GET", "/api/v1/info", nil, ""); r.Code != 401 {
		t.Fatalf("session valid after logout: %d", r.Code)
	}
}

func TestServerHostAllowList(t *testing.T) {
	svc := newSvc(t, fakeRunner(nil))
	_, c := serverMode(t, svc, nil)
	for host, ok := range map[string]bool{"192.168.1.20:8053": true, "[fd00::5]:8053": true, "localhost:8053": true,
		"sadns.home.arpa:8053": true, "SADNS.HOME.ARPA": true, "evil.example:8053": false, "tower.local:8053": false} {
		c.host = host
		r := c.do("GET", "/", nil, "")
		if (r.Code == 200) != ok {
			t.Errorf("host %s: %d", host, r.Code)
		}
	}
	_, any := serverMode(t, svc, func(o *Options) { o.AllowedHosts = []string{"*"} })
	any.host = "tower.local:8053"
	if r := any.do("GET", "/", nil, ""); r.Code != 200 {
		t.Errorf("wildcard allow-list: %d", r.Code)
	}
}

func TestLoginLockoutOverHTTP(t *testing.T) {
	_, c := serverMode(t, newSvc(t, fakeRunner(nil)), nil)
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/v1/login", nil, `{"password":"nope nope nope"}`)
	}
	r := c.do("POST", "/api/v1/login", nil, `{"password":"`+testPassword+`"}`)
	if r.Code != 429 || r.Header().Get("Retry-After") == "" {
		t.Fatalf("lockout: %d", r.Code)
	}
	if r := c.do("POST", "/api/v1/login", nil, strings.Repeat("x", 100<<10)); r.Code != 400 {
		t.Fatalf("oversized login body: %d", r.Code)
	}
}

func waitIdle(t *testing.T, svc *service.Service) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if svc.Current() == nil {
			if _, e := svc.Last(); e != nil {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
}

func TestNoSecretsInReports(t *testing.T) {
	svc := newSvc(t, fakeRunner(nil))
	_, c := serverMode(t, svc, nil)
	login(t, c)
	if code := c.json("POST", "/api/v1/scans", map[string]any{"quick": true, "ipv4": true}, nil); code != 202 {
		t.Fatal(code)
	}
	waitIdle(t, svc)
	sid := strings.SplitN(c.cookie, "=", 2)[1]
	for _, f := range []string{"md", "json"} {
		for _, p := range []string{"full", "technical", "public"} {
			r := c.do("GET", "/api/v1/report?format="+f+"&privacy="+p, nil, "")
			body := r.Body.String()
			if r.Code != 200 || strings.Contains(body, sid) || strings.Contains(body, c.csrf) || strings.Contains(body, testPassword) {
				t.Fatalf("%s/%s: code %d or secret leaked", f, p, r.Code)
			}
		}
	}
	// The stored copy on disk must not contain them either.
	rep, _ := svc.Store().History.Load(svc.Store().History.List()[0].ID)
	b, _ := json.Marshal(rep)
	if bytes.Contains(b, []byte(sid)) || bytes.Contains(b, []byte(testPassword)) {
		t.Fatal("secret in stored report")
	}
}

func TestHistoryAPI(t *testing.T) {
	svc := newSvc(t, fakeRunner(nil))
	_, c := desktop(t, svc)
	c.cookie, c.csrf = "sadns_1234=secret-token", "secret-token"
	for i := 0; i < 2; i++ {
		if code := c.json("POST", "/api/v1/scans", map[string]any{"quick": i == 0, "ipv4": true}, nil); code != 202 {
			t.Fatal(code)
		}
		waitIdle(t, svc)
		time.Sleep(1100 * time.Millisecond) // distinct second-resolution timestamps
	}
	var hist struct {
		Entries []store.Entry
		Retain  int
	}
	c.json("GET", "/api/v1/history", nil, &hist)
	if len(hist.Entries) != 2 || hist.Retain != 100 {
		t.Fatalf("history %+v", hist)
	}
	a, b := hist.Entries[1].ID, hist.Entries[0].ID
	var e store.Entry
	if code := c.json("POST", "/api/v1/history/"+a+"/pin", map[string]bool{"pinned": true}, &e); code != 200 || !e.Pinned {
		t.Fatalf("pin: %d %+v", code, e)
	}
	var cmp store.Comparison
	if code := c.json("GET", "/api/v1/history/compare?a="+b+"&b="+a, nil, &cmp); code != 200 || cmp.A.ID != a || len(cmp.Notes) == 0 {
		t.Fatalf("compare: %d %+v", code, cmp)
	}
	if r := c.do("GET", "/api/v1/report?id="+a+"&format=json&download=1", nil, ""); r.Code != 200 || !strings.Contains(r.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %d", r.Code)
	}
	for _, bad := range []string{"../../etc/passwd", "x", "20260101-000000-zzzzzz"} {
		if r := c.do("GET", "/api/v1/report?id="+bad, nil, ""); r.Code != 400 && r.Code != 404 {
			t.Errorf("bad id %q: %d", bad, r.Code)
		}
	}
	// Import: valid, not-a-report, oversized.
	good, _ := json.Marshal(model.Report{Schema: "sadns/report/v1", StartedAt: time.Now().Add(-48 * time.Hour), System: &sysinfo.Info{Hostname: "laptop"}})
	var imp store.Entry
	if code := c.json("POST", "/api/v1/history/import", json.RawMessage(good), &imp); code != 200 || imp.Source != "imported" || imp.Trigger != store.TriggerImported || imp.Host != "laptop" {
		t.Fatalf("import: %d %+v", code, imp)
	}
	if r := c.do("POST", "/api/v1/history/import", nil, `{"foo":1}`); r.Code != 400 {
		t.Errorf("non-report import: %d", r.Code)
	}
	if r := c.do("POST", "/api/v1/history/import", nil, `{"schema":"sadns/report/v1","x":"`+strings.Repeat("a", maxImportBody)+`"}`); r.Code != 413 {
		t.Errorf("oversized import: %d", r.Code)
	}
	var tr struct{ Points []TrendPoint }
	c.json("GET", "/api/v1/trends", nil, &tr)
	if len(tr.Points) != 2 || !tr.Points[0].StartedAt.Before(tr.Points[1].StartedAt) {
		t.Fatalf("trends should exclude imports and be oldest-first: %+v", tr.Points)
	}
	c.json("GET", "/api/v1/trends?imported=1", nil, &tr)
	if len(tr.Points) != 3 {
		t.Fatalf("trends with imports: %d", len(tr.Points))
	}
	var cl struct{ Removed int }
	if code := c.json("POST", "/api/v1/history/clear", map[string]bool{"include_pinned": false}, &cl); code != 200 || cl.Removed != 2 {
		t.Fatalf("clear: %d %+v", code, cl)
	}
	if r := c.do("DELETE", "/api/v1/history/"+a, nil, ""); r.Code != 200 {
		t.Fatalf("delete pinned: %d", r.Code)
	}
	if r := c.do("DELETE", "/api/v1/history/"+a, nil, ""); r.Code != 404 {
		t.Fatalf("double delete: %d", r.Code)
	}
}

func TestScheduleAndPreferencesAPI(t *testing.T) {
	release := make(chan struct{})
	svc := newSvc(t, fakeRunner(release))
	_, c := desktop(t, svc)
	c.cookie, c.csrf = "sadns_1234=secret-token", "secret-token"
	var v service.ScheduleView
	c.json("GET", "/api/v1/schedule", nil, &v)
	if v.Enabled || v.IntervalMinutes != 60 || v.Mode != "quick" || v.LowData || v.Retain != 100 || v.Status != "disabled" {
		t.Fatalf("defaults %+v", v)
	}
	if code := c.json("PUT", "/api/v1/schedule", map[string]any{"enabled": true, "interval_minutes": 2, "unit": "minutes", "mode": "quick"}, nil); code != 400 {
		t.Fatalf("2-minute interval: %d", code)
	}
	if code := c.json("PUT", "/api/v1/schedule", map[string]any{"enabled": true, "interval_minutes": 120, "unit": "hours", "mode": "full", "history_retain": 50}, &v); code != 200 || v.Status != "scheduled" || v.Retain != 50 || v.State.NextRunAt.IsZero() {
		t.Fatalf("enable: %d %+v", code, v)
	}
	if code := c.json("POST", "/api/v1/schedule/pause", nil, &v); code != 200 || v.Status != "paused" {
		t.Fatalf("pause: %d %+v", code, v)
	}
	if code := c.json("POST", "/api/v1/schedule/resume", nil, &v); code != 200 || v.Status != "scheduled" {
		t.Fatalf("resume: %d %+v", code, v)
	}
	if code := c.json("POST", "/api/v1/schedule/run-now", nil, nil); code != 202 {
		t.Fatalf("run-now: %d", code)
	}
	if code := c.json("POST", "/api/v1/schedule/run-now", nil, nil); code != 409 {
		t.Fatalf("overlapping run-now: %d", code)
	}
	if code := c.json("POST", "/api/v1/scans", map[string]any{"ipv4": true}, nil); code != 409 {
		t.Fatalf("overlapping manual scan: %d", code)
	}
	close(release)
	waitIdle(t, svc)
	if code := c.json("POST", "/api/v1/schedule/explode", nil, nil); code != 404 {
		t.Fatalf("unknown action: %d", code)
	}
	if code := c.json("PUT", "/api/v1/preferences", map[string]any{"urls": []string{"ftp://x"}, "ipv4": true}, nil); code != 400 {
		t.Fatalf("bad URL pref: %d", code)
	}
	var p store.ScanPrefs
	if code := c.json("PUT", "/api/v1/preferences", map[string]any{"urls": []string{"example.com"}, "extra_resolvers": []string{"9.9.9.9"}, "ipv4": true, "traceroute": true}, &p); code != 200 || len(p.URLs) != 1 || !strings.HasPrefix(p.URLs[0], "https://") {
		t.Fatalf("prefs: %d %+v", code, p)
	}
}

// Audit scenario: a UI scan with the real engine is cancelled while probes
// are active; partial results are saved.
func TestCancelRealScan(t *testing.T) {
	m, err := mockdns.Start(mockdns.Behavior{SlowFirst: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	svc := newSvc(t, nil)
	_, c := desktop(t, svc)
	c.cookie, c.csrf = "sadns_1234=secret-token", "secret-token"
	body, _ := json.Marshal(RunRequest{NoProviders: true, LowData: true, Extra: []string{m.Addr}, IPv4: true, IPv6: true, Samples: 1, TimeoutMS: 500})
	if r := c.do("POST", "/api/v1/scans", nil, string(body)); r.Code != 202 {
		t.Fatalf("run: %d %s", r.Code, r.Body)
	}
	time.Sleep(700 * time.Millisecond)
	start := time.Now()
	if r := c.do("POST", "/api/v1/scans/current/cancel", nil, ""); r.Code != 200 {
		t.Fatalf("cancel: %d", r.Code)
	}
	for time.Since(start) < 20*time.Second {
		rep, e := svc.Last()
		if svc.Current() == nil && rep != nil {
			if !rep.Options.LowData || rep.Data.Mode != "low-data" || rep.Data.ScanBudgetBytes == 0 {
				t.Fatalf("low_data not reflected in the report: %+v / %+v", rep.Options, rep.Data)
			}
			if !rep.Cancelled || rep.Summary.Verdict != "cancelled" {
				t.Fatalf("report not marked cancelled: %+v", rep.Summary)
			}
			if e == nil || e.Status != store.StatusCancelled {
				t.Fatalf("partial scan not saved as cancelled: %+v", e)
			}
			t.Logf("stopped %.1fs after cancel", time.Since(start).Seconds())
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("scan did not stop after cancel")
}

func TestEventsStream(t *testing.T) {
	svc := newSvc(t, fakeRunner(nil))
	s, _ := desktop(t, svc)
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/events", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Cookie", s.cookie+"=secret-token")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events: %d", resp.StatusCode)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = svc.Start(store.TriggerManual, probe.Config{IPv4: true})
	}()
	buf := make([]byte, 64<<10)
	var got string
	for !strings.Contains(got, `"type":"done"`) {
		n, err := resp.Body.Read(buf)
		if err != nil {
			t.Fatalf("stream ended: %v (%q)", err, got)
		}
		got += string(buf[:n])
	}
	for _, want := range []string{`"type":"hello"`, `"type":"start"`, `"type":"phase"`, `"entry":`} {
		if !strings.Contains(got, want) {
			t.Errorf("stream missing %s", want)
		}
	}
}
