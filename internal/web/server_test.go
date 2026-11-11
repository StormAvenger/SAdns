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

	"github.com/StormAvenger/SAdns/internal/mockdns"
	"github.com/StormAvenger/SAdns/internal/probe"
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

func newTestServer() (*server, *http.ServeMux, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &server{token: "secret-token", host: "127.0.0.1:1234", cookie: "sadns_1234", subs: map[chan probe.Event]struct{}{}, seen: time.Now(),
		opt: Options{Defaults: probe.Config{Timeout: 300 * time.Millisecond, Samples: 1, IPv4: true, IPv6: true}, Logf: func(string, ...any) {}}}
	return s, s.routes(ctx, cancel), cancel
}

func do(mux *http.ServeMux, method, url string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Host = "127.0.0.1:1234"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestGuard(t *testing.T) {
	_, mux, cancel := newTestServer()
	defer cancel()
	if r := do(mux, "GET", "/", nil, ""); r.Code != 403 {
		t.Fatalf("no token: %d", r.Code)
	}
	r := do(mux, "GET", "/?token=secret-token", nil, "")
	if r.Code != 200 || !strings.Contains(r.Header().Get("Set-Cookie"), "HttpOnly") || !strings.Contains(r.Header().Get("Set-Cookie"), "SameSite=Strict") {
		t.Fatalf("index: %d cookie=%q", r.Code, r.Header().Get("Set-Cookie"))
	}
	cookie := map[string]string{"Cookie": "sadns_1234=secret-token"}
	if r := do(mux, "GET", "/api/info", cookie, ""); r.Code != 200 {
		t.Fatalf("api with cookie: %d", r.Code)
	}
	if r := do(mux, "GET", "/api/info?token=secret-token", nil, ""); r.Code != 403 {
		t.Fatalf("API must not accept the token in the URL: %d", r.Code)
	}
	if r := do(mux, "POST", "/api/cancel", cookie, ""); r.Code != 403 {
		t.Fatalf("POST without CSRF header accepted: %d", r.Code)
	}
	req := httptest.NewRequest("GET", "/api/info", nil)
	req.Host = "evil.example:1234" // DNS rebinding attempt
	req.Header.Set("Cookie", "sadns_1234=secret-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("foreign Host accepted: %d", rec.Code)
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

// Audit scenario: a UI scan is cancelled while probes are active.
func TestCancelRun(t *testing.T) {
	m, err := mockdns.Start(mockdns.Behavior{SlowFirst: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s, mux, cancel := newTestServer()
	defer cancel()
	hdr := map[string]string{"Cookie": "sadns_1234=secret-token", "X-SAdns-Token": "secret-token"}
	body, _ := json.Marshal(runReq{NoProviders: true, LowData: true, Extra: []string{m.Addr}, IPv4: true, IPv6: true, Samples: 1, TimeoutMS: 500})
	if r := do(mux, "POST", "/api/run", hdr, string(body)); r.Code != 200 {
		t.Fatalf("run: %d %s", r.Code, r.Body)
	}
	time.Sleep(700 * time.Millisecond)
	start := time.Now()
	if r := do(mux, "POST", "/api/cancel", hdr, ""); r.Code != 200 {
		t.Fatalf("cancel: %d", r.Code)
	}
	for time.Since(start) < 20*time.Second {
		s.mu.Lock()
		done, rep := !s.running, s.rep
		s.mu.Unlock()
		if done && rep != nil {
			if !rep.Options.LowData || rep.Data.Mode != "low-data" || rep.Data.ScanBudgetBytes == 0 {
				t.Fatalf("low_data not reflected in the report: %+v / %+v", rep.Options, rep.Data)
			}
			if !rep.Cancelled || rep.Summary.Verdict != "cancelled" {
				t.Fatalf("report not marked cancelled: %+v", rep.Summary)
			}
			t.Logf("stopped %.1fs after cancel", time.Since(start).Seconds())
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("scan did not stop after cancel")
}
