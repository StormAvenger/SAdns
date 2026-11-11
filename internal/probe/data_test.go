package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/StormAvenger/SAdns/internal/model"
)

func TestDataPolicyDefaults(t *testing.T) {
	std := NewDataPolicy(false, false)
	if std.LowData || std.WebSamples != 3 || std.CustomBodyLimit != 20*mib || std.ScanBodyBudget != 0 {
		t.Fatalf("standard must stay full quality: %+v", std)
	}
	low := NewDataPolicy(true, false)
	if !low.LowData || low.WebSamples != 1 || low.BaselineBodyLimit != 512*kib || low.CustomBodyLimit != 512*kib || low.ScanBodyBudget != 10*mib {
		t.Fatalf("low data: %+v", low)
	}
	if e := New(Config{}, nil); e.pol.LowData || e.dataUsage().Mode != "standard" {
		t.Fatal("default engine must be Standard / High Data")
	}
	if d := New(Config{LowData: true}, nil).dataUsage(); d.Mode != "low-data" || !d.ConfidenceAffected || d.ScanBudgetBytes != 10*mib {
		t.Fatalf("%+v", d)
	}
}

func TestMeterNeverOverBudgetConcurrently(t *testing.T) {
	m := &dataMeter{budget: 1000}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := m.reserve(100)
			m.settle(g, g) // every goroutine uses all it was granted
			mu.Lock()
			total += g
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 1000 || m.used != 1000 || m.reserved != 0 || !m.exhausted() {
		t.Fatalf("granted %d used %d reserved %d", total, m.used, m.reserved)
	}
}

func dataServer() *httptest.Server {
	big := bytes.Repeat([]byte("x"), 1<<20)
	mux := http.NewServeMux()
	sized := func(b []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.Write(b)
		}
	}
	mux.HandleFunc("/big", sized(big)) // declared size: 1 MiB
	mux.HandleFunc("/exact", sized(big[:512<<10]))
	chunked := func(n int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for sent := 0; sent < n; sent += 64 << 10 {
				w.Write(big[:64<<10])
				w.(http.Flusher).Flush() // forces chunked encoding: no Content-Length
			}
		}
	}
	mux.HandleFunc("/chunked-small", chunked(128<<10))
	mux.HandleFunc("/chunked-big", chunked(1<<20))
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		z.Write(big)
		z.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(b.Len()))
		w.Write(b.Bytes())
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/big", http.StatusFound) })
	mux.HandleFunc("/cut", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.Write(big[:1000])
		w.(http.Flusher).Flush()
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	})
	return httptest.NewServer(mux)
}

// Reaching the sample limit is neither an error nor a verified full download.
func TestDownloadOutcomes(t *testing.T) {
	srv := dataServer()
	defer srv.Close()
	ctx := context.Background()
	cases := []struct {
		path    string
		outcome string
		ok      bool
		bytes   int64
	}{
		{"/big", model.OutcomeSampled, true, 512 << 10},            // large resource, known size
		{"/exact", model.OutcomeVerified, true, 512 << 10},         // exactly the limit is still complete
		{"/chunked-small", model.OutcomeComplete, true, 128 << 10}, // unknown size, ended cleanly
		{"/chunked-big", model.OutcomeSampled, true, 512 << 10},    // unknown size, more remained
		{"/cut", model.OutcomeFailed, false, 1000},                 // interrupted
	}
	for _, c := range cases {
		e := newTestEngine()
		w := e.fetchFollow(ctx, srv.URL+c.path, 4, false)
		if w.Outcome != c.outcome || w.OK != c.ok || w.Bytes != c.bytes || !w.Reachable {
			t.Errorf("%s: outcome=%s ok=%v bytes=%d err=%q", c.path, w.Outcome, w.OK, w.Bytes, w.Error)
		}
		if c.outcome == model.OutcomeSampled && (w.Error != "" || !w.HTTPOK) {
			t.Errorf("%s: a deliberate sample must not be an error: %+v", c.path, w)
		}
		if e.meter.used != c.bytes {
			t.Errorf("%s: meter counted %d, want %d", c.path, e.meter.used, c.bytes)
		}
	}
	// Compressed content: bytes are counted as transferred and verified against Content-Length.
	e := newTestEngine()
	w := e.fetchFollow(ctx, srv.URL+"/gzip", 4, false)
	if w.Outcome != model.OutcomeVerified || w.ContentEncoding != "gzip" || w.Bytes != w.ContentLength || w.Bytes > 64<<10 {
		t.Errorf("gzip: %+v", w)
	}
	// Redirect: both requests are counted, the redirect body is not downloaded.
	e = newTestEngine()
	w = e.fetchFollow(ctx, srv.URL+"/redir", 4, false)
	if w.Redirects != 1 || w.Outcome != model.OutcomeSampled || e.meter.requests != 2 || e.meter.used != 512<<10 {
		t.Errorf("redirect: %+v requests=%d used=%d", w, e.meter.requests, e.meter.used)
	}
	// User-specified URLs get the larger standard limit and complete the 1 MiB file.
	e = newTestEngine()
	if w = e.fetchFollow(ctx, srv.URL+"/big", 4, true); w.Outcome != model.OutcomeVerified || w.Bytes != 1<<20 {
		t.Errorf("custom: %+v", w)
	}
}

// Many concurrent downloads must not jointly exceed the scan budget, and
// requests that lose out are budget-limited, not network failures.
func TestScanBudgetUnderConcurrency(t *testing.T) {
	srv := dataServer()
	defer srv.Close()
	e := New(Config{LowData: true, IPv4: true}, nil)
	const budget = 2 * 512 << 10 // room for two full samples
	e.pol.ScanBodyBudget, e.meter.budget = budget, budget
	var wg sync.WaitGroup
	out := make([]model.WebTiming, 12)
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = e.fetchFollow(context.Background(), srv.URL+"/big", 4, false)
			e.meter.mark(out[i].Outcome)
		}()
	}
	wg.Wait()
	var sampled, limited int
	for _, w := range out {
		switch w.Outcome {
		case model.OutcomeSampled:
			sampled++
		case model.OutcomeBudget:
			limited++
			if w.OK || w.Error != "" {
				t.Errorf("budget-limited must be neither success nor error: %+v", w)
			}
		default:
			t.Errorf("unexpected outcome %s (%s)", w.Outcome, w.Error)
		}
	}
	if e.meter.used > budget || e.meter.reserved != 0 {
		t.Fatalf("budget exceeded: used %d of %d (reserved %d)", e.meter.used, budget, e.meter.reserved)
	}
	if sampled < 1 || limited < 1 || e.dataUsage().BudgetLimited != limited {
		t.Fatalf("sampled=%d limited=%d usage=%+v", sampled, limited, e.dataUsage())
	}
}

// Low Data Mode: one run per family; standard: three. Budget-limited rows are not failures.
func TestWebLoadSampleCounts(t *testing.T) {
	srv := dataServer()
	defer srv.Close()
	conn := model.Connectivity{IPv4: model.FamilyConn{Working: true}}
	for low, want := range map[bool]int{false: 3, true: 1} {
		e := New(Config{LowData: low, IPv4: true}, nil)
		rows := e.webLoad(context.Background(), srv.URL+"/exact", true, conn)
		if len(rows) != 1 || rows[0].Runs != want || !rows[0].OK {
			t.Fatalf("low=%v: %+v", low, rows)
		}
	}
	e := New(Config{LowData: true, IPv4: true}, nil)
	e.meter.budget, e.meter.used = 100, 100 // already exhausted
	rows := e.webLoad(context.Background(), srv.URL+"/exact", true, conn)
	if len(rows) != 1 || rows[0].OK || rows[0].FailedRuns != 0 || rows[0].LimitedRuns != 1 || rows[0].Error != "" || e.meter.requests != 0 {
		t.Fatalf("exhausted budget: %+v (requests %d)", rows, e.meter.requests)
	}
}
