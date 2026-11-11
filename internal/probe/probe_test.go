package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/StormAvenger/SAdns/internal/mockdns"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

func newTestEngine() *Engine {
	e := New(Config{Samples: 3, Timeout: 500 * time.Millisecond, IPv4: true, IPv6: true}, nil)
	e.sys = &sysinfo.Info{ResolverOptions: map[string]string{}}
	return e
}

func runMock(t *testing.T, b mockdns.Behavior) model.ResolverResult {
	t.Helper()
	s, err := mockdns.Start(b)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := newTestEngine()
	return e.runResolver(context.Background(), target{label: "mock", role: "custom", addr: netip.MustParseAddrPort(s.Addr)})
}

func status(r model.ResolverResult, id string) string {
	if t := r.Test(id); t != nil {
		return t.Status
	}
	return "missing"
}

func TestHealthyValidatingResolver(t *testing.T) {
	r := runMock(t, mockdns.Behavior{Validating: true, Version: "dnsmasq-2.90", Egress: "203.0.113.7"})
	if !r.Reachable {
		t.Fatal("not reachable")
	}
	for _, id := range []string{"udp_a", "tcp", "udp_aaaa", "edns", "tc_fallback", "edns_large", "dnssec", "nxdomain"} {
		if s := status(r, id); s != model.Pass {
			t.Errorf("%s = %s (%s)", id, s, r.Test(id).Detail)
		}
	}
	if r.DNSSEC != "validating" || r.NXDOMAIN != "correct" || r.Filtering != "no-ad-blocking" {
		t.Errorf("dnssec=%s nx=%s filter=%s", r.DNSSEC, r.NXDOMAIN, r.Filtering)
	}
	if r.Identity["nsid"] != "mock-1" || r.Identity["version.bind"] != "dnsmasq-2.90" || r.Software == "" {
		t.Errorf("identity %+v software %q", r.Identity, r.Software)
	}
	if r.Egress.IP != "203.0.113.7" {
		t.Errorf("egress %+v", r.Egress)
	}
	if r.Latency.Received != 3 || r.Latency.LossPct != 0 {
		t.Errorf("latency %+v", r.Latency)
	}
	if tc := r.Test("tc_fallback"); tc.Size == 0 || tc.Size > 512 {
		t.Errorf("tc size %d", tc.Size)
	}
}

func TestBrokenResolver(t *testing.T) {
	r := runMock(t, mockdns.Behavior{HijackNX: true, Filtering: true, NoTCP: true, DropLargeUDP: true})
	if !r.Reachable {
		t.Fatal("not reachable")
	}
	want := map[string]string{"tcp": model.Warn, "tc_fallback": model.Fail, "edns_large": model.Warn, "nxdomain": model.Warn, "dnssec": model.Info}
	for id, w := range want {
		if s := status(r, id); s != w {
			t.Errorf("%s = %s, want %s (%s)", id, s, w, r.Test(id).Detail)
		}
	}
	if r.NXDOMAIN != "hijacked" || r.Filtering != "blocks-ads" || r.DNSSEC != "not-validating" {
		t.Errorf("nx=%s filter=%s dnssec=%s", r.NXDOMAIN, r.Filtering, r.DNSSEC)
	}
}

func TestUnreachableResolver(t *testing.T) {
	// Grab a free UDP port and close it so nothing answers.
	s, _ := mockdns.Start(mockdns.Behavior{NoTCP: true})
	addr := s.Addr
	s.Close()
	e := newTestEngine()
	r := e.runResolver(context.Background(), target{label: "dead", role: "system", addr: netip.MustParseAddrPort(addr)})
	if r.Reachable {
		t.Fatal("dead resolver reported reachable")
	}
	if status(r, "udp_a") != model.Fail || status(r, "dnssec") != model.Skip {
		t.Fatalf("udp_a=%s dnssec=%s", status(r, "udp_a"), status(r, "dnssec"))
	}
}

func TestNoEDNS(t *testing.T) {
	r := runMock(t, mockdns.Behavior{NoEDNS: true})
	if status(r, "edns") != model.Warn {
		t.Fatalf("edns = %s", status(r, "edns"))
	}
}

func TestParseTrace(t *testing.T) {
	linux := `traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms
 2  *
 3  100.64.0.1  9.81 ms
 4  1.1.1.1  12.3 ms`
	h := parseTrace(linux)
	if len(h) != 4 || h[0].Scope != "private" || !h[1].Timeout || h[2].Scope != "cgnat" || h[3].Addr != "1.1.1.1" || h[3].RTTMS != 12.3 {
		t.Fatalf("linux parse: %+v", h)
	}
	win := `Tracing route to 1.1.1.1 over a maximum of 20 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    11 ms    10 ms    12 ms  1.1.1.1

Trace complete.`
	h = parseTrace(win)
	if len(h) != 3 || h[0].Addr != "192.168.1.1" || h[0].RTTMS != 1 || !h[1].Timeout || h[2].Addr != "1.1.1.1" {
		t.Fatalf("windows parse: %+v", h)
	}
	tp := ` 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1                                           0.433ms
 2:  2001:db8::1                                          8.1ms`
	h = parseTrace(tp)
	if len(h) != 2 || h[0].Addr != "192.168.1.1" || h[1].Addr != "2001:db8::1" {
		t.Fatalf("tracepath parse: %+v", h)
	}
}

func TestStats(t *testing.T) {
	l := stats(5, []float64{10, 12, 11, 30})
	if l.Received != 4 || l.LossPct != 20 || l.MinMS != 10 || l.MaxMS != 30 || l.MedianMS != 11.5 || l.P90MS != 30 {
		t.Fatalf("%+v", l)
	}
}

func TestExtraHealthy(t *testing.T) {
	r := runMock(t, mockdns.Behavior{Validating: true, SlowFirst: 30 * time.Millisecond})
	for _, id := range []string{"case_0x20", "edns_version", "cookie", "https_rr", "burst", "cache", "dnssec"} {
		if s := status(r, id); s != model.Pass {
			t.Errorf("%s = %s (%s)", id, s, r.Test(id).Detail)
		}
	}
	if r.Case0x20 != "preserved" || r.Cookies != "yes" || r.Rebind != "off" || r.Caching != "local-cache" || r.HTTPSRR != "records" ||
		r.CanaryDoH != "allows-doh" || r.CanaryRelay != "allows-relay" || len(r.DDR) != 0 || r.DNSSECConfidence != "confirmed" {
		t.Errorf("unexpected: cookies=%s rebind=%s caching=%s https=%s dnssec=%s/%s", r.Cookies, r.Rebind, r.Caching, r.HTTPSRR, r.DNSSEC, r.DNSSECConfidence)
	}
	if r.ColdMS < 25 {
		t.Errorf("uncached median %.1f ms should reflect the 30 ms recursion delay", r.ColdMS)
	}
}

func TestExtraQuirky(t *testing.T) {
	r := runMock(t, mockdns.Behavior{Lowercase: true, BadHTTPS: true, RebindProtect: true, Canaries: true, RateLimit: 8})
	for id, want := range map[string]string{"case_0x20": model.Warn, "https_rr": model.Warn, "burst": model.Warn} {
		if s := status(r, id); s != want {
			t.Errorf("%s = %s want %s (%s)", id, s, want, r.Test(id).Detail)
		}
	}
	if r.Rebind != "on" || r.CanaryDoH != "disables-doh" || r.CanaryRelay != "blocks-relay" {
		t.Errorf("rebind=%s doh=%s relay=%s", r.Rebind, r.CanaryDoH, r.CanaryRelay)
	}
}

// Audit scenario: a resolver with no cache forwarding to an upstream that caches.
func TestCacheClassification(t *testing.T) {
	cases := []struct {
		b    mockdns.Behavior
		want string
	}{
		{mockdns.Behavior{SlowFirst: 40 * time.Millisecond}, "local-cache"},
		{mockdns.Behavior{SlowFirst: 45 * time.Millisecond, SlowRepeat: 15 * time.Millisecond}, "upstream-cache"},
		{mockdns.Behavior{SlowFirst: 30 * time.Millisecond, SlowRepeat: 30 * time.Millisecond}, "no-cache"},
		{mockdns.Behavior{NoWildcard: true}, "unknown"},
	}
	for _, c := range cases {
		r := runMock(t, c.b)
		if r.Caching != c.want {
			t.Errorf("%+v: caching=%s want %s (%s)", c.b, r.Caching, c.want, r.Test("cache").Detail)
		}
	}
}

// Audit scenario: SERVFAIL for the bogus zone because the whole upstream is broken.
func TestDNSSECBrokenUpstreamIsInconclusive(t *testing.T) {
	r := runMock(t, mockdns.Behavior{BrokenUpstream: true})
	if r.DNSSEC != "inconclusive" || status(r, "dnssec") == model.Pass {
		t.Fatalf("dnssec=%s status=%s (%s)", r.DNSSEC, status(r, "dnssec"), r.Test("dnssec").Detail)
	}
}

func TestRebindInconclusiveWithoutControl(t *testing.T) {
	r := runMock(t, mockdns.Behavior{NoWildcard: true, RebindProtect: true})
	if r.Rebind != "unknown" {
		t.Fatalf("rebind=%s (%s)", r.Rebind, r.Test("rebind").Detail)
	}
}

func TestStrippedHTTPSRecords(t *testing.T) {
	r := runMock(t, mockdns.Behavior{StripHTTPS: true})
	if r.HTTPSRR != "empty" || status(r, "https_rr") == model.Pass {
		t.Fatalf("https=%s status=%s", r.HTTPSRR, status(r, "https_rr"))
	}
}

func TestDDR(t *testing.T) {
	r := runMock(t, mockdns.Behavior{DDR: true})
	if len(r.DDR) != 1 || r.DDR[0] != "dns.google." {
		t.Fatalf("ddr=%v (%s)", r.DDR, r.Test("ddr").Detail)
	}
}

func TestParsePing(t *testing.T) {
	linux := `PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=11.2 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=12.8 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 402ms
rtt min/avg/max/mdev = 11.2/12.0/12.8/0.8 ms`
	if r := parsePing(linux, "1.1.1.1"); len(r) != 2 || r[0] != 11.2 {
		t.Fatalf("linux %v", r)
	}
	win := "Pinging 1.1.1.1 with 32 bytes of data:\r\nReply from 1.1.1.1: bytes=32 time<1ms TTL=57\r\nReply from 1.1.1.1: bytes=32 time=14ms TTL=57\r\nRequest timed out.\r\n\r\nPing statistics for 1.1.1.1:\r\n    Packets: Sent = 3, Received = 2, Lost = 1 (33% loss),\r\nApproximate round trip times in milli-seconds:\r\n    Minimum = 0ms, Maximum = 14ms, Average = 7ms"
	if r := parsePing(win, "1.1.1.1"); len(r) != 2 || r[1] != 14 {
		t.Fatalf("windows %v", r)
	}
	de := "Antwort von 1.1.1.1: Bytes=32 Zeit=9ms TTL=57"
	if r := parsePing(de, "1.1.1.1"); len(r) != 1 || r[0] != 9 {
		t.Fatalf("german %v", r)
	}
	v6 := "64 bytes from 2606:4700:4700::1111: icmp_seq=1 ttl=57 time=10.1 ms"
	if r := parsePing(v6, "2606:4700:4700::1111"); len(r) != 1 {
		t.Fatalf("v6 %v", r)
	}
}

func TestNTPTimestamps(t *testing.T) {
	now := time.Now()
	b := make([]byte, 8)
	putNTPTime(b, now)
	if d := ntpTime(b).Sub(now); d > time.Microsecond || d < -time.Microsecond {
		t.Fatalf("round trip off by %v", d)
	}
}

func TestEvalFamilies(t *testing.T) {
	cases := []struct {
		exp     string
		v4, v6  bool
		ok      bool
		missing string
	}{
		{"v4+v6", true, true, true, ""},
		{"v4+v6", true, false, false, "AAAA"}, // audit scenario: IPv4 resolves, AAAA absent
		{"v4", true, false, true, ""},
		{"v6", true, false, false, "AAAA"},
		{"nxdomain", true, false, false, ""},
	}
	for _, c := range cases {
		ok, miss := evalFamilies(c.exp, c.v4, c.v6)
		if ok != c.ok || miss != c.missing {
			t.Errorf("%s v4=%v v6=%v: got %v %q", c.exp, c.v4, c.v6, ok, miss)
		}
	}
}

func TestParseCymru(t *testing.T) {
	for in, want := range map[string]string{
		"13335 | 172.68.0.0/16 | US | arin | 2014-03-28": "13335",
		"15169 36040 | 8.8.8.0/24 | US | arin | x":       "15169",
		"":                   "", // audit scenario: empty TXT must not panic
		"   ":                "",
		"|||":                "",
		"AS13335 | x":        "",
		"<script> | evil":    "",
		"99999999999999 | x": "",
	} {
		got, ok := parseCymruOrigin(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q %v", in, got, ok)
		}
	}
}

func TestTargetsKeepProviderForSystemResolver(t *testing.T) {
	e := New(Config{IPv4: true, IPv6: true}, nil)
	e.sys = &sysinfo.Info{Resolvers: []sysinfo.Resolver{{Addr: "1.1.1.1"}}}
	ts := e.targets(model.Connectivity{IPv4: model.FamilyConn{Working: true}, IPv6: model.FamilyConn{Working: true}})
	var found *target
	n := 0
	for i := range ts {
		if ts[i].addr.String() == "1.1.1.1:53" {
			found = &ts[i]
			n++
		}
	}
	if n != 1 || found == nil {
		t.Fatalf("1.1.1.1 tested %d times", n)
	}
	if found.role != "system" || found.prov == nil || found.prov.Key != "cloudflare" {
		t.Fatalf("lost classification: role=%s prov=%v", found.role, found.prov)
	}
}

// Audit scenario: DNS64 with a prefix length other than /96.
func TestNAT64Prefixes(t *testing.T) {
	cases := map[string]string{
		"64:ff9b::c000:aa":             "64:ff9b::/96", // well-known prefix
		"2001:db8:c000:aa::":           "2001:db8::/32",
		"2001:db8:100:c000:00:aa00::":  "2001:db8:100::/48",
		"2001:db8:122:344:c0:0:aa00:0": "2001:db8:122:344::/64",
	}
	for in, want := range cases {
		p, ok := nat64Prefix(netip.MustParseAddr(in))
		if !ok || p.String() != want {
			t.Errorf("%s: got %v %v want %s", in, p, ok, want)
		}
	}
	if _, ok := nat64Prefix(netip.MustParseAddr("2606:4700::1")); ok {
		t.Error("ordinary address detected as NAT64")
	}
}

func TestPingSequenceOrder(t *testing.T) {
	linux := "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=11 ms\n64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=13 ms\n"
	got := pingSequence(linux, "1.1.1.1", 3)
	if len(got) != 3 || got[0] != 11 || got[1] != -1 || got[2] != 13 {
		t.Fatalf("linux order: %v", got)
	}
	win := "\r\nPinging 1.1.1.1 with 32 bytes of data:\r\nRequest timed out.\r\nReply from 1.1.1.1: bytes=32 time=14ms TTL=57\r\nReply from 1.1.1.1: bytes=32 time<1ms TTL=57\r\n\r\nPing statistics for 1.1.1.1:\r\n"
	got = pingSequence(win, "1.1.1.1", 3)
	if len(got) != 3 || got[0] != -1 || got[1] != 14 || got[2] != 1 {
		t.Fatalf("windows order: %v", got)
	}
}

func TestValidateNTP(t *testing.T) {
	req := make([]byte, 48)
	req[0] = 0x23
	putNTPTime(req[40:], time.Now())
	good := func() []byte {
		b := make([]byte, 48)
		b[0] = 0x24 // LI 0, VN 4, mode 4
		b[1] = 2
		copy(b[24:32], req[40:48])
		putNTPTime(b[32:], time.Now())
		putNTPTime(b[40:], time.Now())
		return b
	}
	if err := validateNTP(req, good()); err != nil {
		t.Fatalf("good reply rejected: %v", err)
	}
	for name, mut := range map[string]func([]byte){
		"client mode":    func(b []byte) { b[0] = 0x23 },
		"unsynchronised": func(b []byte) { b[0] = 0xE4 },
		"kiss of death":  func(b []byte) { b[1] = 0 },
		"bad stratum":    func(b []byte) { b[1] = 16 },
		"wrong origin":   func(b []byte) { b[24]++ },
		"zero transmit":  func(b []byte) { copy(b[40:48], make([]byte, 8)) },
	} {
		b := good()
		mut(b)
		if validateNTP(req, b) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestWebFetchSemantics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusServiceUnavailable) })
	mux.HandleFunc("/cut", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	e := newTestEngine()
	ctx := context.Background()

	w := e.fetchFollow(ctx, srv.URL+"/ok", 4, false)
	if !w.OK || w.Status != 200 || w.TTFBMS < 55 || w.Bytes != 2 || w.ElapsedMS < w.TTFBMS {
		t.Fatalf("ok: %+v", w)
	}
	// A redirect is followed and reported; it is not itself a successful load.
	w = e.fetchFollow(ctx, srv.URL+"/redir", 4, false)
	if !w.OK || w.Redirects != 1 || w.Status != 200 || w.FinalURL != srv.URL+"/ok" {
		t.Fatalf("redirect: %+v", w)
	}
	if w = e.fetchFollow(ctx, srv.URL+"/loop", 4, false); w.OK || w.Error == "" {
		t.Fatalf("redirect loop accepted: %+v", w)
	}
	if w = e.fetchFollow(ctx, srv.URL+"/gone", 4, false); w.OK || w.Error != "HTTP 503" {
		t.Fatalf("error status accepted: %+v", w)
	}
	// Audit scenario: an incomplete download must not count as success.
	if w = e.fetchFollow(ctx, srv.URL+"/cut", 4, false); w.OK || w.Error == "" {
		t.Fatalf("incomplete body accepted: %+v", w)
	}
}

func TestSummarizeRuns(t *testing.T) {
	w := summarizeRuns([]model.WebTiming{{OK: true, ElapsedMS: 30, TLSMS: 3}, {OK: true, ElapsedMS: 10, TLSMS: 1}, {OK: true, ElapsedMS: 20, TLSMS: 2}})
	if !w.OK || w.Runs != 3 || w.ElapsedMS != 20 || w.TLSMS != 2 || w.MinElapsedMS != 10 || w.MaxElapsedMS != 30 || len(w.RunTotalsMS) != 3 {
		t.Fatalf("%+v", w)
	}
	w = summarizeRuns([]model.WebTiming{{OK: true, ElapsedMS: 10}, {Error: "boom"}})
	if w.OK || w.OKRuns != 1 || w.Error == "" {
		t.Fatalf("flaky run reported healthy: %+v", w)
	}
}

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{"reddit.com": "https://reddit.com", "http://a.example/x.png": "http://a.example/x.png",
		"ftp://x": "", "https://user:pw@x.example/": "", "": "", "file:///etc/passwd": ""} {
		got, err := NormalizeURL(in)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
}

// Audit: deselecting every public provider must test none, not all.
func TestNoProvidersMeansNone(t *testing.T) {
	conn := model.Connectivity{IPv4: model.FamilyConn{Working: true}, IPv6: model.FamilyConn{Working: true}}
	e := New(Config{IPv4: true, IPv6: true, NoProviders: true}, nil)
	e.sys = &sysinfo.Info{Resolvers: []sysinfo.Resolver{{Addr: "192.168.1.1"}}}
	if ts := e.targets(conn); len(ts) != 1 {
		t.Fatalf("got %d targets", len(ts))
	}
	e = New(Config{IPv4: true, IPv6: true}, nil)
	e.sys = &sysinfo.Info{}
	if ts := e.targets(conn); len(ts) < 20 {
		t.Fatalf("default should be the full catalog, got %d", len(ts))
	}
}

// Audit: a cookie must be maintained on the follow-up, not just issued once.
func TestCookieNotMaintained(t *testing.T) {
	r := runMock(t, mockdns.Behavior{CookieOnce: true})
	if r.Cookies != "partial" || status(r, "cookie") == model.Pass {
		t.Fatalf("cookies=%s (%s)", r.Cookies, r.Test("cookie").Detail)
	}
}
