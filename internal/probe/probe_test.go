package probe

import (
	"context"
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
	r := runMock(t, mockdns.Behavior{Caching: true})
	for _, id := range []string{"case_0x20", "edns_version", "cookie", "https_rr", "burst", "cache"} {
		if s := status(r, id); s != model.Pass {
			t.Errorf("%s = %s (%s)", id, s, r.Test(id).Detail)
		}
	}
	if r.Case0x20 != "preserved" || r.Cookies != "yes" || r.Rebind != "off" || r.Caching != "yes" ||
		r.CanaryDoH != "allows-doh" || r.CanaryRelay != "allows-relay" || len(r.DDR) != 0 {
		t.Errorf("unexpected: %+v", r)
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
		t.Errorf("rebind=%s doh=%s relay=%s ddr=%v", r.Rebind, r.CanaryDoH, r.CanaryRelay, r.DDR)
	}
	if r.Caching != "no" {
		t.Errorf("caching=%s", r.Caching)
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
