package analyze

import (
	"strings"
	"testing"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

func has(r *model.Report, id, sev string) bool {
	for _, f := range r.Findings {
		if f.ID == id && f.Severity == sev {
			return true
		}
	}
	return false
}

func res(label, role, addr string, fam int, reach bool, tests ...model.TestResult) model.ResolverResult {
	return model.ResolverResult{Label: label, Role: role, Addr: addr, Family: fam, Reachable: reach, Tests: tests, DNSSEC: "validating", Filtering: "no-ad-blocking", NXDOMAIN: "correct",
		Latency: model.Latency{Sent: 5, Received: 5, MedianMS: 3}}
}

var ok = model.TestResult{ID: "udp_a", Status: model.Pass}

func baseReport() *model.Report {
	return &model.Report{
		System: &sysinfo.Info{ResolverOptions: map[string]string{}},
		Connectivity: model.Connectivity{
			IPv4: model.FamilyConn{HasAddress: true, HasGlobal: true, HasGateway: true, Working: true},
			IPv6: model.FamilyConn{HasAddress: true, HasGlobal: true, HasGateway: true, Working: true},
		},
	}
}

// The classic UniFi-style failure: IPv6 RDNSS advertised but dead, IPv4 DNS fine.
func TestDeadIPv6RDNSS(t *testing.T) {
	r := baseReport()
	r.Resolvers = []model.ResolverResult{
		res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok),
		res("System DNS #2", "system", "[fd00::1]:53", 6, false, model.TestResult{ID: "udp_a", Status: model.Fail}),
	}
	Run(r)
	if !has(r, "SYS-V6-DNS-DOWN", model.Fail) {
		t.Fatalf("missing SYS-V6-DNS-DOWN: %+v", r.Findings)
	}
	if r.Summary.Verdict != "problems" {
		t.Fatal(r.Summary)
	}
}

func TestBrokenIPv6AndMixedResolvers(t *testing.T) {
	r := baseReport()
	r.Connectivity.IPv6.Working = false
	a := res("System DNS #1", "system", "192.168.1.2:53", 4, true, ok)
	a.Filtering = "blocks-ads"
	b := res("System DNS #2", "system", "8.8.8.8:53", 4, true, ok)
	r.Resolvers = []model.ResolverResult{a, b}
	Run(r)
	for _, id := range []string{"CONN-V6-BROKEN"} {
		if !has(r, id, model.Fail) {
			t.Errorf("missing fail %s", id)
		}
	}
	for _, id := range []string{"SYS-MIXED", "SYS-FILTER-MIX"} {
		if !has(r, id, model.Warn) {
			t.Errorf("missing warn %s", id)
		}
	}
	if !strings.Contains(r.Summary.Headline, "IPv6") {
		t.Errorf("headline should lead with the IPv6 root cause, got %q", r.Summary.Headline)
	}
}

// An egress-ASN mismatch alone is an indicator, not proof (audit finding).
func TestInterceptionByEgressIsOnlySuspected(t *testing.T) {
	r := baseReport()
	sys := res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok)
	cf := res("Cloudflare primary IPv4", "public", "1.1.1.1:53", 4, true, ok)
	cf.ProviderKey = "cloudflare"
	cf.Egress = model.Egress{IP: "73.1.2.3", ASN: "7922", ASName: "COMCAST", Matches: "no"}
	r.Resolvers = []model.ResolverResult{sys, cf}
	Run(r)
	if !has(r, "INTERCEPT-SUSPECTED", model.Warn) || has(r, "INTERCEPT-PUBLIC", model.Fail) {
		t.Fatalf("want suspected only: %+v", r.Findings)
	}
}

func TestInterceptionConfirmedByIndependentIndicators(t *testing.T) {
	r := baseReport()
	bad := model.TestResult{ID: "udp_a", Status: model.Warn, Rcode: "NXDOMAIN"}
	cf := res("Cloudflare primary IPv4", "public", "1.1.1.1:53", 4, true, bad)
	cf.ProviderKey = "cloudflare"
	gg := res("Google primary IPv4", "public", "8.8.8.8:53", 4, true, ok)
	gg.ProviderKey = "google"
	gg.NXDOMAIN = "hijacked"
	r.Resolvers = []model.ResolverResult{res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok), cf, gg}
	Run(r)
	var f *model.Finding
	for i := range r.Findings {
		if r.Findings[i].ID == "INTERCEPT-PUBLIC" {
			f = &r.Findings[i]
		}
	}
	if f == nil || f.Severity != model.Fail || f.Confidence != "confirmed" {
		t.Fatalf("want confirmed interception, got %+v", f)
	}
}

// Audit scenario: a Tailscale address must not be reported as ISP CGNAT.
func TestTailscaleIsNotCGNAT(t *testing.T) {
	r := baseReport()
	r.PublicIP.CGNAT = false // probe-level: overlay interface excluded
	r.PublicIP.Notes = []string{"interface tailscale0 has 100.101.1.2 from 100.64.0.0/10 — an overlay/VPN address"}
	r.Resolvers = []model.ResolverResult{res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok)}
	Run(r)
	if has(r, "CGNAT", model.Info) {
		t.Fatal("overlay address reported as CGNAT")
	}
}

// Audit scenario: ICMP blocked while TCP/HTTPS work must not look like an outage.
func TestICMPBlockedIsNotAnOutage(t *testing.T) {
	r := baseReport()
	r.Resolvers = []model.ResolverResult{res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok)}
	r.Network.Pings = []model.Ping{{Target: "1.1.1.1", Label: "Internet (IPv4)", Family: 4, Sent: 10, Received: 0}}
	Run(r)
	if !has(r, "PING-NET-NONE-V4", model.Info) || r.Summary.Fail > 0 {
		t.Fatalf("ICMP block misdiagnosed: %+v", r.Summary)
	}
}

// Audit scenario: TLS interception without DNS interception.
func TestTLSInterceptionWithoutDNSInterception(t *testing.T) {
	r := baseReport()
	cf := res("Cloudflare primary IPv4", "public", "1.1.1.1:53", 4, true, ok)
	cf.ProviderKey = "cloudflare"
	cf.Egress = model.Egress{IP: "172.68.1.1", ASN: "13335", Matches: "yes"}
	r.Resolvers = []model.ResolverResult{res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok), cf}
	r.PublicIP.IPv4 = model.TraceInfo{OK: true, Method: "http fallback", Error: "TLS verification failed: x509: certificate signed by unknown authority"}
	Run(r)
	if !has(r, "TLS-INTERCEPT-V4", model.Warn) || !has(r, "INTERCEPT-NONE", model.Pass) {
		t.Fatalf("want TLS warning and clean DNS: %+v", r.Findings)
	}
}

func TestHealthy(t *testing.T) {
	r := baseReport()
	a := res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok)
	a.OnLink = true
	b := res("System DNS #2", "system", "192.168.1.2:53", 4, true, ok)
	b.OnLink = true
	cf := res("Cloudflare primary IPv4", "public", "1.1.1.1:53", 4, true, ok)
	cf.ProviderKey = "cloudflare"
	cf.Egress = model.Egress{IP: "172.68.1.1", ASN: "13335", Matches: "yes"}
	r.Resolvers = []model.ResolverResult{a, b, cf}
	r.OSLookups = []model.OSLookup{{Name: "example.com", Expected: "v4+v6", OK: true, Resolved: true, HasV4: true, HasV6: true}}
	Run(r)
	if r.Summary.Verdict != "healthy" || r.Summary.Fail+r.Summary.Warn != 0 {
		for _, f := range r.Findings {
			t.Log(f.Severity, f.ID, f.Title)
		}
		t.Fatalf("verdict %s", r.Summary.Verdict)
	}
	if !has(r, "INTERCEPT-NONE", model.Pass) || !has(r, "FAILOVER-OK", model.Pass) {
		t.Fatal("expected pass findings")
	}
}

// Audit example: DNS takes 5 ms but TLS takes 800 ms → blame TLS, not DNS.
func TestWebCorrelationBlamesTLSNotDNS(t *testing.T) {
	r := baseReport()
	r.Resolvers = []model.ResolverResult{res("System DNS #1", "system", "192.168.1.1:53", 4, true, ok)}
	for _, u := range []string{"https://a/", "https://b/", "https://c/"} {
		r.Web = append(r.Web, model.WebTiming{URL: u, Host: u, Family: 4, OK: true, DNSMS: 5, ConnectMS: 20, TLSMS: 800, TTFBMS: 40, TotalMS: 865})
	}
	Run(r)
	if !has(r, "WEB-TLS-SLOW", model.Warn) || has(r, "WEB-DNS-BOTTLENECK", model.Warn) {
		t.Fatalf("wrong attribution: %+v", r.Findings)
	}
}
