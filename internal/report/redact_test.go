package report

import (
	"strings"
	"testing"

	"github.com/StormAvenger/SAdns/internal/execx"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

func sensitiveReport() *model.Report {
	raw := "Host Name . . . : davids-desktop\nPhysical Address: A4-83-E7-12-34-56\nIPv4 192.168.1.50 gw 192.168.1.1\nIPv6 2601:600:a17f:7d00:abcd::5\nDNS Suffix: home.lan\nVPN corp.example.com via 10.8.0.1"
	return &model.Report{
		System: &sysinfo.Info{
			Hostname:       "davids-desktop",
			SearchDomains:  []string{"home.lan"},
			SplitResolvers: []sysinfo.Resolver{{Addr: "10.8.0.1", Domain: "corp.example.com"}},
			Interfaces: []sysinfo.Interface{{Name: "eth0", Up: true, HWAddr: "a4:83:e7:12:34:56", Addrs: []sysinfo.IfAddr{
				{CIDR: "192.168.1.50/24", IP: "192.168.1.50", Family: 4, Scope: "private"},
				{CIDR: "2601:600:a17f:7d00:abcd::5/64", IP: "2601:600:a17f:7d00:abcd::5", Family: 6, Scope: "public"},
			}}},
			Raw: []execx.Output{{Command: "ipconfig /all", Output: raw}},
		},
		PublicIP: model.PublicIP{IPv4: model.TraceInfo{OK: true, IP: "73.15.22.9"}, IPv6: model.TraceInfo{OK: true, IP: "2601:600:a17f:7d00::1234"}},
		Resolvers: []model.ResolverResult{
			{Label: "System DNS #1", Role: "system", Addr: "192.168.1.1:53", Egress: model.Egress{IP: "68.87.1.2", ECS: "73.15.22.0/24"},
				Tests: []model.TestResult{{ID: "rebind", Name: "rebind", Query: "10.0.0.1.nip.io A", Detail: "ok"}}},
			{Label: "Cloudflare primary IPv4", Role: "public", Addr: "1.1.1.1:53"},
		},
	}
}

// Audit scenario: redacted Markdown and JSON must contain no prohibited identifiers.
func TestRedactionLevels(t *testing.T) {
	r := sensitiveReport()
	md, js := Markdown(r), func() string { b, _ := JSON(r); return string(b) }()
	always := []string{"davids-desktop", "73.15.22.9", "2601:600:a17f:7d00", "a4:83:e7:12:34:56", "A4-83-E7-12-34-56", "73.15.22.0/24"}
	publicOnly := []string{"192.168.1.50", "192.168.1.1", "home.lan", "corp.example.com", "10.8.0.1", "68.87.1.2"}
	for _, level := range []string{PrivacyTechnical, PrivacyPublic} {
		for name, doc := range map[string]string{"md": md, "json": js} {
			out := NewRedactor(r, level).Apply(doc)
			for _, bad := range always {
				if strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
					t.Errorf("%s/%s leaks %q", level, name, bad)
				}
			}
			for _, x := range publicOnly {
				if level == PrivacyPublic && strings.Contains(out, x) {
					t.Errorf("public/%s leaks %q", name, x)
				}
			}
			if !strings.Contains(out, "1.1.1.1") {
				t.Errorf("%s/%s removed the public resolver address", level, name)
			}
			if !strings.Contains(out, "10.0.0.1.nip.io") {
				t.Errorf("%s/%s mangled a test hostname", level, name)
			}
		}
	}
	// Technical keeps the LAN layout an expert needs.
	tech := NewRedactor(r, PrivacyTechnical).Apply(md)
	if !strings.Contains(tech, "192.168.1.1") || !strings.Contains(tech, "home.lan") {
		t.Error("technical level removed LAN details")
	}
	// Public placeholders are consistent: the same address maps to the same token.
	pub := NewRedactor(r, PrivacyPublic)
	a, b := pub.Apply("gw 192.168.1.1"), pub.Apply("dns 192.168.1.1:53")
	if strings.TrimPrefix(a, "gw ") != strings.TrimSuffix(strings.TrimPrefix(b, "dns "), ":53") {
		t.Errorf("inconsistent placeholders: %q vs %q", a, b)
	}
	if NewRedactor(r, PrivacyFull).Apply(md) != md {
		t.Error("full level changed output")
	}
}
