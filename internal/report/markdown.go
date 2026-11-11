// Package report renders a model.Report as Markdown (optimised for pasting
// into an AI assistant) and JSON, with optional redaction.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
)

var sevIcon = map[string]string{model.Fail: "❌", model.Warn: "⚠️", model.Info: "ℹ️", model.Pass: "✅", model.Skip: "➖"}

func icon(s string) string {
	if i, ok := sevIcon[s]; ok {
		return i
	}
	return "·"
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

type w struct{ sb strings.Builder }

func (w *w) p(format string, a ...any) { fmt.Fprintf(&w.sb, format, a...); w.sb.WriteByte('\n') }
func (w *w) nl()                       { w.sb.WriteByte('\n') }

// AIPrompt is the instruction block placed at the top of every report.
const AIPrompt = `You are a senior network engineer. Below is a complete DNS and network diagnostic report produced by SAdns, an open-source tool that tested this computer's DNS configuration, the local/router resolver, major public resolvers (Cloudflare, Google, Quad9, OpenDNS, AdGuard, Control D), IPv4/IPv6 connectivity, DNS failover, interception and routing.

Please:
1. Identify the root cause(s) of any problems, starting with ❌ FAIL and ⚠️ WARN findings. Use the evidence and raw data sections to confirm or refute each finding — do not assume a finding is correct if the data disagrees.
2. Explain the impact in plain terms (what the user would notice).
3. Give exact, step-by-step fixes for the equipment shown (router/gateway model, OS). Ask for the router make/model or settings screenshots if you need them.
4. Point out anything suspicious the automated rules may have missed.`

// Markdown renders the report.
func Markdown(r *model.Report) string {
	var o w
	sys := r.System
	o.p("# DNS & Network Diagnostic Report")
	o.nl()
	o.p("| | |")
	o.p("|---|---|")
	o.p("| **Generated** | %s (run took %.1f s) |", r.StartedAt.Format("2006-01-02 15:04:05 MST"), r.DurationSec)
	o.p("| **Tool** | %s %s (%s) — %s |", r.Tool.Name, r.Tool.Version, r.Tool.Commit, r.Tool.Repo)
	if sys != nil {
		o.p("| **Host** | %s — %s (%s/%s) |", cell(sys.Hostname), cell(sys.OSVersion), sys.OS, sys.Arch)
	}
	o.p("| **Verdict** | **%s** — %s |", strings.ToUpper(r.Summary.Verdict), cell(r.Summary.Headline))
	o.p("| **Findings** | ❌ %d fail · ⚠️ %d warn · ℹ️ %d info · ✅ %d pass |", r.Summary.Fail, r.Summary.Warn, r.Summary.Info, r.Summary.Pass)
	opts := r.Options
	o.p("| **Options** | samples=%d, timeout=%dms, quick=%v, traceroute=%v, encrypted=%v, ipv4=%v, ipv6=%v |", opts.Samples, opts.TimeoutMS, opts.Quick, opts.Traceroute, opts.Encrypted, opts.IPv4, opts.IPv6)
	if r.Redacted {
		o.p("| **Privacy** | Redacted: public IPs, hostname and MAC addresses replaced with placeholders |")
	}
	o.nl()
	o.p("## How to use this report with an AI assistant")
	o.nl()
	for _, l := range strings.Split(AIPrompt, "\n") {
		o.p("> %s", l)
	}
	o.nl()

	// 1. Findings
	o.p("## 1. Findings")
	o.nl()
	var passes []model.Finding
	for _, f := range r.Findings {
		if f.Severity == model.Pass {
			passes = append(passes, f)
			continue
		}
		o.p("### %s %s — %s", icon(f.Severity), strings.ToUpper(f.Severity), f.Title)
		o.p("`%s` · %s", f.ID, f.Category)
		o.nl()
		if f.Detail != "" {
			o.p("%s", f.Detail)
			o.nl()
		}
		if len(f.Evidence) > 0 {
			o.p("**Evidence**")
			for _, e := range f.Evidence {
				o.p("- %s", e)
			}
			o.nl()
		}
		if f.Recommendation != "" {
			o.p("**Suggested fix:** %s", f.Recommendation)
			o.nl()
		}
	}
	if len(passes) > 0 {
		o.p("### ✅ Verified working")
		o.nl()
		o.p("| Check | Result | Evidence |")
		o.p("|---|---|---|")
		for _, f := range passes {
			ev := ""
			if len(f.Evidence) > 0 {
				ev = f.Evidence[0]
				if len(f.Evidence) > 1 {
					ev += fmt.Sprintf(" (+%d more)", len(f.Evidence)-1)
				}
			}
			o.p("| `%s` | %s | %s |", f.ID, cell(f.Title), cell(ev))
		}
		o.nl()
	}

	// 2. Environment
	if sys != nil {
		o.p("## 2. Network environment")
		o.nl()
		o.p("### Interfaces")
		o.nl()
		o.p("| Interface | State | MTU | Addresses (scope) | Notes |")
		o.p("|---|---|---|---|---|")
		for _, i := range sys.SortedInterfaces() {
			if !i.Up && len(i.Addrs) == 0 {
				continue
			}
			var addrs []string
			for _, a := range i.Addrs {
				addrs = append(addrs, fmt.Sprintf("%s (%s)", a.CIDR, a.Scope))
			}
			state := "down"
			if i.Up {
				state = "up"
			}
			var notes []string
			if i.Loopback {
				notes = append(notes, "loopback")
			}
			if i.LikelyVPN {
				notes = append(notes, "VPN/tunnel-like")
			}
			if i.HWAddr != "" {
				notes = append(notes, "MAC "+i.HWAddr)
			}
			o.p("| %s | %s | %d | %s | %s |", cell(i.Name), state, i.MTU, cell(strings.Join(addrs, "<br>")), cell(strings.Join(notes, ", ")))
		}
		o.nl()
		o.p("### Default gateways")
		o.nl()
		if len(sys.Gateways) == 0 {
			o.p("_No default gateway found._")
		} else {
			o.p("| Family | Gateway | Interface | Metric | Source |")
			o.p("|---|---|---|---|---|")
			for _, g := range sys.Gateways {
				o.p("| IPv%d | %s | %s | %d | %s |", g.Family, g.Gateway, cell(g.Interface), g.Metric, cell(g.Source))
			}
		}
		o.nl()
		o.p("### OS DNS configuration")
		o.nl()
		o.p("- **Resolver manager:** %s", nonEmpty(sys.ResolverManager, "unknown"))
		if len(sys.StubResolvers) > 0 {
			var s []string
			for _, x := range sys.StubResolvers {
				s = append(s, x.Addr)
			}
			o.p("- **Local stub resolver(s):** %s", strings.Join(s, ", "))
		}
		o.p("- **Search domains:** %s", nonEmpty(strings.Join(sys.SearchDomains, ", "), "none"))
		if len(sys.ResolverOptions) > 0 {
			var ks []string
			for k, v := range sys.ResolverOptions {
				if v != "" {
					ks = append(ks, k+":"+v)
				} else {
					ks = append(ks, k)
				}
			}
			sort.Strings(ks)
			o.p("- **Resolver options:** %s", strings.Join(ks, " "))
		}
		o.nl()
		if len(sys.Resolvers) > 0 {
			o.p("| # | Upstream resolver | Interface | Source |")
			o.p("|---|---|---|---|")
			for i, x := range sys.Resolvers {
				o.p("| %d | %s | %s | %s |", i+1, x.Addr, cell(x.Interface), cell(x.Source))
			}
			o.nl()
		}
		if len(sys.SplitResolvers) > 0 {
			o.p("**Split-DNS (domain-scoped) resolvers** — not tested for internet names:")
			for _, x := range sys.SplitResolvers {
				o.p("- `%s` → %s (%s)", x.Domain, x.Addr, x.Interface)
			}
			o.nl()
		}
		if len(sys.Notes) > 0 {
			o.p("**Notes:**")
			for _, n := range sys.Notes {
				o.p("- %s", n)
			}
			o.nl()
		}
	}

	// 3. Connectivity
	c := r.Connectivity
	o.p("## 3. Internet connectivity")
	o.nl()
	o.p("| Family | Has address | Global address | Default route | Working |")
	o.p("|---|---|---|---|---|")
	o.p("| IPv4 | %s | %s | %s | %s |", yn(c.IPv4.HasAddress), yn(c.IPv4.HasGlobal), yn(c.IPv4.HasGateway), okIcon(c.IPv4.Working))
	o.p("| IPv6 | %s | %s | %s | %s |", yn(c.IPv6.HasAddress), yn(c.IPv6.HasGlobal), yn(c.IPv6.HasGateway), okIcon(c.IPv6.Working))
	o.nl()
	o.p("| Probe (TCP 443) | Provider | Result | Time | Local address / error |")
	o.p("|---|---|---|---|---|")
	for _, p := range append(append([]model.Probe{}, c.IPv4.Probes...), c.IPv6.Probes...) {
		o.p("| %s | %s | %s | %.1f ms | %s |", p.Target, p.Name, okIcon(p.OK), p.RTTMS, cell(nonEmpty(p.LocalAddr, p.ErrClass+" "+p.Error)))
	}
	o.nl()
	o.p("### Public addresses (Cloudflare trace)")
	o.nl()
	o.p("| Family | OK | Public IP | Cloudflare PoP | Country | TLS | Cert issuer | Clock skew | Method / error |")
	o.p("|---|---|---|---|---|---|---|---|---|")
	for _, x := range []struct {
		f int
		t model.TraceInfo
	}{{4, r.PublicIP.IPv4}, {6, r.PublicIP.IPv6}} {
		skew := "—"
		if x.t.ClockKnown {
			skew = fmt.Sprintf("%.1f s", x.t.ClockSkew)
		}
		o.p("| IPv%d | %s | %s | %s | %s | %s | %s | %s | %s |", x.f, okIcon(x.t.OK), x.t.IP, x.t.Colo, x.t.Loc, x.t.TLS, cell(x.t.CertIssuer), skew, cell(strings.TrimSpace(x.t.Method+" "+x.t.Error)))
	}
	for _, n := range r.PublicIP.Notes {
		o.p("- %s", n)
	}
	o.nl()

	// 4. OS path
	o.p("## 4. Operating-system resolution path")
	o.nl()
	o.p("Lookups made through the OS resolver API (what browsers and apps use), including the hosts file, search domains, stub resolvers and failover.")
	o.nl()
	o.p("| Name | Purpose | Result | IPv4 | IPv6 | Time | Answer / error |")
	o.p("|---|---|---|---|---|---|---|")
	for _, l := range r.OSLookups {
		ans := strings.Join(l.Addrs, ", ")
		if l.Error != "" {
			ans = l.Error
		}
		o.p("| %s | %s | %s | %s | %s | %.0f ms | %s |", l.Name, l.Purpose, okIcon(l.OK), yn(l.HasV4), yn(l.HasV6), l.MS, cell(ans))
	}
	o.nl()
	if len(r.DualStack) > 0 {
		o.p("**Dual-stack reachability (Happy Eyeballs inputs)**")
		o.nl()
		o.p("| Host | A | AAAA | IPv4 connect | IPv6 connect |")
		o.p("|---|---|---|---|---|")
		for _, d := range r.DualStack {
			o.p("| %s | %s | %s | %s | %s |", d.Host, yn(d.HasA), yn(d.HasAAAA), probeCell(d.V4), probeCell(d.V6))
		}
		o.nl()
	}

	// 5. Matrix
	o.p("## 5. Resolver test matrix")
	o.nl()
	o.p("Legend: ✅ pass · ⚠️ warn · ❌ fail · ℹ️ info · ➖ skipped. Latency = median of repeated cached queries.")
	o.nl()
	o.p("| Resolver | Address | UDP | TCP | AAAA | EDNS | TC→TCP | Big UDP | DNSSEC | NXDOMAIN | Ad filter | Median | Uncached | Loss | DoT | DoH | Egress AS |")
	o.p("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
	for i := range r.Resolvers {
		x := &r.Resolvers[i]
		st := func(id string) string {
			if t := x.Test(id); t != nil {
				return icon(t.Status)
			}
			return ""
		}
		med, cold, loss := "—", "—", "—"
		if x.Latency.Received > 0 {
			med = fmt.Sprintf("%.1f ms", x.Latency.MedianMS)
			loss = fmt.Sprintf("%.0f%%", x.Latency.LossPct)
		}
		if x.ColdMS > 0 {
			cold = fmt.Sprintf("%.0f ms", x.ColdMS)
		}
		as := ""
		if x.Egress.ASN != "" {
			as = "AS" + x.Egress.ASN
			if x.Egress.Matches == "no" {
				as += " ❗"
			}
		}
		o.p("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |",
			cell(x.Label), x.Addr, st("udp_a"), st("tcp"), st("udp_aaaa"), st("edns"), st("tc_fallback"), st("edns_large"),
			x.DNSSEC, x.NXDOMAIN, x.Filtering, med, cold, loss, st("dot"), st("doh"), as)
	}
	o.nl()

	// 6. Details
	o.p("## 6. Resolver details")
	o.nl()
	for i := range r.Resolvers {
		x := &r.Resolvers[i]
		o.p("### %s — `%s`", x.Label, x.Addr)
		o.nl()
		facts := []string{"role=" + x.Role, "provider=" + x.Provider, fmt.Sprintf("reachable=%v", x.Reachable), fmt.Sprintf("on-link=%v", x.OnLink)}
		if x.Interface != "" {
			facts = append(facts, "interface="+x.Interface)
		}
		if x.LocalAddr != "" {
			facts = append(facts, "source="+x.LocalAddr)
		}
		if x.Software != "" {
			facts = append(facts, "software="+x.Software)
		}
		if x.Egress.IP != "" {
			eg := "egress=" + x.Egress.IP
			if x.Egress.ASN != "" {
				eg += " (AS" + x.Egress.ASN + " " + x.Egress.ASName + ", matches provider: " + x.Egress.Matches + ")"
			}
			facts = append(facts, eg)
		}
		if x.Egress.ECS != "" {
			facts = append(facts, "ECS="+x.Egress.ECS)
		}
		if len(x.Identity) > 0 {
			var ks []string
			for k, v := range x.Identity {
				ks = append(ks, k+"="+v)
			}
			sort.Strings(ks)
			facts = append(facts, "identity: "+strings.Join(ks, ", "))
		}
		if x.Latency.Received > 0 {
			l := x.Latency
			facts = append(facts, fmt.Sprintf("latency min/med/avg/p90/max = %.1f/%.1f/%.1f/%.1f/%.1f ms, jitter %.1f ms, %d/%d answered", l.MinMS, l.MedianMS, l.AvgMS, l.P90MS, l.MaxMS, l.JitterMS, l.Received, l.Sent))
		}
		o.p("%s", strings.Join(facts, " · "))
		o.nl()
		o.p("| Test | Status | Detail | Query | RTT | Rcode / flags | Size | Answers / EDE / error |")
		o.p("|---|---|---|---|---|---|---|---|")
		for _, t := range x.Tests {
			extra := strings.Join(t.Answers, "; ")
			if len(t.EDE) > 0 {
				extra = strings.TrimPrefix(extra+"; "+strings.Join(t.EDE, "; "), "; ")
			}
			if t.Error != "" {
				extra = strings.TrimPrefix(extra+"; "+t.Error, "; ")
			}
			if len(extra) > 300 {
				extra = extra[:300] + "…"
			}
			rtt := ""
			if t.RTTMS > 0 {
				rtt = fmt.Sprintf("%.1f ms", t.RTTMS)
			}
			size := ""
			if t.Size > 0 {
				size = fmt.Sprintf("%d B", t.Size)
			}
			o.p("| %s | %s | %s | %s | %s | %s | %s | %s |", cell(t.Name), icon(t.Status), cell(t.Detail), cell(t.Query), rtt, cell(strings.TrimSpace(t.Rcode+" "+t.Flags)), size, cell(extra))
		}
		o.nl()
	}

	// 7. Interception
	o.p("## 7. Interception & integrity")
	o.nl()
	o.p("| Probe | Status | Detail |")
	o.p("|---|---|---|")
	for _, b := range r.Interception.BogonProbes {
		o.p("| %s | %s | %s |", cell(b.Name), icon(b.Status), cell(b.Detail))
	}
	o.nl()
	o.p("| Resolver | Egress IP | ASN | AS name | Matches provider | ECS sent |")
	o.p("|---|---|---|---|---|---|")
	for _, x := range r.Resolvers {
		if x.Egress.IP == "" {
			continue
		}
		o.p("| %s (%s) | %s | %s | %s | %s | %s |", cell(x.Label), x.Addr, x.Egress.IP, x.Egress.ASN, cell(x.Egress.ASName), x.Egress.Matches, x.Egress.ECS)
	}
	o.nl()

	// 8. Failover
	fo := r.Failover
	o.p("## 8. DNS failover")
	o.nl()
	o.p("- Configured system resolvers: %d (working: %d, distinct hosts: %d)", fo.ConfiguredCount, fo.WorkingCount, fo.DistinctHosts)
	if fo.Model != "" {
		o.p("- OS failover behaviour: %s", fo.Model)
	}
	if fo.WorstCaseSec > 0 {
		o.p("- Estimated worst-case delay before a lookup fails over: ~%.0f s", fo.WorstCaseSec)
	}
	for _, n := range fo.Notes {
		o.p("- %s", n)
	}
	o.nl()

	// 9. Routing
	o.p("## 9. Routing")
	o.nl()
	if len(r.Routing.Choices) > 0 {
		o.p("| Destination | Purpose | Interface | Source address | On-link | VPN | Error |")
		o.p("|---|---|---|---|---|---|---|")
		for _, ch := range r.Routing.Choices {
			o.p("| %s | %s | %s | %s | %s | %s | %s |", ch.Dest, cell(ch.Label), cell(ch.Interface), ch.LocalAddr, yn(ch.OnLink), yn(ch.VPN), cell(ch.Error))
		}
		o.nl()
	}
	for _, t := range r.Routing.Traces {
		o.p("### Traceroute — %s", t.Label)
		o.nl()
		if t.Error != "" && len(t.Hops) == 0 {
			o.p("_%s_", t.Error)
			o.nl()
			continue
		}
		o.p("Tool: `%s` · reached destination: %v · private hops: %d · CGNAT hops: %d", t.Tool, t.Reached, t.PrivateHops, t.CGNATHops)
		o.nl()
		o.p("| Hop | Address | Scope | RTT |")
		o.p("|---|---|---|---|")
		for _, h := range t.Hops {
			if h.Timeout {
				o.p("| %d | * | | |", h.TTL)
			} else {
				o.p("| %d | %s | %s | %.1f ms |", h.TTL, h.Addr, h.Scope, h.RTTMS)
			}
		}
		o.nl()
	}

	// 10. Methodology
	o.p("## 10. Methodology (what each test means)")
	o.nl()
	for _, m := range methodology {
		o.p("- **%s** — %s", m[0], m[1])
	}
	o.nl()

	// Appendix
	o.p("## Appendix A — Raw command output")
	o.nl()
	if sys != nil {
		for _, raw := range sys.Raw {
			o.p("<details><summary><code>%s</code>%s</summary>", htmlEsc(raw.Command), errSuffix(raw.Error))
			o.nl()
			o.p("```text")
			o.p("%s", strings.TrimRight(raw.Output, "\n"))
			o.p("```")
			o.nl()
			o.p("</details>")
			o.nl()
		}
	}
	for _, t := range r.Routing.Traces {
		if t.Raw == nil {
			continue
		}
		o.p("<details><summary><code>%s</code>%s</summary>", htmlEsc(t.Raw.Command), errSuffix(t.Raw.Error))
		o.nl()
		o.p("```text")
		o.p("%s", t.Raw.Output)
		o.p("```")
		o.nl()
		o.p("</details>")
		o.nl()
	}
	o.p("---")
	o.p("_Generated by [SAdns](%s) %s at %s. Machine-readable data is in the matching .json file._", r.Tool.Repo, r.Tool.Version, r.FinishedAt.Format(time.RFC3339))
	return o.sb.String()
}

var methodology = [][2]string{
	{"UDP/53 query", "A record for example.com sent directly to the resolver IP over UDP (EDNS0, 1232-byte buffer, NSID requested); one retry."},
	{"TCP/53 query", "Same query over TCP. Required for answers that do not fit in UDP."},
	{"AAAA query", "IPv6 address lookup; empty NOERROR answers may indicate AAAA filtering."},
	{"Latency", "Repeated cached queries (min/median/p90/jitter) plus one query for a random, uncached name."},
	{"EDNS0", "Checks the OPT record in the reply (EDNS version, server UDP size, NSID) and the RA (recursion available) flag."},
	{"Truncation → TCP fallback", "Root DNSKEY with DNSSEC records (~1.1 KB) requested with a 512-byte UDP limit: the server should set TC=1, then the same query over TCP must succeed."},
	{"Large UDP", "Same root DNSKEY query with a 4096-byte limit over UDP: detects firewalls/middleboxes that drop large or fragmented DNS packets."},
	{"DNSSEC", "ietf.org (validly signed; AD flag expected) and dnssec-failed.org (deliberately broken; a validating resolver must return SERVFAIL)."},
	{"NXDOMAIN integrity", "A random non-existent .com name must return NXDOMAIN; an address means NXDOMAIN rewriting (ISP ads/search pages)."},
	{"Ad filtering", "pagead2.googlesyndication.com and ad.doubleclick.net: NXDOMAIN/REFUSED/0.0.0.0/private address/EDE 15–18 = blocked."},
	{"Server identity", "CHAOS TXT version.bind, hostname.bind, id.server — fingerprints dnsmasq/Unbound/BIND and anycast PoPs."},
	{"Egress", "TXT o-o.myaddr.l.google.com (and whoami.akamai.net) reveal the IP the resolver uses toward authoritative servers; its ASN (Team Cymru) shows which network actually resolved the query."},
	{"Interception (bogon)", "Queries to 192.0.2.53 and 2001:db8::53 (documentation ranges that never host DNS). Any answer proves port-53 traffic is transparently redirected."},
	{"Interception (egress ASN)", "Queries sent to a public provider must be resolved from that provider's network (e.g. Cloudflare AS13335, Google AS15169, Quad9 AS19281/AS42, OpenDNS AS36692, Control D AS398962)."},
	{"DoT / DoH", "Encrypted DNS to each public provider's IP on TCP/853 (TLS, certificate verified against the provider's hostname) and HTTPS/443 (RFC 8484 POST)."},
	{"OS resolution path", "Lookups through the operating system resolver API, as applications perform them (hosts file, search domains, stub resolvers, failover)."},
	{"Connectivity", "TCP connects to anycast addresses of Cloudflare/Google/Quad9 on port 443 over IPv4 and IPv6; public IP, PoP and server time from Cloudflare's /cdn-cgi/trace."},
	{"Routing", "Kernel route selection (source address/interface) for each resolver, plus the system traceroute tool toward 1.1.1.1 and 2606:4700:4700::1111."},
	{"Direct path", "All DNS tests bypass the OS resolver and any HTTP proxy and talk to the exact IP being tested, so each result reflects that server and path only."},
}

func htmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func errSuffix(e string) string {
	if e == "" {
		return ""
	}
	return " — " + htmlEsc(e)
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func okIcon(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

func probeCell(p *model.Probe) string {
	if p == nil {
		return "—"
	}
	if p.OK {
		return fmt.Sprintf("✅ %.1f ms", p.RTTMS)
	}
	return "❌ " + p.ErrClass
}

// JSON renders the report as indented JSON.
func JSON(r *model.Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
