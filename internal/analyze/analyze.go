// Package analyze turns raw measurements into findings with severities,
// evidence and recommendations. Rules are deliberately explicit so both humans
// and AI assistants can trace every conclusion back to data in the report.
package analyze

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

type az struct {
	r           *model.Report
	f           []model.Finding
	intercepted bool
	sigGaps     int // coverage gaps large enough that "healthy" would overstate the result
}

func (a *az) add(sev, cat, id, title, detail, rec string, ev ...string) {
	a.f = append(a.f, model.Finding{ID: id, Severity: sev, Category: cat, Title: title, Detail: detail, Recommendation: rec, Evidence: ev})
}

// conf sets the confidence of the most recently added finding.
func (a *az) conf(c string) {
	if len(a.f) > 0 {
		a.f[len(a.f)-1].Confidence = c
	}
}

const (
	confirmed    = "confirmed"
	suspected    = "suspected"
	inconclusive = "inconclusive"
)

// Run analyzes the report in place, filling Findings and Summary.
func Run(r *model.Report) {
	a := &az{r: r}
	a.connectivity()
	a.osPath()
	a.system()
	a.interception()
	a.public()
	a.resolverExtras()
	a.netHealth()
	a.webLoads()
	a.routing()
	gaps := a.coverage()

	rank := map[string]int{model.Fail: 0, model.Warn: 1, model.Info: 2, model.Pass: 3}
	// Within a severity, root causes (connectivity, interception, the system
	// resolvers) come before per-resolver protocol symptoms.
	cat := map[string]int{"connectivity": 0, "system": 1, "security": 2, "dns": 3, "failover": 4, "filtering": 5, "performance": 6, "privacy": 7, "routing": 8}
	sort.SliceStable(a.f, func(i, j int) bool {
		if rank[a.f[i].Severity] != rank[a.f[j].Severity] {
			return rank[a.f[i].Severity] < rank[a.f[j].Severity]
		}
		return cat[a.f[i].Category] < cat[a.f[j].Category]
	})
	for i := range a.f {
		a.f[i].Layer = layerOf(a.f[i])
	}
	r.Findings = a.f
	s := model.Summary{Layers: layers(a.f)}
	for _, f := range a.f {
		switch f.Severity {
		case model.Pass:
			s.Pass++
		case model.Info:
			s.Info++
		case model.Warn:
			s.Warn++
		case model.Fail:
			s.Fail++
		}
	}
	switch {
	case s.Fail > 0:
		s.Verdict = "problems"
	case s.Warn > 0:
		s.Verdict = "degraded"
	default:
		s.Verdict = "healthy"
	}
	if len(a.f) > 0 && a.f[0].Severity != model.Pass && a.f[0].Severity != model.Info {
		s.Headline = a.f[0].Title
	} else {
		s.Headline = "No DNS or connectivity problems detected"
	}
	s.Coverage = gaps
	// "Healthy" is only claimed for what was actually tested.
	if s.Verdict == "healthy" && a.sigGaps > 0 {
		s.Verdict = "partial"
		s.Headline = fmt.Sprintf("No problems found in what was tested — but %d area(s) could not be tested", a.sigGaps)
	}
	if r.Cancelled {
		s.Verdict = "cancelled"
		s.Headline = "Scan was cancelled — results are incomplete"
	}
	r.Summary = s
}

// coverage lists checks that could not run or could not reach a conclusion.
func (a *az) coverage() []string {
	var g []string
	r := a.r
	sig := func(s string) { g = append(g, s); a.sigGaps++ }
	if r.Connectivity.IPv4.Disabled {
		sig("IPv4 tests disabled by option")
	}
	if r.Connectivity.IPv6.Disabled {
		sig("IPv6 tests disabled by option")
	}
	if len(a.resolvers("system", "stub")) == 0 {
		sig("no system DNS resolvers were discovered, so the DNS this device actually uses was not tested")
	}
	if len(r.Web) == 0 && !r.Cancelled {
		sig("website loading tests did not run")
	}
	skippedV6 := 0
	for _, x := range r.Resolvers {
		if t := x.Test("udp_a"); t != nil && t.Status == model.Skip && x.Family == 6 {
			skippedV6++
		}
	}
	if skippedV6 > 0 {
		g = append(g, fmt.Sprintf("%d IPv6 public-resolver addresses skipped (no working IPv6)", skippedV6))
	}
	for _, p := range r.Network.Pings {
		if p.Sent == 0 {
			sig("ping / packet-loss tests: " + p.Error)
			break
		}
	}
	for _, m := range r.Network.MTU {
		if m.Error != "" {
			g = append(g, fmt.Sprintf("path MTU (IPv%d): %s", m.Family, m.Error))
		}
	}
	for _, t := range r.Routing.Traces {
		if t.Error != "" && len(t.Hops) == 0 {
			g = append(g, "traceroute: "+t.Error)
			break
		}
	}
	if !r.Options.Traceroute {
		g = append(g, "traceroute disabled by option")
	}
	if r.Data.Mode == "low-data" {
		g = append(g, fmt.Sprintf("Low Data Mode: %d website sample per address family, response bodies capped at %d KiB, scan HTTP budget %d MiB — website timing confidence reduced", r.Data.WebSamples, r.Data.BaselineLimitBytes>>10, r.Data.ScanBudgetBytes>>20))
	}
	if r.Data.BudgetLimited > 0 {
		g = append(g, fmt.Sprintf("%d website request(s) skipped or cut short because the scan data budget was reached", r.Data.BudgetLimited))
	}
	if !r.Options.Encrypted {
		sig("DoT/DoH tests disabled by option")
	}
	var dnssec, rebind, cache []string
	for _, x := range r.Resolvers {
		if x.Role == "public" || x.ProviderKey != "" || !x.Reachable {
			continue
		}
		if x.DNSSEC == "inconclusive" {
			dnssec = append(dnssec, x.Addr)
		}
		if x.Rebind == "unknown" {
			rebind = append(rebind, x.Addr)
		}
		if x.Caching == "unknown" {
			cache = append(cache, x.Addr)
		}
	}
	if len(dnssec) > 0 {
		g = append(g, "DNSSEC validation inconclusive for "+strings.Join(dnssec, ", "))
	}
	if len(rebind) > 0 {
		g = append(g, "rebinding-protection test inconclusive for "+strings.Join(rebind, ", ")+" (wildcard control names unreachable)")
	}
	if len(cache) > 0 {
		g = append(g, "caching test inconclusive for "+strings.Join(cache, ", "))
	}
	for _, f := range a.f {
		if f.ID == "INTERCEPT-INCONCLUSIVE" {
			sig("interception: egress of public resolvers could not be verified")
		}
	}
	if runtime := r.System; runtime != nil && runtime.OS != "windows" && runtime.OS != "darwin" {
		// Release builds use Go's own resolver on Linux/BSD: it reads
		// resolv.conf/hosts but not nsswitch plugins (mDNS, LDAP, systemd-resolved
		// via nss-resolve), so it can differ from what glibc apps see.
		g = append(g, "OS-path lookups on Linux/BSD use Go's resolver (resolv.conf + hosts), not glibc nsswitch modules such as mdns or nss-resolve")
	}
	if len(g) > 0 {
		a.add(model.Info, "coverage", "COVERAGE", "Some checks could not run or reach a conclusion", "These parts of the network were not fully tested. Treat the absence of findings in these areas as 'unknown', not 'healthy'.", "Install the missing tools (ping, traceroute) or re-run with both address families to close the gaps.", g...)
	}
	return g
}

func (a *az) resolvers(roles ...string) []*model.ResolverResult {
	var out []*model.ResolverResult
	for i := range a.r.Resolvers {
		for _, ro := range roles {
			// A system resolver that is a public provider's address (e.g.
			// 1.1.1.1 configured on the OS) belongs to both groups.
			if x := &a.r.Resolvers[i]; x.Role == ro || (ro == "public" && x.ProviderKey != "") {
				out = append(out, x)
				break
			}
		}
	}
	return out
}

func probeEv(ps []model.Probe) []string {
	var ev []string
	for _, p := range ps {
		if p.OK {
			ev = append(ev, fmt.Sprintf("TCP %s (%s): connected in %.1f ms", p.Target, p.Name, p.RTTMS))
		} else {
			ev = append(ev, fmt.Sprintf("TCP %s (%s): FAILED %s", p.Target, p.Name, p.ErrClass))
		}
	}
	return ev
}

// ---------------------------------------------------------------- connectivity

func (a *az) connectivity() {
	c := a.r.Connectivity
	switch {
	case c.IPv4.Disabled:
		a.add(model.Info, "connectivity", "CONN-V4-DISABLED", "IPv4 tests disabled by option", "Run without -4/-6 to test both families.", "")
	case c.IPv4.Working:
		a.add(model.Pass, "connectivity", "CONN-V4-OK", "IPv4 internet connectivity works", "TCP connections to public anycast hosts succeeded over IPv4.", "", probeEv(c.IPv4.Probes)...)
	case !c.IPv4.HasAddress:
		a.add(model.Fail, "connectivity", "CONN-V4-NOADDR", "No IPv4 address configured", "No interface has a usable IPv4 address.", "Check the cable/Wi-Fi link and that the router's DHCP server is handing out leases.")
	case !c.IPv4.HasGateway:
		a.add(model.Fail, "connectivity", "CONN-V4-NOGW", "No IPv4 default route", "The host has an IPv4 address but no default gateway, so nothing beyond the local subnet is reachable.", "Check the DHCP 'router' option on the gateway, or the static configuration.")
	default:
		a.add(model.Fail, "connectivity", "CONN-V4-DOWN", "IPv4 internet is unreachable", "The host has an IPv4 address and default route, but TCP connections to 1.1.1.1/8.8.8.8/9.9.9.9 all failed.", "Check the router's WAN status, upstream modem, and any firewall rules blocking outbound traffic.", probeEv(c.IPv4.Probes)...)
	}

	switch {
	case c.IPv6.Disabled:
		a.add(model.Info, "connectivity", "CONN-V6-DISABLED", "IPv6 tests disabled by option", "Run without -4/-6 to test both families.", "")
	case c.IPv6.Working:
		a.add(model.Pass, "connectivity", "CONN-V6-OK", "IPv6 internet connectivity works", "TCP connections to public anycast hosts succeeded over IPv6.", "", probeEv(c.IPv6.Probes)...)
	case !c.IPv6.HasGlobal && !c.IPv6.HasGateway:
		a.add(model.Info, "connectivity", "CONN-V6-NONE", "IPv6 is not provisioned on this network", "No global IPv6 address and no IPv6 default route. The network runs IPv4-only; this is not an error by itself.", "If your ISP offers IPv6, enable it on the router WAN (usually DHCPv6 with prefix delegation) and on the LAN (SLAAC/RA). On UniFi: Network → Internet → IPv6 = DHCPv6 + Prefix Delegation, then LAN networks → IPv6 Interface Type = Prefix Delegation.")
	case c.IPv6.HasGlobal && !c.IPv6.HasGateway:
		a.add(model.Fail, "connectivity", "CONN-V6-NOGW", "IPv6 address present but no IPv6 default route", "The host has a global IPv6 address but received no router advertisement with a default route. IPv6-capable apps may stall before falling back to IPv4.", "Check that the router is sending Router Advertisements on this LAN (RA enabled, router lifetime > 0).")
	default:
		a.add(model.Fail, "connectivity", "CONN-V6-BROKEN", "IPv6 is configured but broken", "The host has IPv6 addressing and a default route, but every IPv6 TCP connection failed. Applications will try IPv6 first and lose time before falling back to IPv4 (Happy Eyeballs), and IPv6-only resources are unreachable.", "Check the WAN IPv6 status on the router, the delegated prefix, and IPv6 firewall rules. If the ISP's IPv6 is unreliable, disable IPv6 on the LAN rather than leaving it half-working.", probeEv(c.IPv6.Probes)...)
	}

	for _, d := range a.r.DualStack {
		if d.V6 != nil && !d.V6.OK && d.V4 != nil && d.V4.OK && c.IPv6.HasGlobal {
			a.add(model.Warn, "connectivity", "DUALSTACK-V6-FAIL", "Site publishes IPv6 but this host cannot reach it over IPv6: "+d.Host, "DNS returned AAAA records, but the IPv6 connection failed while IPv4 worked. Browsers will fall back, but with delay.", "See the IPv6 connectivity findings; this is a symptom of broken IPv6 routing.", fmt.Sprintf("%s v4 %s ok %.1f ms; v6 %s failed %s", d.Host, d.V4.Target, d.V4.RTTMS, d.V6.Target, d.V6.ErrClass))
		}
	}

	pi := a.r.PublicIP
	for fam, t := range map[int]model.TraceInfo{4: pi.IPv4, 6: pi.IPv6} {
		if strings.HasPrefix(t.Error, "TLS verification failed") && t.OK {
			a.add(model.Warn, "security", fmt.Sprintf("TLS-INTERCEPT-V%d", fam), fmt.Sprintf("HTTPS to 1.1.1.1 failed certificate verification (IPv%d)", fam), "Plain HTTP worked but HTTPS to Cloudflare's trace endpoint did not validate. This indicates TLS interception (corporate proxy, antivirus HTTPS scanning, router 'SSL inspection') or a badly wrong clock.", "Check for TLS/SSL inspection features on the firewall or antivirus, and verify the system clock.", t.Error)
		}
		if t.ClockKnown && math.Abs(t.ClockSkew) > 60 {
			sev := model.Warn
			if math.Abs(t.ClockSkew) > 300 {
				sev = model.Fail
			}
			a.add(sev, "system", "CLOCK-SKEW", fmt.Sprintf("System clock is off by %.0f seconds", t.ClockSkew), "Compared with Cloudflare's server timestamp. Large clock errors break TLS certificate checks, DoT/DoH and DNSSEC validation.", "Enable automatic time sync (NTP) on this device and on the router.", fmt.Sprintf("skew=%.1fs (positive = local clock ahead)", t.ClockSkew))
			break
		}
	}
	if pi.CGNAT {
		a.add(model.Info, "connectivity", "CGNAT", "Carrier-grade NAT likely", "The interface carrying the default route holds a 100.64.0.0/10 address, which ISPs and phone hotspots use for carrier-grade NAT. Inbound connections and some games/VPNs then need relaying. (Overlay VPNs such as Tailscale also use this range; those interfaces are excluded.)", "Normal for cellular/Starlink/T-Mobile Home Internet; ask the ISP for a public IPv4 or use IPv6 for inbound access.", pi.Notes...)
		a.conf(suspected)
	}
	for _, t := range a.r.Routing.Traces {
		if t.Family == 4 && t.CGNATHops > 0 {
			a.add(model.Info, "routing", "CGNAT-PATH", "Shared address space (100.64.0.0/10) seen in the ISP path", "Traceroute crossed 100.64.0.0/10 router addresses. Many ISPs use this range for CGNAT, but some also number internal routers with it, so this alone does not prove you are behind CGNAT.", "Compare your router's WAN IP with the public IP in this report: if they differ, you are behind CGNAT.", hopsEv(t)...)
			a.conf(inconclusive)
			break
		}
	}
	for _, t := range a.r.Routing.Traces {
		if t.Family != 4 {
			continue
		}
		lead := 0
		for _, h := range t.Hops {
			if h.Timeout {
				continue
			}
			if h.Scope == "private" {
				lead++
				continue
			}
			break
		}
		if lead >= 2 {
			a.add(model.Warn, "routing", "DOUBLE-NAT", "Possible double NAT", fmt.Sprintf("The first %d responding hops toward the internet are private (RFC 1918) addresses. Usually this means a router behind another router (e.g. ISP modem/router + your own gateway), which complicates port forwarding, VPNs and UPnP.", lead), "Put the ISP device in bridge/passthrough mode, or give your gateway a DMZ/IP passthrough. Ignore if your network intentionally routes through internal subnets.", hopsEv(t)...)
			a.conf(suspected)
		}
		break
	}
}

func hopsEv(t model.Trace) []string {
	var ev []string
	for i, h := range t.Hops {
		if i >= 6 {
			break
		}
		if h.Timeout {
			ev = append(ev, fmt.Sprintf("hop %d: *", h.TTL))
		} else {
			ev = append(ev, fmt.Sprintf("hop %d: %s (%s) %.1f ms", h.TTL, h.Addr, h.Scope, h.RTTMS))
		}
	}
	return ev
}

// ---------------------------------------------------------------- OS path

func (a *az) osPath() {
	var resolved, total int
	var slow, ev, missing []string
	for _, l := range a.r.OSLookups {
		ev = append(ev, osEv(l))
		switch l.Expected {
		case "v4+v6", "v4":
			total++
			if l.Resolved {
				resolved++
				if l.Missing != "" {
					missing = append(missing, fmt.Sprintf("%s: no %s record returned (got %s)", l.Name, l.Missing, strings.Join(l.Addrs, ", ")))
				}
			}
			if l.Resolved && l.MS > 500 {
				slow = append(slow, fmt.Sprintf("%s %.0f ms", l.Name, l.MS))
			}
		case "nxdomain":
			if !l.OK && len(l.Addrs) > 0 {
				a.add(model.Warn, "dns", "OS-NX-HIJACK", "Non-existent domains resolve to an address via the OS resolver", "A random, non-existent name resolved instead of failing. Something in the resolution path (ISP DNS, router, or filtering software) rewrites NXDOMAIN answers. This breaks typo detection, some VPN/split-DNS setups and security tools.", "Find which resolver does it in the per-resolver NXDOMAIN tests and switch away from it (or disable 'search assist'/'error redirect' at the ISP).", osEv(l))
			}
		case "v6":
			if l.Missing != "" || (!l.Resolved && a.r.Connectivity.IPv6.Working) {
				a.add(model.Warn, "dns", "OS-V6ONLY-FAIL", "IPv6-only name did not resolve through the OS", "ipv6.google.com has only AAAA records. The OS resolver path did not return one, so AAAA lookups are being dropped or filtered.", "Check AAAA filtering on the router/DNS filter (e.g. 'filter-AAAA' in dnsmasq or Pi-hole), and the stub resolver configuration.", osEv(l))
			}
		}
	}
	switch {
	case total > 0 && resolved == 0:
		a.add(model.Fail, "dns", "OS-RESOLVE-FAIL", "Applications cannot resolve names", "Every lookup through the operating system resolver failed. Browsers and apps on this device cannot reach anything by name.", "See the system-resolver findings below for the exact cause.", ev...)
	case resolved < total:
		a.add(model.Warn, "dns", "OS-RESOLVE-PARTIAL", fmt.Sprintf("Some OS lookups failed (%d of %d)", total-resolved, total), "Name resolution through the OS resolver is intermittent or partially blocked.", "Compare the failing names with the per-resolver results.", ev...)
	case total > 0 && len(missing) == 0:
		a.add(model.Pass, "dns", "OS-RESOLVE-OK", "Name resolution through the OS works", fmt.Sprintf("All %d lookups through the operating system resolver succeeded and returned every expected record family.", total), "", ev...)
	}
	if len(missing) > 0 {
		sev, why := model.Warn, "The OS resolver path returned these names without records they are known to publish. AAAA records are being filtered (router/Pi-hole 'filter AAAA', a stub resolver policy) or lost, so apps cannot use IPv6 for them."
		if !a.r.Connectivity.IPv6.HasGlobal {
			sev, why = model.Info, "These dual-stack names came back without AAAA records. This host has no global IPv6 address, and some OS resolvers deliberately omit AAAA in that case (AI_ADDRCONFIG), so this is expected here."
		}
		a.add(sev, "dns", "OS-FAMILY-MISSING", "Expected IPv6 (AAAA) records missing from OS lookups", why, "Compare with the per-resolver AAAA test: if resolvers return AAAA but the OS does not, the filtering is local.", missing...)
	}
	if len(slow) > 0 {
		a.add(model.Warn, "performance", "OS-RESOLVE-SLOW", "Slow lookups through the OS resolver", "Some names took more than 500 ms to resolve through the OS. Common causes: a dead primary resolver (failover delay), a slow upstream, or IPv6 resolvers timing out first.", "Look at the failover section and the per-resolver latency table.", slow...)
	}
}

func osEv(l model.OSLookup) string {
	if l.Error != "" {
		return fmt.Sprintf("%s [%s]: %s (%.0f ms)", l.Name, l.Purpose, l.Error, l.MS)
	}
	return fmt.Sprintf("%s [%s]: %s (%.0f ms)", l.Name, l.Purpose, strings.Join(l.Addrs, ", "), l.MS)
}

// ---------------------------------------------------------------- system resolvers

func resEv(r *model.ResolverResult, ids ...string) []string {
	var ev []string
	for _, id := range ids {
		if t := r.Test(id); t != nil {
			s := fmt.Sprintf("%s @ %s — %s: %s", t.Name, r.Addr, strings.ToUpper(t.Status), t.Detail)
			if t.Error != "" && !strings.Contains(t.Detail, t.Error) {
				s += " [" + t.Error + "]"
			}
			ev = append(ev, s)
		}
	}
	return ev
}

func isPrivateAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return false
	}
	return sysinfo.IsLocalScope(sysinfo.Classify(ap.Addr()))
}

func (a *az) system() {
	sys := a.resolvers("system")
	stubs := a.resolvers("stub")
	gws := a.resolvers("gateway")
	for _, n := range a.r.System.Notes {
		if strings.Contains(n, "fec0:0:0:ffff") {
			a.add(model.Warn, "dns", "SYS-WIN-FEC0", "Windows is configured with placeholder IPv6 DNS servers (fec0:0:0:ffff::x)", "These deprecated site-local addresses are a Windows default when no IPv6 DNS is learned. They never answer, so IPv6 DNS lookups time out first.", "Set real IPv6 DNS servers (or 'Obtain automatically' with working RDNSS/DHCPv6 from the router), or uncheck IPv6 DNS overrides on the adapter.", n)
		}
	}
	if len(sys) == 0 && len(stubs) == 0 {
		a.add(model.Fail, "dns", "SYS-NONE", "No DNS servers are configured", "The operating system has no DNS resolvers configured, so nothing can be resolved by name.", "Check DHCP option 6 (IPv4) / RDNSS (IPv6) on the router, or configure DNS manually.")
		return
	}
	for _, c := range a.resolvers("custom") {
		ud := c.Test("udp_a")
		switch {
		case !c.Reachable:
			a.add(model.Fail, "dns", "CUSTOM-DOWN", "Resolver "+c.Addr+" (requested for testing) does not respond", "No answer over UDP or TCP.", "Check that the DNS service is running, listening on this address, and allowed through the firewall.", resEv(c, "udp_a", "tcp")...)
		case ud != nil && ud.Status != model.Pass:
			a.add(model.Fail, "dns", "CUSTOM-BAD-ANSWER", "Resolver "+c.Addr+" (requested for testing) does not resolve correctly", ud.Detail, "Check its upstream/forwarders and access lists.", resEv(c, "udp_a")...)
		default:
			a.add(model.Pass, "dns", "CUSTOM-OK", fmt.Sprintf("Resolver %s answers (median %.1f ms)", c.Addr, c.Latency.MedianMS), "", "", resEv(c, "udp_a", "latency")...)
		}
		if c.Reachable {
			a.resolverQuality(c, "CUSTOM")
		}
	}
	for _, s := range stubs {
		if s.Reachable {
			a.resolverQuality(s, "STUB")
		}
		if s.Reachable {
			a.add(model.Pass, "dns", "STUB-OK", "Local stub resolver answers ("+s.Addr+")", fmt.Sprintf("The OS uses a local caching stub (%s). It responded in %.1f ms median.", a.r.System.ResolverManager, s.Latency.MedianMS), "", resEv(s, "udp_a", "latency")...)
		} else {
			a.add(model.Fail, "dns", "STUB-DOWN", "Local stub resolver is not answering ("+s.Addr+")", "The OS points at a local stub resolver that does not respond. All application lookups will fail.", "Restart the stub service (e.g. `sudo systemctl restart systemd-resolved`) and check its upstream configuration.", resEv(s, "udp_a", "tcp")...)
		}
	}
	working := 0
	for _, r := range sys {
		if r.Reachable {
			working++
		}
	}
	if len(sys) > 0 && working == 0 {
		a.add(model.Fail, "dns", "SYS-ALL-DOWN", "None of the configured DNS servers respond", "Every resolver the OS is configured to use failed to answer over UDP and TCP.", "Check the router's DNS service, firewall rules for port 53, and whether the configured DNS addresses are still valid (stale static DNS is common after a router change).")
	}
	v4ok := false
	for _, r := range sys {
		if r.Family == 4 && r.Reachable {
			v4ok = true
		}
	}
	for _, r := range sys {
		ud := r.Test("udp_a")
		switch {
		case !r.Reachable && r.Family == 6 && v4ok:
			a.add(model.Fail, "dns", "SYS-V6-DNS-DOWN", "IPv6 DNS server "+r.Addr+" does not respond", "The OS learned this IPv6 resolver (usually via Router Advertisement RDNSS or DHCPv6), but it never answers. Lookups that try it first stall for the timeout before falling back to IPv4 DNS — a classic cause of 'the internet feels slow'.", "On the router, make sure the advertised IPv6 DNS address is one the router actually listens on (on UniFi: LAN → IPv6 → DNS Server, use the gateway's LAN IPv6 address or 'Auto'), or stop advertising IPv6 DNS.", resEv(r, "udp_a", "tcp")...)
		case !r.Reachable:
			a.add(model.Fail, "dns", "SYS-DOWN", "Configured DNS server "+r.Addr+" does not respond", "This resolver is in the OS configuration but did not answer over UDP or TCP.", "Remove or replace it. If it is the router, check that its DNS service is enabled and that the client VLAN is allowed to reach it.", resEv(r, "udp_a", "tcp")...)
		case ud != nil && ud.Status == model.Fail:
			a.add(model.Fail, "dns", "SYS-REFUSED", "DNS server "+r.Addr+" refuses queries from this host", "It responds but returns REFUSED, so it is not acting as a recursive resolver for this client (ACL, wrong VLAN or a non-recursive server).", "Allow this subnet in the resolver's access list or point clients at a recursive resolver.", resEv(r, "udp_a")...)
		case ud != nil && ud.Status == model.Warn:
			a.add(model.Fail, "dns", "SYS-BAD-ANSWER", "DNS server "+r.Addr+" answers, but not correctly", "It responds, yet returned "+ud.Rcode+" for example.com — a name that always exists. The resolver is broken, filtering far too aggressively, or its upstream is failing. Apps will see 'site not found' errors.", "Check the resolver's upstream/forwarder configuration and blocklists; test it against another resolver.", resEv(r, "udp_a", "udp_aaaa")...)
		default:
			a.add(model.Pass, "dns", "SYS-OK", fmt.Sprintf("System DNS %s answers (median %.1f ms)", r.Addr, r.Latency.MedianMS), "", "", resEv(r, "udp_a", "latency")...)
		}
		if !r.Reachable {
			continue
		}
		a.resolverQuality(r, "SYS")
		if r.Egress.IP != "" && isPrivateAddr(r.Addr) {
			as := r.Egress.ASN
			if r.Egress.ASName != "" {
				as += " " + r.Egress.ASName
			}
			a.add(model.Info, "dns", "SYS-UPSTREAM", "Local resolver "+r.Addr+" forwards to "+nonEmpty(r.Egress.ASName, r.Egress.IP), "Authoritative servers see this resolver's queries coming from the address below, which identifies the upstream it forwards to (ISP DNS, Cloudflare, Google, ...).", "If this is not the upstream you configured on the router, check the router's WAN DNS settings (on UniFi: Internet → DNS Server, and any 'DNS Shield' / encrypted DNS setting).", "egress "+r.Egress.IP+" AS"+as, "method: "+r.Egress.Method)
		}
		if r.Software != "" {
			a.add(model.Info, "dns", "SYS-SOFTWARE", "DNS server "+r.Addr+" identifies as "+r.Software, "Fingerprint from CHAOS-class queries (version.bind / hostname.bind / id.server).", "", fmt.Sprint(r.Identity))
		}
	}

	if len(sys) == 1 {
		a.add(model.Warn, "failover", "SYS-SINGLE", "Only one DNS server is configured", "If it fails, all name resolution fails — there is no fallback.", "Add a second resolver. Note: pairing a filtering resolver (Pi-hole, UniFi ad-blocking) with a public one lets clients bypass filtering whenever they fail over.", sys[0].Addr)
	}
	if fo := a.r.Failover; fo.ConfiguredCount > 1 && fo.DistinctHosts == 1 {
		a.add(model.Warn, "failover", "SYS-SAMEHOST", "All configured DNS servers are the same host", "Multiple entries point to one device, so there is no real redundancy.", "Add a resolver on a different device or a public resolver as the secondary.")
	}
	// Mixed local + public resolvers.
	var local, public []string
	for _, r := range sys {
		if isPrivateAddr(r.Addr) {
			local = append(local, r.Addr)
		} else {
			public = append(public, r.Addr)
		}
	}
	if len(local) > 0 && len(public) > 0 {
		a.add(model.Warn, "failover", "SYS-MIXED", "Local and public DNS servers are mixed", "Clients may use either. Local-only names (printers, NAS, *.lan, split-horizon records) will randomly fail when the public resolver is used, and any DNS filtering on the local resolver is bypassed.", "Use only the local resolver(s) on clients, and configure upstream redundancy on the router instead.", "local: "+strings.Join(local, ", "), "public: "+strings.Join(public, ", "))
	}
	// Filtering consistency.
	var blocks, open []string
	for _, r := range sys {
		switch r.Filtering {
		case "blocks-ads":
			blocks = append(blocks, r.Addr)
		case "no-ad-blocking":
			open = append(open, r.Addr)
		}
	}
	if len(blocks) > 0 && len(open) > 0 {
		a.add(model.Warn, "filtering", "SYS-FILTER-MIX", "DNS filtering is inconsistent between configured servers", "Some configured resolvers block ad/tracker domains and others do not. Ads/blocked content will leak through intermittently, depending on which server answers.", "Make all client resolvers the filtering one(s); give the filtering resolver its own upstream redundancy.", "blocking: "+strings.Join(blocks, ", "), "not blocking: "+strings.Join(open, ", "))
	} else if len(blocks) > 0 {
		a.add(model.Info, "filtering", "SYS-FILTERING", "Your DNS blocks ad/tracker domains", "All reachable system resolvers block common ad domains (Pi-hole, AdGuard Home, UniFi Ad Blocking or a filtering upstream).", "", blocks...)
	}
	// Failover cost when the primary is dead.
	if len(sys) > 1 && !sys[0].Reachable && working > 0 {
		a.add(model.Warn, "failover", "FAILOVER-PRIMARY-DEAD", "Primary DNS is dead; every lookup pays the failover delay", fmt.Sprintf("The first configured resolver (%s) does not answer, so lookups wait for it to time out before trying the next one. %s", sys[0].Addr, a.r.Failover.Model), "Remove or fix the dead primary resolver.", fmt.Sprintf("estimated worst case: %.0fs", a.r.Failover.WorstCaseSec))
	} else if working > 1 {
		a.add(model.Pass, "failover", "FAILOVER-OK", fmt.Sprintf("DNS failover available (%d working resolvers)", working), a.r.Failover.Model, "")
	}

	// Gateway DNS when the gateway is not already a system resolver.
	for _, g := range gws {
		if !g.Reachable {
			a.add(model.Info, "dns", "GW-NO-DNS", "Default gateway "+g.Addr+" does not answer DNS", "The router does not run a DNS forwarder on this address (or blocks it). This is only a problem if you expect clients to use the router for DNS.", "", resEv(g, "udp_a")...)
		} else {
			a.add(model.Info, "dns", "GW-DNS", "Default gateway "+g.Addr+" also answers DNS but is not configured on this host", fmt.Sprintf("The router runs a DNS forwarder (median %.1f ms) that this device does not use.", g.Latency.MedianMS), "If you want clients to use the router's DNS (local hostnames, filtering), hand out its address via DHCP.", resEv(g, "udp_a")...)
		}
	}
}

// resolverQuality applies per-resolver protocol checks.
func (a *az) resolverQuality(r *model.ResolverResult, prefix string) {
	who := r.Label + " (" + r.Addr + ")"
	if t := r.Test("tcp"); t != nil && t.Status != model.Pass {
		a.add(model.Warn, "dns", prefix+"-NO-TCP", "DNS over TCP fails for "+who, "Answers that do not fit in UDP (DNSSEC, many TXT/HTTPS records, large CNAME chains) must be retried over TCP. Those lookups will fail.", "Allow TCP/53 to the resolver (firewall) and ensure the DNS service listens on TCP.", resEv(r, "tcp")...)
	}
	if t := r.Test("tc_fallback"); t != nil && t.Status == model.Fail {
		a.add(model.Fail, "dns", prefix+"-TC-BROKEN", "Truncated answers cannot be recovered via "+who, t.Detail, "Allow TCP/53 and check that no middlebox strips the TC flag.", resEv(r, "tc_fallback")...)
	} else if t != nil && t.Status == model.Warn {
		a.add(model.Warn, "dns", prefix+"-BUFSIZE", "Resolver ignores the client's EDNS buffer size: "+who, t.Detail, "Usually harmless on a LAN, but can cause fragmentation/drops across the internet.", resEv(r, "tc_fallback")...)
	}
	if t := r.Test("edns_large"); t != nil && t.Status == model.Warn {
		a.add(model.Warn, "dns", prefix+"-LARGE-UDP", "Large UDP DNS responses are dropped on the path to "+who, t.Detail+". DNSSEC-signed and record-heavy answers will time out unless the client falls back to TCP quickly.", "Look for firewalls/'DNS inspection' features limiting UDP DNS to 512 bytes, or MTU/fragmentation issues (PPPoE, VPN tunnels).", resEv(r, "edns_large")...)
	}
	if t := r.Test("edns"); t != nil && t.Status == model.Warn {
		a.add(model.Warn, "dns", prefix+"-EDNS", "EDNS problem with "+who, t.Detail, "Update the resolver/router firmware or disable the middlebox feature stripping EDNS.", resEv(r, "edns")...)
	}
	if r.Latency.LossPct > 0 {
		a.add(model.Warn, "performance", prefix+"-LOSS", fmt.Sprintf("Packet loss to %s (%.0f%%)", who, r.Latency.LossPct), "Some repeated queries were never answered. Each loss costs the client a full timeout (often 1–5 s).", "Check Wi-Fi quality, the resolver's load/rate limiting, and upstream link congestion.", resEv(r, "latency")...)
	}
	if r.Reachable && r.Latency.Received > 0 {
		lim := 100.0
		if r.OnLink {
			lim = 15
		}
		if r.Latency.MedianMS > lim {
			a.add(model.Warn, "performance", prefix+"-SLOW", fmt.Sprintf("High DNS latency to %s (median %.0f ms)", who, r.Latency.MedianMS), fmt.Sprintf("Cached answers should come back in under %.0f ms from %s.", lim, map[bool]string{true: "a resolver on the local network", false: "a nearby resolver"}[r.OnLink]), "For a LAN resolver: check router CPU load and Wi-Fi. For a remote one: pick a closer/faster resolver (see the public resolver comparison).", resEv(r, "latency")...)
		}
		if r.ColdMS > 1000 {
			a.add(model.Warn, "performance", prefix+"-UNCACHED-SLOW", fmt.Sprintf("Uncached lookups via %s are slow (%.0f ms)", who, r.ColdMS), "Lookups that miss the cache take over a second, which users feel on every new site.", "Check the resolver's upstream (forwarder) health and latency.")
		}
	}
	if r.NXDOMAIN == "hijacked" {
		a.add(model.Warn, "dns", prefix+"-NXHIJACK", "NXDOMAIN rewriting by "+who, "Non-existent names resolve to an address instead of failing.", "Disable 'search assist'/'DNS error redirect' with the ISP or stop using this resolver.", resEv(r, "nxdomain")...)
	}
	switch r.DNSSEC {
	case "validating":
		if prefix == "SYS" {
			d := "Forged or tampered DNS answers for signed domains are rejected."
			if r.DNSSECConfidence == suspected {
				d += " (Likely: the resolver did not honour CD=1, so the cause of its SERVFAIL could not be independently confirmed.)"
			}
			a.add(model.Pass, "security", "SYS-DNSSEC-OK", "DNSSEC is validated by "+who, d, "", resEv(r, "dnssec")...)
			a.conf(r.DNSSECConfidence)
		}
	case "inconclusive":
		if prefix == "SYS" {
			a.add(model.Info, "security", "SYS-DNSSEC-UNKNOWN", "DNSSEC validation could not be determined for "+who, "The evidence was missing or contradictory (see the DNSSEC test detail). A SERVFAIL on its own is not treated as proof of validation.", "", resEv(r, "dnssec")...)
			a.conf(inconclusive)
		}
	case "not-validating":
		if prefix == "SYS" {
			a.add(model.Info, "security", "SYS-DNSSEC-NONE", "DNSSEC is not validated by "+who, "Answers for signed domains are not checked, so spoofed answers for those domains would be accepted.", "Optional hardening: forward to a validating upstream (Cloudflare, Google, Quad9) or enable DNSSEC validation on the local resolver.", resEv(r, "dnssec")...)
		}
	case "inconsistent":
		a.add(model.Warn, "security", prefix+"-DNSSEC-AD", "Misleading DNSSEC AD bit from "+who, "The resolver marks answers as authenticated but accepts bogus signatures — usually a forwarder copying the AD bit from an upstream without validating.", "Have the forwarder either validate or clear the AD bit.", resEv(r, "dnssec")...)
	}
}

// ---------------------------------------------------------------- public

func (a *az) public() {
	pub := a.resolvers("public")
	if len(pub) == 0 {
		return
	}
	type fam struct{ ok, total int }
	byFam := map[int]*fam{4: {}, 6: {}}
	var failed []string
	for _, r := range pub {
		if t := r.Test("udp_a"); t != nil && t.Status == model.Skip {
			continue
		}
		byFam[r.Family].total++
		if r.Reachable {
			byFam[r.Family].ok++
		} else {
			failed = append(failed, r.Label+" "+r.Addr)
		}
	}
	sysWorks := false
	for _, r := range a.resolvers("system", "stub") {
		if r.Reachable {
			sysWorks = true
		}
	}
	for f, s := range byFam {
		switch {
		case s.total == 0:
		case s.ok == 0 && sysWorks:
			a.add(model.Warn, "dns", fmt.Sprintf("PUB-BLOCKED-V%d", f), fmt.Sprintf("Outbound DNS to public resolvers is blocked over IPv%d", f), "No public resolver answered on port 53 even though the local resolver works. A firewall policy is forcing clients to use local DNS, or port 53 is filtered by the ISP.", "Expected if you deliberately block outbound DNS. Otherwise check firewall rules for UDP/TCP 53.", failed...)
		case s.ok == 0:
			a.add(model.Fail, "dns", fmt.Sprintf("PUB-ALL-DOWN-V%d", f), fmt.Sprintf("No public resolver reachable over IPv%d", f), "Neither public resolvers nor (see above) system resolvers work over this family.", "Check internet connectivity for this address family.", failed...)
		case s.ok < s.total:
			a.add(model.Warn, "dns", fmt.Sprintf("PUB-PARTIAL-V%d", f), fmt.Sprintf("Some public resolvers are unreachable over IPv%d (%d of %d)", f, s.total-s.ok, s.total), "Specific providers are blocked or unreachable. If you rely on one of them, lookups will fail.", "Check for firewall rules or ISP filtering targeting these addresses.", failed...)
		default:
			a.add(model.Pass, "dns", fmt.Sprintf("PUB-OK-V%d", f), fmt.Sprintf("All public resolvers reachable over IPv%d (%d/%d)", f, s.ok, s.total), "", "")
		}
	}

	// Encrypted DNS.
	var dotOK, dotN, dohOK, dohN int
	for _, r := range pub {
		if t := r.Test("dot"); t != nil && t.Status != model.Skip {
			dotN++
			if t.Status == model.Pass {
				dotOK++
			}
		}
		if t := r.Test("doh"); t != nil && t.Status != model.Skip {
			dohN++
			if t.Status == model.Pass {
				dohOK++
			}
		}
	}
	switch {
	case dotN > 0 && dotOK == 0 && dohOK > 0:
		a.add(model.Warn, "dns", "PUB-DOT-BLOCKED", "DNS-over-TLS (port 853) is blocked; DNS-over-HTTPS works", "Every DoT attempt failed while DoH succeeded, which means TCP/853 is filtered.", "If you want encrypted DNS on the router, use DoH (UniFi 'DNS Shield' uses DoH). Otherwise check firewall rules for TCP 853.")
	case dotN+dohN > 0 && dotOK+dohOK == 0:
		a.add(model.Warn, "dns", "PUB-ENCRYPTED-BLOCKED", "Encrypted DNS (DoT and DoH) does not work", "All DNS-over-TLS and DNS-over-HTTPS attempts failed. Either TLS is intercepted, the clock is wrong, or these endpoints are blocked.", "Check the TLS/clock findings and firewall rules for TCP 853/443 to the resolver IPs.")
	case dotOK+dohOK > 0:
		a.add(model.Pass, "dns", "PUB-ENCRYPTED-OK", fmt.Sprintf("Encrypted DNS works (DoT %d/%d, DoH %d/%d)", dotOK, dotN, dohOK, dohN), "Encrypted DNS to public resolvers is possible from this network.", "")
	}

	// TCP/53 to the internet as a whole.
	tcpBad, tcpN := 0, 0
	for _, r := range pub {
		if r.Reachable {
			tcpN++
			if t := r.Test("tcp"); t != nil && t.Status != model.Pass {
				tcpBad++
			}
		}
	}
	if tcpN > 0 && tcpBad == tcpN {
		a.add(model.Warn, "dns", "PUB-TCP-BLOCKED", "DNS over TCP to the internet is blocked", fmt.Sprintf("All %d reachable public resolvers failed over TCP/53 while UDP worked. A firewall is blocking outbound TCP port 53, which breaks large DNS answers for any resolver outside your network.", tcpN), "Allow outbound TCP/53 (at least from your router/local resolver).")
	}

	// Fastest provider per family (meaningless if answers are intercepted).
	for _, f := range []int{4, 6} {
		if a.intercepted {
			break
		}
		var best *model.ResolverResult
		for _, r := range pub {
			if r.Family == f && r.Reachable && r.Latency.Received > 0 && (best == nil || r.Latency.MedianMS < best.Latency.MedianMS) {
				best = r
			}
		}
		if best == nil {
			continue
		}
		var lines []string
		for _, r := range pub {
			if r.Family == f && r.Reachable && r.Latency.Received > 0 {
				lines = append(lines, fmt.Sprintf("%s %s: median %.1f ms, uncached %.0f ms", r.Label, r.Addr, r.Latency.MedianMS, r.ColdMS))
			}
		}
		a.add(model.Info, "performance", fmt.Sprintf("PUB-FASTEST-V%d", f), fmt.Sprintf("Fastest public resolver over IPv%d: %s (%.1f ms)", f, best.Provider, best.Latency.MedianMS), "Cached-query latency from this location. Useful when choosing the router's upstream DNS.", "", lines...)
	}
}

// ---------------------------------------------------------------- interception

func (a *az) interception() {
	in := a.r.Interception
	var ev []string
	for _, b := range in.BogonProbes {
		ev = append(ev, b.Name+": "+b.Detail)
	}
	if in.Detected {
		a.add(model.Fail, "security", "INTERCEPT-BOGON", "DNS traffic is being transparently intercepted", "A query sent to an address that cannot host a DNS server (TEST-NET / documentation range) received an answer. A router, ISP or security appliance is redirecting all port-53 traffic to its own resolver, so the public resolvers you think you are using are not the ones answering.", "If it is your own router (e.g. a 'force DNS' / DNS redirect NAT rule, UniFi Content Filtering, Pi-hole interception) this may be intentional. Otherwise use DoH/DoT to bypass, and ask the ISP.", ev...)
		a.conf(confirmed)
		a.intercepted = true
	}

	// Indicators are graded. Strong: things a genuine public resolver never
	// does (rewrite NXDOMAIN, fail example.com, several providers sharing one
	// egress). Weak: things with innocent explanations (egress ASN differs —
	// providers use partner networks/new ASNs; same software string as the
	// local resolver — both could simply run the same software).
	pub := a.resolvers("public")
	var strong, weak []string
	strongAddrs := map[string]bool{}
	egressByProv := map[string]map[string]bool{}
	for _, r := range pub {
		if r.Egress.Matches == "no" {
			weak = append(weak, fmt.Sprintf("%s %s was resolved from AS%s %s (egress %s), not the provider's usual network", r.Label, r.Addr, r.Egress.ASN, r.Egress.ASName, r.Egress.IP))
		}
		if r.Egress.IP != "" {
			if egressByProv[r.Egress.IP] == nil {
				egressByProv[r.Egress.IP] = map[string]bool{}
			}
			egressByProv[r.Egress.IP][r.ProviderKey] = true
		}
	}
	for ip, provs := range egressByProv {
		if len(provs) > 1 {
			var ks []string
			for k := range provs {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			strong = append(strong, fmt.Sprintf("different providers (%s) all reached authoritative servers from the same address %s", strings.Join(ks, ", "), ip))
			for _, k := range ks {
				strongAddrs["egress:"+k] = true
			}
		}
	}
	localIDs := map[string]bool{}
	for _, r := range a.resolvers("system", "stub", "gateway") {
		if v := r.Identity["version.bind"]; v != "" && r.ProviderKey == "" {
			localIDs[v] = true
		}
	}
	for _, r := range pub {
		if v := r.Identity["version.bind"]; v != "" && localIDs[v] {
			weak = append(weak, fmt.Sprintf("%s %s reports the same software version as your local resolver (%q)", r.Label, r.Addr, v))
		}
		if r.NXDOMAIN == "hijacked" {
			strong = append(strong, fmt.Sprintf("%s %s rewrote NXDOMAIN (public resolvers never do this)", r.Label, r.Addr))
			strongAddrs[r.Addr] = true
		}
		if t := r.Test("udp_a"); t != nil && r.Reachable && t.Status == model.Warn && !r.Filters() {
			strong = append(strong, fmt.Sprintf("%s %s returned %s for example.com (a public resolver always resolves it)", r.Label, r.Addr, t.Rcode))
			strongAddrs[r.Addr] = true
		}
	}
	all := append(append([]string{}, strong...), weak...)
	switch {
	case len(strongAddrs) >= 2 || (in.Detected && len(all) > 0):
		a.intercepted = true
		a.add(model.Fail, "security", "INTERCEPT-PUBLIC", "Queries to public resolvers are answered by someone else", "Several independent checks show that queries addressed to well-known public resolvers are answered by a different system. This is DNS redirection somewhere between this host and the internet.", "Check the router for DNS redirect/'force local DNS' rules. To bypass an ISP-level redirect, use encrypted DNS (DoH/DoT).", all...)
		a.conf(confirmed)
	case len(strong) > 0 || len(weak) > 0:
		a.intercepted = in.Detected || len(strong) > 0
		a.add(model.Warn, "security", "INTERCEPT-SUSPECTED", "Possible DNS interception (not confirmed)", "Some answers from public resolvers do not look like they came from the provider. This can be interception, but there are innocent explanations: providers sometimes resolve from partner networks or newly acquired ASNs, the ASN database can lag, and two resolvers can run identical software.", "Confirm with the bogon probe (already run — see Interception & integrity) and by comparing DoH results, which cannot be transparently redirected. If DoH answers differ from plain DNS, interception is real.", all...)
		a.conf(suspected)
	case !in.Detected && len(pub) > 0:
		checked := 0
		for _, r := range pub {
			if r.Egress.Matches == "yes" {
				checked++
			}
		}
		if checked > 0 {
			a.add(model.Pass, "security", "INTERCEPT-NONE", "No DNS interception detected", fmt.Sprintf("Bogon probes got no reply, and %d public resolver answers were verified to come from the provider's own network (egress ASN check).", checked), "", ev...)
			a.conf(confirmed)
		} else {
			a.add(model.Info, "security", "INTERCEPT-INCONCLUSIVE", "DNS interception check was inconclusive", "Bogon probes got no reply, but no public resolver answer could be traced back to its provider's network (the egress echo names or the ASN lookup did not answer), so redirection cannot be ruled out.", "Re-run when the network is stable; check the egress table in the report.", ev...)
			a.conf(inconclusive)
		}
	}
	// ECS privacy note for local upstream.
	for _, r := range a.resolvers("system") {
		if r.Egress.ECS != "" && r.Egress.ECS != "0.0.0.0/0" {
			a.add(model.Info, "privacy", "SYS-ECS", "Your resolver sends EDNS Client Subnet ("+r.Egress.ECS+")", "Part of your IP address is forwarded to authoritative DNS servers. It improves CDN routing at a small privacy cost.", "Use a resolver that does not send ECS (Cloudflare, Quad9) if this matters to you.", r.Addr)
			break
		}
	}
}

// ---------------------------------------------------------------- routing

func (a *az) routing() {
	defIf := map[int]string{}
	for _, g := range a.r.System.Gateways {
		if _, ok := defIf[g.Family]; !ok {
			defIf[g.Family] = g.Interface
		}
	}
	var viaVPN []string
	for _, c := range a.r.Routing.Choices {
		if c.VPN {
			viaVPN = append(viaVPN, fmt.Sprintf("%s (%s) → interface %s, source %s", c.Dest, c.Label, c.Interface, c.LocalAddr))
		}
	}
	if len(viaVPN) > 0 {
		a.add(model.Info, "routing", "ROUTE-VPN", "Some DNS/internet traffic is routed through a VPN interface", "The kernel routes these destinations through a tunnel-like interface. DNS answers and latency will reflect the VPN, not your local network.", "Expected if a VPN is active. If not, look for leftover VPN routes or a 'kill switch'.", viaVPN...)
	}
	var pathEv []string
	for _, c := range a.r.Routing.Choices {
		if c.Error != "" {
			pathEv = append(pathEv, fmt.Sprintf("%s (%s): no route — %s", c.Dest, c.Label, c.Error))
		} else {
			pathEv = append(pathEv, fmt.Sprintf("%s (%s): via %s, source %s, on-link=%v", c.Dest, c.Label, c.Interface, c.LocalAddr, c.OnLink))
		}
	}
	if len(pathEv) > 0 {
		a.add(model.Info, "routing", "ROUTE-CHOICES", "Route selection for DNS servers", "Which interface and source address the OS picks for each resolver.", "", pathEv...)
	}
	traceNoted := false
	for _, t := range a.r.Routing.Traces {
		if t.Error != "" && len(t.Hops) == 0 {
			if !traceNoted {
				a.add(model.Info, "routing", "TRACE-UNAVAILABLE", "Traceroute could not run", t.Error, "")
				traceNoted = true
			}
			continue
		}
		sev := model.Pass
		title := fmt.Sprintf("Path traced: %s (%d hops)", t.Label, len(t.Hops))
		if !t.Reached {
			sev = model.Info
			title = fmt.Sprintf("Traceroute did not reach the destination: %s", t.Label)
		}
		a.add(sev, "routing", fmt.Sprintf("TRACE-V%d", t.Family), title, "Not reaching the destination is common (ICMP filtering) and is only meaningful together with failed connectivity tests.", "", hopsEv(t)...)
	}
}

// layerOf assigns a finding to a hop of the path device → LAN → gateway →
// internet → DNS → websites.
func layerOf(f model.Finding) string {
	id := f.ID
	has := func(p ...string) bool {
		for _, x := range p {
			if strings.HasPrefix(id, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("WEB-"):
		return "web"
	case has("PING-GW", "LOCAL-NAMES", "WPAD"):
		return "lan"
	case has("GW-", "DOUBLE-NAT", "REBIND", "DDR", "CANARY", "LOCAL-ENC"):
		return "gateway"
	case has("CLOCK", "NTP-OFFSET", "STUB-", "OS-", "SYS-WIN", "ROUTE-", "COVERAGE", "SYS-NONE"):
		return "device"
	case has("CONN-", "DUALSTACK", "PING-", "MTU-", "CGNAT", "NTP-", "CAPTIVE", "HTTP-", "NAT64", "TRACE", "TLS-INTERCEPT"):
		return "internet"
	}
	return "dns"
}

func layers(fs []model.Finding) []model.Layer {
	defs := []model.Layer{
		{Key: "device", Name: "This device"}, {Key: "lan", Name: "Wi-Fi / LAN"}, {Key: "gateway", Name: "Router"},
		{Key: "internet", Name: "Internet path"}, {Key: "dns", Name: "DNS"}, {Key: "web", Name: "Websites"},
	}
	rank := map[string]int{"unknown": 0, model.Pass: 1, model.Warn: 2, model.Fail: 3}
	for i := range defs {
		l := &defs[i]
		l.Status = "unknown"
		n := map[string]int{}
		for _, f := range fs {
			if f.Layer != l.Key || f.Severity == model.Info {
				continue
			}
			n[f.Severity]++
			if rank[f.Severity] > rank[l.Status] {
				l.Status = f.Severity
				if f.Severity != model.Pass {
					l.Note = f.Title
				}
			}
		}
		switch l.Status {
		case "unknown":
			l.Note = "not tested"
		case model.Pass:
			l.Note = fmt.Sprintf("%d checks passed", n[model.Pass])
		default:
			if extra := n[model.Fail] + n[model.Warn] - 1; extra > 0 {
				l.Note += fmt.Sprintf(" (+%d more)", extra)
			}
		}
	}
	return defs
}
