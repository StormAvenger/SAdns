package analyze

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/StormAvenger/SAdns/internal/model"
)

// resolverExtras applies the protocol-compliance and behaviour rules to the
// resolvers clients actually use (system, stub) and to user-specified ones.
func (a *az) resolverExtras() {
	// If public resolvers also "block" the rebinding test name, the test
	// domain itself is down and the result is meaningless.
	rebindValid := false
	for _, r := range a.resolvers("public") {
		if r.Rebind == "off" {
			rebindValid = true
		}
	}

	var dohOff, relayOff, ddr, rebindOn, rebindOff, noCache, encPorts []string
	for _, r := range a.resolvers("system", "stub", "custom") {
		if !r.Reachable {
			continue
		}
		who := r.Label + " (" + r.Addr + ")"
		pfx := map[string]string{"system": "SYS", "stub": "STUB", "custom": "CUSTOM"}[r.Role]
		if t := r.Test("case_0x20"); t != nil && t.Status == model.Warn {
			a.add(model.Warn, "dns", pfx+"-0X20", "Query names are rewritten on the way to "+who, t.Detail, "Look for a DNS-inspecting firewall/ALG or an old forwarder; disable DNS 'inspection'/'proxy' features on the router.", resEv(r, "case_0x20")...)
		}
		if t := r.Test("edns_version"); t != nil && t.Status == model.Warn {
			a.add(model.Warn, "dns", pfx+"-EDNS-VERSION", "Unusual EDNS queries are silently dropped by "+who, t.Detail, "Update the router/resolver firmware; disable DNS inspection on firewalls between client and resolver.", resEv(r, "edns_version")...)
		}
		if t := r.Test("https_rr"); t != nil && t.Status == model.Warn {
			a.add(model.Warn, "dns", pfx+"-HTTPS-RR", "Modern DNS record types fail via "+who, t.Detail+". Apple devices and Chromium query HTTPS records for every site and may stall waiting for them.", "Update the router firmware or point clients at a resolver that handles all record types (Unbound, AdGuard Home, Pi-hole v6, or a public resolver).", resEv(r, "https_rr")...)
		}
		if t := r.Test("burst"); t != nil && t.Status == model.Warn {
			a.add(model.Warn, "performance", pfx+"-BURST", "Resolver "+who+" drops queries under load", t.Detail, "Raise the resolver's concurrent-query limit (dnsmasq: dns-forward-max; Pi-hole: rate limit setting) or check router CPU.", resEv(r, "burst")...)
		}
		switch r.Rebind {
		case "on":
			rebindOn = append(rebindOn, who)
		case "off":
			rebindOff = append(rebindOff, who)
		}
		if (r.Caching == "no-cache" || r.Caching == "upstream-cache") && r.OnLink {
			noCache = append(noCache, who+": "+r.Caching)
		}
		if r.CanaryDoH == "disables-doh" {
			dohOff = append(dohOff, who)
		}
		if r.CanaryRelay == "blocks-relay" {
			relayOff = append(relayOff, who)
		}
		if len(r.DDR) > 0 {
			ddr = append(ddr, who+" → "+strings.Join(r.DDR, ", "))
		}
		if len(r.OpenPorts) > 0 {
			encPorts = append(encPorts, fmt.Sprintf("%s: TCP %v", who, r.OpenPorts))
		}
	}
	pubHasHTTPS := false
	for _, r := range a.resolvers("public") {
		if r.HTTPSRR == "records" {
			pubHasHTTPS = true
		}
	}
	for _, r := range a.resolvers("system", "stub", "custom") {
		if r.Reachable && r.HTTPSRR == "empty" {
			if pubHasHTTPS {
				a.add(model.Warn, "dns", "HTTPS-RR-STRIPPED", "HTTPS records are stripped by "+r.Label+" ("+r.Addr+")", "Public resolvers return HTTPS records for cloudflare.com but this resolver returns an empty answer. Browsers lose HTTP/3 and ECH hints and may do extra lookups.", "Update the resolver/router firmware; some filtering resolvers drop HTTPS records deliberately to stop ad bypass.", resEv(r, "https_rr")...)
				a.conf(confirmed)
			} else {
				a.add(model.Info, "dns", "HTTPS-RR-EMPTY", "No HTTPS records via "+r.Label+" ("+r.Addr+")", "No public resolver result was available to compare against, so stripping cannot be confirmed.", "", resEv(r, "https_rr")...)
				a.conf(inconclusive)
			}
		}
	}
	if rebindValid && len(rebindOn) > 0 {
		a.add(model.Info, "security", "REBIND-ON", "DNS rebinding protection is active", "Public names that point to private addresses are blocked. This protects against DNS-rebinding attacks, but also breaks services that deliberately use such names (Plex *.plex.direct, nip.io/sslip.io, some smart-home and self-hosted setups) — a frequent cause of 'works remotely but not at home'.", "If a local service fails, whitelist its domain (dnsmasq: rebind-domain-ok=/plex.direct/; UniFi: add a DNS exception; Pi-hole: REBIND_DOMAIN_OK).", rebindOn...)
		a.conf(confirmed)
	}
	if rebindValid && len(rebindOff) > 0 {
		a.add(model.Info, "security", "REBIND-OFF", "No DNS rebinding protection on your resolver", "Public names may resolve to private IPs. Malicious websites can use this to reach devices on your LAN (routers, NAS, IoT) from your browser.", "Optional hardening: enable rebinding protection on the router/resolver (dnsmasq stop-dns-rebind, Unbound private-address).", rebindOff...)
	}
	if len(noCache) > 0 {
		a.add(model.Info, "performance", "NO-CACHE", "Local resolver does not cache answers itself", "Repeating a just-resolved name was not answered at LAN speed, so every lookup travels upstream (upstream-cache = a cache further away answered; no-cache = nothing in the path cached).", "Enable caching on the router/resolver (dnsmasq cache-size; Pi-hole/AdGuard Home cache settings).", noCache...)
		a.conf(suspected)
	}
	var sig []string
	if len(dohOff) > 0 {
		sig = append(sig, "Firefox auto-DoH disabled by: "+strings.Join(dohOff, ", "))
	}
	if len(relayOff) > 0 {
		sig = append(sig, "iCloud Private Relay blocked by: "+strings.Join(relayOff, ", "))
	}
	if len(sig) > 0 {
		a.add(model.Info, "dns", "CANARY-SIGNALS", "Your network signals devices not to bypass its DNS", "Canary domains are answered negatively, so browsers/OSes keep using this resolver instead of their own encrypted DNS or relay. Typical for Pi-hole, AdGuard Home, UniFi content filtering and parental controls.", "Expected if you filter DNS; otherwise check the resolver's blocklists.", sig...)
	}
	if len(ddr) > 0 {
		a.add(model.Info, "dns", "DDR", "Resolver advertises encrypted DNS (DDR)", "Windows 11, macOS and iOS can automatically upgrade to the advertised DoH/DoT endpoint, so their queries may not use plain DNS to the router.", "", ddr...)
	}
	if len(encPorts) > 0 {
		a.add(model.Info, "dns", "LOCAL-ENC-PORTS", "Local resolver has encrypted-DNS ports open", "TCP 853 (DoT) or 443 (DoH or a web UI) answer on the resolver address.", "", encPorts...)
	}
}

// netHealth applies rules to ping, MTU, NTP, HTTP, NAT64 and local-name checks.
func (a *az) netHealth() {
	nh := a.r.Network
	pingAvail := false
	for _, p := range nh.Pings {
		if p.Error != "" && strings.Contains(p.Error, "not available") {
			continue
		}
		pingAvail = true
		ev := []string{fmt.Sprintf("%s: %d/%d replies, min/avg/max %.1f/%.1f/%.1f ms, jitter %.1f ms", p.Target, p.Received, p.Sent, p.MinMS, p.AvgMS, p.MaxMS, p.JitterMS)}
		gw := strings.HasPrefix(p.Label, "Default gateway")
		switch {
		case p.Received == 0 && gw:
			a.add(model.Info, "routing", "PING-GW-NONE", "Router does not answer ping", "The gateway ignores ICMP echo. Common on routers with WAN-hardening; only a problem if other tests also fail.", "", ev...)
		case p.Received == 0:
			a.add(model.Info, "routing", fmt.Sprintf("PING-NET-NONE-V%d", p.Family), fmt.Sprintf("Internet ping blocked (IPv%d)", p.Family), "No ICMP echo replies from 1.1.1.1 even though TCP works — ICMP is filtered somewhere. This also prevents path-MTU discovery.", "Allow ICMP echo/ICMPv6 on the firewall (ICMPv6 must not be blocked for IPv6 to work).", ev...)
		case gw && p.LossPct > 0:
			a.add(model.Warn, "performance", "PING-GW-LOSS", fmt.Sprintf("Packet loss to your router (%.0f%%)", p.LossPct), "Packets are lost before they even leave your home network. Every lost DNS packet costs a timeout (1–5 s).", "Check Wi-Fi signal/interference or the Ethernet cable/switch port; test on a wired connection.", ev...)
		case gw && p.AvgMS > 10:
			a.add(model.Warn, "performance", "PING-GW-SLOW", fmt.Sprintf("High latency to your router (avg %.0f ms)", p.AvgMS), "The first hop should answer in a few ms. High values usually mean a weak or congested Wi-Fi link.", "Move closer to the access point, use 5/6 GHz, or test wired.", ev...)
		case !gw && p.LossPct > 0:
			a.add(model.Warn, "performance", fmt.Sprintf("PING-NET-LOSS-V%d", p.Family), fmt.Sprintf("Packet loss to the internet over IPv%d (%.0f%%)", p.Family, p.LossPct), "Loss beyond your router points at the ISP link, modem or congestion.", "Check the modem's signal stats and the router's WAN interface errors; contact the ISP if it persists.", ev...)
		case p.JitterMS > 20:
			a.add(model.Info, "performance", "PING-JITTER", "High jitter: "+p.Label, "Latency varies a lot between packets (bufferbloat or wireless contention). Calls and games will stutter.", "Enable Smart Queues / SQM on the router.", ev...)
		default:
			a.add(model.Pass, "performance", fmt.Sprintf("PING-OK-%s", strings.ReplaceAll(p.Target, ":", "_")), fmt.Sprintf("Clean ping: %s (avg %.1f ms, 0%% loss)", p.Label, p.AvgMS), "", "", ev...)
		}
	}
	if !pingAvail && len(nh.Pings) > 0 {
		a.add(model.Info, "routing", "PING-UNAVAILABLE", "Ping tests skipped", "The system ping command is not available.", "")
	}

	for _, m := range nh.MTU {
		switch {
		case m.Error != "":
			a.add(model.Info, "routing", fmt.Sprintf("MTU-UNKNOWN-V%d", m.Family), fmt.Sprintf("Path MTU could not be measured (IPv%d)", m.Family), m.Error, "", m.Probes...)
		case m.MTU >= 1500:
			a.add(model.Pass, "routing", fmt.Sprintf("MTU-OK-V%d", m.Family), fmt.Sprintf("Full 1500-byte path MTU (IPv%d)", m.Family), m.Detail, "", m.Probes...)
		case m.MTU < 1400:
			a.add(model.Warn, "routing", fmt.Sprintf("MTU-LOW-V%d", m.Family), fmt.Sprintf("Small path MTU: %d bytes (IPv%d)", m.MTU, m.Family), m.Detail+". Large DNS/TLS packets need fragmentation or PMTUD; if ICMP is filtered anywhere, connections hang ('some sites never load').", "Set the router WAN MTU / MSS clamping to match the path, or fix the VPN MTU.", m.Probes...)
		default:
			a.add(model.Info, "routing", fmt.Sprintf("MTU-REDUCED-V%d", m.Family), fmt.Sprintf("Path MTU is %d bytes (IPv%d)", m.MTU, m.Family), m.Detail+".", "Normal for this link type as long as the router does MSS clamping.", m.Probes...)
		}
	}

	if len(nh.NTP) > 0 {
		ok := 0
		var ev []string
		var off float64
		for _, n := range nh.NTP {
			if n.OK {
				ok++
				off = n.OffsetMS
				ev = append(ev, fmt.Sprintf("%s (%s): offset %+.1f ms, delay %.1f ms, stratum %d", n.Server, n.Addr, n.OffsetMS, n.RTTMS, n.Stratum))
			} else {
				ev = append(ev, fmt.Sprintf("%s (%s): %s", n.Server, n.Addr, n.Error))
			}
		}
		switch {
		case ok == 0:
			a.add(model.Warn, "system", "NTP-BLOCKED", "Network time (NTP, UDP 123) is unreachable", "No NTP server answered. Devices that rely on NTP (routers, IoT, Linux servers, cameras) will drift; large clock errors break TLS, DoT/DoH and DNSSEC.", "Allow outbound UDP 123, or point devices at the router's NTP server.", ev...)
		case math.Abs(off) > 1000:
			a.add(model.Warn, "system", "NTP-OFFSET", fmt.Sprintf("This computer's clock is off by %.1f s", off/1000), "Measured against NTP servers.", "Enable automatic time sync in the OS settings.", ev...)
		default:
			a.add(model.Pass, "system", "NTP-OK", fmt.Sprintf("Network time reachable; clock offset %+.0f ms", off), "", "", ev...)
		}
	}

	if len(nh.HTTP) > 0 {
		ok, failed := 0, 0
		var bad, ev, proxies []string
		for _, h := range nh.HTTP {
			ev = append(ev, fmt.Sprintf("%s %s → %d %s (%.0f ms)", h.Name, h.URL, h.Status, nonEmpty(h.Detail, h.Error), h.MS))
			switch {
			case h.OK:
				ok++
			case h.Error != "":
				failed++
			default:
				bad = append(bad, h.Name+": "+h.Detail)
			}
			if h.Proxy != "" {
				proxies = append(proxies, h.Name+": "+h.Proxy)
			}
		}
		switch {
		case len(bad) > 0:
			a.add(model.Warn, "security", "CAPTIVE", "Captive portal or HTTP interception detected", "Operating-system connectivity checks did not get their expected answers. Phones/laptops will show 'sign in to network' or 'no internet' even if browsing works.", "Complete the portal login, or disable HTTP interception/filter pages on the router.", append(bad, ev...)...)
		case ok == len(nh.HTTP):
			a.add(model.Pass, "connectivity", "HTTP-OK", "OS connectivity checks pass (no captive portal)", "Google, Apple and Microsoft connectivity probes all returned their expected answers.", "", ev...)
		case failed == len(nh.HTTP):
			a.add(model.Warn, "connectivity", "HTTP-FAIL", "Plain HTTP connectivity checks failed", "The OS-style connectivity probes could not complete. Devices may report 'No internet'.", "Check whether outbound TCP 80 is blocked and that these names resolve.", ev...)
		}
		if len(proxies) > 0 {
			a.add(model.Info, "security", "HTTP-PROXY", "An HTTP proxy is in the path", "Responses carried proxy headers (Via/X-Cache). Plain-HTTP traffic is being proxied by the ISP, a corporate proxy or a security appliance.", "", proxies...)
		}
	}

	if nh.NAT64.Detected {
		a.add(model.Info, "connectivity", "NAT64", "DNS64/NAT64 network detected", nh.NAT64.Detail+". IPv4-only sites are reached via translation; IPv4 literals in apps may fail.", "", nh.NAT64.Prefixes...)
	}

	var wpad, missing, found []string
	for _, l := range nh.Local {
		switch l.Expected {
		case "absent":
			if !l.OK {
				wpad = append(wpad, fmt.Sprintf("%s → %s", l.Name, strings.Join(l.Addrs, ", ")))
			}
		case "local", "ptr":
			if l.OK {
				found = append(found, fmt.Sprintf("%s (%s) → %s", l.Name, l.Purpose, strings.Join(l.Addrs, ", ")))
			} else {
				missing = append(missing, fmt.Sprintf("%s (%s): %s", l.Name, l.Purpose, l.Error))
			}
		}
	}
	if len(wpad) > 0 {
		a.add(model.Warn, "security", "WPAD", "The name 'wpad' resolves on this network", "Browsers and Windows use WPAD to auto-discover a web proxy. If you did not set this up, anyone who controls that answer can intercept web traffic.", "Remove the wpad record (or block it on the resolver) and disable 'Automatically detect settings' unless you use a proxy.", wpad...)
	}
	if len(missing) > 0 {
		a.add(model.Info, "dns", "LOCAL-NAMES", "Some local names / reverse lookups do not resolve", "Local hostname or reverse (PTR) lookups failed. Not a fault, but it makes logs and device lists show IPs instead of names, and some apps (SSH, SMB, printers) resolve slowly while waiting.", "Enable 'register DHCP hostnames in DNS' / local domain on the router (UniFi: Settings → Networks → Domain Name).", append(missing, found...)...)
	} else if len(found) > 0 {
		a.add(model.Pass, "dns", "LOCAL-NAMES-OK", "Local names and reverse lookups resolve", "", "", found...)
	}
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// webLoads attributes slow loads to the responsible layer. Each row is the
// median of several fresh connections; conclusions are "observed in this
// scan", so they are at most suspected, never confirmed.
func (a *az) webLoads() {
	if len(a.r.Web) == 0 {
		return
	}
	// With Low Data Mode each resource is loaded once, so a timing finding
	// rests on a single measurement: report it with lower confidence.
	webConf, lowNote := suspected, ""
	if a.r.Data.ConfidenceAffected {
		webConf = inconclusive
		lowNote = " Low Data Mode was on: each resource was loaded only once per address family, so this is a single measurement — re-run in standard mode to confirm."
	}
	var ok []model.WebTiming
	var failed, flaky, limited []string
	for _, w := range a.r.Web {
		fam := ""
		if w.Family > 0 {
			fam = fmt.Sprintf(" IPv%d", w.Family)
		}
		switch {
		case w.OKRuns == 0 && w.FailedRuns == 0 && w.LimitedRuns > 0:
			limited = append(limited, fmt.Sprintf("%s%s: not tested — scan data budget reached", w.URL, fam))
		case w.OKRuns == 0:
			failed = append(failed, fmt.Sprintf("%s%s: %s", w.URL, fam, w.Error))
		case !w.OK:
			flaky = append(flaky, fmt.Sprintf("%s%s: %s", w.URL, fam, w.Error))
			ok = append(ok, w)
		default:
			ok = append(ok, w)
		}
	}
	outcome := map[string]string{
		model.OutcomeVerified: "complete, length verified", model.OutcomeComplete: "complete, no declared length to verify",
		model.OutcomeSampled: "sample only — stopped at the per-response limit, rest not downloaded",
	}
	line := func(w model.WebTiming) string {
		s := fmt.Sprintf("%s IPv%d: DNS %.0f · connect %.0f · TLS %.0f · first byte %.0f · transfer %.0f ms; measured %.0f ms end-to-end (%d/%d runs ok, range %.0f–%.0f ms, %s", w.Host, w.Family, w.DNSMS, w.ConnectMS, w.TLSMS, w.TTFBMS, w.DownloadMS, w.TotalMS, w.OKRuns, w.Runs, w.MinElapsedMS, w.MaxElapsedMS, w.Proto)
		if w.Redirects > 0 {
			s += fmt.Sprintf(", %d redirect(s) costing %.0f ms", w.Redirects, w.RedirectMS)
		}
		s += fmt.Sprintf(", %d bytes", w.Bytes)
		if w.RateKbps > 0 {
			s += fmt.Sprintf(" at %.0f kbit/s", w.RateKbps)
		}
		if o := outcome[w.Outcome]; o != "" {
			s += ", " + o
		}
		return s + ")"
	}
	ev := func(ws []model.WebTiming) []string {
		var out []string
		for _, w := range ws {
			out = append(out, line(w))
		}
		return out
	}
	if len(limited) > 0 {
		a.add(model.Info, "coverage", "WEB-BUDGET", fmt.Sprintf("%d website test(s) skipped: data budget reached", len(limited)), "The scan's HTTP download budget was used up before these could run. They were not tested — this is not a network failure.", "Run without Low Data Mode (or with fewer custom URLs) to test them.", limited...)
	}
	if len(ok) == 0 {
		if len(failed) > 0 {
			a.add(model.Warn, "connectivity", "WEB-FAIL", "Test web pages could not be loaded", "None of the HTTPS test resources loaded, even though lower-level tests ran.", "See the errors: TLS errors point at interception or a wrong clock; timeouts at filtering or routing.", failed...)
		}
		return
	}
	med := func(f func(model.WebTiming) float64) float64 {
		var v []float64
		for _, w := range ok {
			v = append(v, f(w))
		}
		sort.Float64s(v)
		return v[len(v)/2]
	}
	dns := med(func(w model.WebTiming) float64 { return w.DNSMS })
	con := med(func(w model.WebTiming) float64 { return w.ConnectMS })
	tlsT := med(func(w model.WebTiming) float64 { return w.TLSMS })
	ttfb := med(func(w model.WebTiming) float64 { return w.TTFBMS })
	tot := med(func(w model.WebTiming) float64 { return w.TotalMS })
	summary := fmt.Sprintf("Across %d site/family combinations (each loaded several times on fresh connections) the typical phases were: DNS %.0f ms, connect %.0f ms, TLS %.0f ms, first byte %.0f ms; typical measured end-to-end time %.0f ms. (Each figure is its own median, so they do not add up exactly.)", len(ok), dns, con, tlsT, ttfb, tot)
	caveat := " This is what this scan observed on a handful of single resources — not a full browser page load — so treat it as a strong lead rather than proof." + lowNote

	issue := false
	if dns > 150 && dns > con*2 {
		issue = true
		a.add(model.Warn, "performance", "WEB-DNS-BOTTLENECK", "DNS was the slowest step when loading the test sites", summary+" Name resolution took longer than connecting."+caveat, "Check the resolver findings (dead primary, slow upstream, IPv6 DNS timeouts) and re-run to see whether it repeats.", ev(ok)...)
		a.conf(webConf)
	}
	if tlsT > 400 && tlsT > con*4 {
		issue = true
		a.add(model.Warn, "performance", "WEB-TLS-SLOW", "TLS handshakes were slow while DNS and TCP were fast", summary+" The delay is in the encrypted handshake, not in DNS — changing DNS servers is unlikely to help."+caveat, "Look for TLS/SSL inspection (firewall, antivirus web shield), a struggling middlebox, or a CPU-starved router doing deep packet inspection.", ev(ok)...)
		a.conf(webConf)
	}
	if con > 250 {
		issue = true
		a.add(model.Warn, "performance", "WEB-CONNECT-SLOW", "TCP connections to websites were slow", summary+" High connect time means latency or loss on the path itself."+caveat, "Check the ping/packet-loss results and the ISP link.", ev(ok)...)
		a.conf(webConf)
	}
	// Per-resource: content transfer or server response dominating.
	var xfer, server []string
	for _, w := range ok {
		setup := w.DNSMS + w.ConnectMS + w.TLSMS
		if w.DownloadMS > 1000 && w.DownloadMS > 3*(setup+w.TTFBMS) {
			xfer = append(xfer, line(w))
		} else if w.TTFBMS > 1500 && w.TTFBMS > 4*setup {
			server = append(server, line(w))
		}
	}
	if len(xfer) > 0 {
		issue = true
		a.add(model.Warn, "performance", "WEB-TRANSFER-SLOW", "Content transfer is the slow part for some resources — not DNS", "For these resources, name resolution, connection and TLS were quick, and almost all the time went into receiving the content. Changing DNS servers will not help; the limit is throughput on the path, packet loss, or how fast that server/CDN delivers."+lowNote, "Compare IPv4 vs IPv6 rows and the packet-loss/MTU results; test the same URL on another network to tell your link from the CDN.", xfer...)
		a.conf(webConf)
	}
	if len(server) > 0 {
		issue = true
		a.add(model.Info, "performance", "WEB-SERVER-SLOW", "Some servers were slow to start responding", "Connection setup was quick but the server took long to send its first byte. That is usually the website itself (or a proxy in front of it), not your network.", "", server...)
		a.conf(webConf)
	}
	// IPv6 vs IPv4 for the same resource.
	by := map[string]map[int]model.WebTiming{}
	for _, w := range ok {
		if by[w.URL] == nil {
			by[w.URL] = map[int]model.WebTiming{}
		}
		by[w.URL][w.Family] = w
	}
	var slow6 []string
	for u, m := range by {
		v4, ok4 := m[4]
		v6, ok6 := m[6]
		if ok4 && ok6 && v6.ConnectMS+v6.TLSMS > 2*(v4.ConnectMS+v4.TLSMS)+80 {
			slow6 = append(slow6, fmt.Sprintf("%s: IPv6 connect+TLS %.0f ms vs IPv4 %.0f ms", u, v6.ConnectMS+v6.TLSMS, v4.ConnectMS+v4.TLSMS))
		}
	}
	sort.Strings(slow6)
	if len(slow6) > 0 {
		issue = true
		a.add(model.Warn, "performance", "WEB-V6-SLOWER", "Websites were noticeably slower over IPv6", "Browsers prefer IPv6, so a slower IPv6 path is felt on every dual-stack site.", "Compare the IPv6 ping/MTU results; check the router's IPv6 path, tunnel or MTU.", slow6...)
		a.conf(webConf)
	}
	if len(failed)+len(flaky) > 0 {
		issue = true
		a.add(model.Warn, "connectivity", "WEB-PARTIAL", fmt.Sprintf("%d of %d website tests failed or were unreliable", len(failed)+len(flaky), len(a.r.Web)), "Other resources loaded, so this is specific to a site, an address family or it is intermittent. A response only counts as loaded when it ends in a complete 2xx answer (redirects are followed; cut-off transfers and error statuses fail).", "Compare which family/site fails; re-run to see whether it is intermittent.", append(append(failed, flaky...), ev(ok)...)...)
	}
	if !issue {
		sampled := 0
		for _, w := range ok {
			if w.SampledRuns > 0 {
				sampled++
			}
		}
		title := fmt.Sprintf("All %d website tests loaded completely (typical %.0f ms)", len(ok), tot)
		if sampled > 0 {
			title = fmt.Sprintf("All %d website tests succeeded (typical %.0f ms); %d were size-limited samples, not full downloads", len(ok), tot, sampled)
		}
		if lowNote != "" {
			title += " — limited sample (Low Data Mode)"
		}
		a.add(model.Pass, "performance", "WEB-OK", title, summary+lowNote, "", ev(ok)...)
		if lowNote != "" {
			a.conf(webConf)
		}
	}
}
