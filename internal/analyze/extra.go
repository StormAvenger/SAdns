package analyze

import (
	"fmt"
	"math"
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
		if r.Caching == "no" && r.OnLink {
			noCache = append(noCache, who)
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
	if rebindValid && len(rebindOn) > 0 {
		a.add(model.Info, "security", "REBIND-ON", "DNS rebinding protection is active", "Public names that point to private addresses are blocked. This protects against DNS-rebinding attacks, but also breaks services that deliberately use such names (Plex *.plex.direct, nip.io/sslip.io, some smart-home and self-hosted setups) — a frequent cause of 'works remotely but not at home'.", "If a local service fails, whitelist its domain (dnsmasq: rebind-domain-ok=/plex.direct/; UniFi: add a DNS exception; Pi-hole: REBIND_DOMAIN_OK).", rebindOn...)
	}
	if rebindValid && len(rebindOff) > 0 {
		a.add(model.Info, "security", "REBIND-OFF", "No DNS rebinding protection on your resolver", "Public names may resolve to private IPs. Malicious websites can use this to reach devices on your LAN (routers, NAS, IoT) from your browser.", "Optional hardening: enable rebinding protection on the router/resolver (dnsmasq stop-dns-rebind, Unbound private-address).", rebindOff...)
	}
	if len(noCache) > 0 {
		a.add(model.Info, "performance", "NO-CACHE", "Local resolver does not appear to cache answers", "TTLs did not count down between two lookups, so repeat lookups may go upstream every time.", "Enable caching on the router/resolver (dnsmasq cache-size).", noCache...)
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
