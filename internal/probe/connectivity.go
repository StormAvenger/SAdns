package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/dnsclient"
	"github.com/StormAvenger/SAdns/internal/dnswire"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

var connTargets = []struct {
	addr, name string
}{
	{"1.1.1.1", "Cloudflare"},
	{"8.8.8.8", "Google"},
	{"9.9.9.9", "Quad9"},
	{"2606:4700:4700::1111", "Cloudflare"},
	{"2001:4860:4860::8888", "Google"},
	{"2620:fe::fe", "Quad9"},
}

// tcpProbe opens a TCP connection to addr:port and reports timing.
func (e *Engine) tcpProbe(ctx context.Context, ip netip.Addr, port uint16, name string) model.Probe {
	ap := netip.AddrPortFrom(ip, port)
	p := model.Probe{Target: ap.String(), Name: name, Family: 4}
	if ip.Is6() && !ip.Is4In6() {
		p.Family = 6
	}
	d := net.Dialer{Timeout: e.cfg.Timeout + time.Second}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", ap.String())
	p.RTTMS = ms(time.Since(start))
	if err != nil {
		p.Error = err.Error()
		p.ErrClass = dnsclient.Classify(err)
		return p
	}
	p.OK = true
	p.LocalAddr = c.LocalAddr().String()
	c.Close()
	return p
}

func (e *Engine) connectivity(ctx context.Context) model.Connectivity {
	var c model.Connectivity
	c.IPv4.HasAddress = e.sys.HasAddr(4)
	c.IPv6.HasAddress = e.sys.HasAddr(6)
	c.IPv6.HasGlobal = e.sys.HasGlobalV6()
	c.IPv4.HasGlobal = c.IPv4.HasAddress
	c.IPv4.HasGateway = e.sys.HasGateway(4)
	c.IPv6.HasGateway = e.sys.HasGateway(6)

	c.IPv4.Disabled, c.IPv6.Disabled = !e.cfg.IPv4, !e.cfg.IPv6
	probes := make([]model.Probe, len(connTargets))
	var wg sync.WaitGroup
	for i, t := range connTargets {
		if a := netip.MustParseAddr(t.addr); (a.Is4() && !e.cfg.IPv4) || (a.Is6() && !e.cfg.IPv6) {
			probes[i] = model.Probe{Target: t.addr, Name: t.name, Family: map[bool]int{true: 4, false: 6}[a.Is4()], Error: "disabled by option", ErrClass: "disabled"}
			continue
		}
		wg.Add(1)
		go func(i int, addr, name string) {
			defer wg.Done()
			probes[i] = e.tcpProbe(ctx, netip.MustParseAddr(addr), 443, name)
		}(i, t.addr, t.name)
	}
	wg.Wait()
	for _, p := range probes {
		if p.Family == 4 {
			c.IPv4.Probes = append(c.IPv4.Probes, p)
			c.IPv4.Working = c.IPv4.Working || p.OK
		} else {
			c.IPv6.Probes = append(c.IPv6.Probes, p)
			c.IPv6.Working = c.IPv6.Working || p.OK
		}
	}
	return c
}

// publicIP queries Cloudflare's trace endpoint over each family. It also
// yields a trustworthy server timestamp for clock-skew detection.
func (e *Engine) publicIP(ctx context.Context, conn model.Connectivity) model.PublicIP {
	var p model.PublicIP
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if e.cfg.IPv4 {
			p.IPv4 = e.trace(ctx, "1.1.1.1", conn.IPv4.Working)
		} else {
			p.IPv4.Error = "disabled by option"
		}
	}()
	go func() {
		defer wg.Done()
		if e.cfg.IPv6 {
			p.IPv6 = e.trace(ctx, "2606:4700:4700::1111", conn.IPv6.Working)
		} else {
			p.IPv6.Error = "disabled by option"
		}
	}()
	wg.Wait()
	// CGNAT: only an address in 100.64.0.0/10 on the interface that carries
	// the default route counts. Overlays (Tailscale, ZeroTier, WireGuard…)
	// use the same range on their own interfaces and must not trigger it.
	gwIf := map[string]bool{}
	for _, g := range e.sys.Gateways {
		if g.Family == 4 {
			gwIf[g.Interface] = true
		}
	}
	for _, ifc := range e.sys.Interfaces {
		for _, a := range ifc.Addrs {
			if a.Scope != "cgnat" || !ifc.Up {
				continue
			}
			switch {
			case ifc.LikelyVPN:
				p.Notes = append(p.Notes, fmt.Sprintf("interface %s has %s from 100.64.0.0/10 — an overlay/VPN address (e.g. Tailscale), not ISP CGNAT", ifc.Name, a.IP))
			case gwIf[ifc.Name] || len(gwIf) == 0:
				p.CGNAT = true
				p.Notes = append(p.Notes, fmt.Sprintf("default-route interface %s has carrier-grade NAT address %s", ifc.Name, a.IP))
			default:
				p.Notes = append(p.Notes, fmt.Sprintf("interface %s has %s from 100.64.0.0/10 but does not carry the default route", ifc.Name, a.IP))
			}
		}
	}
	if ip, err := netip.ParseAddr(p.IPv4.IP); err == nil && !e.sys.IsLocalIP(ip) && p.IPv4.OK {
		p.Notes = append(p.Notes, "IPv4 is NATed (public address differs from any local interface address)")
	}
	if ip, err := netip.ParseAddr(p.IPv6.IP); err == nil && p.IPv6.OK {
		if e.sys.IsLocalIP(ip) {
			p.Notes = append(p.Notes, "IPv6 is end-to-end (public address is assigned to this host)")
		} else {
			p.Notes = append(p.Notes, "IPv6 public address is NOT on this host (NPTv6/NAT66 or proxy in the path)")
		}
	}
	return p
}

func (e *Engine) trace(ctx context.Context, ip string, familyWorking bool) model.TraceInfo {
	var ti model.TraceInfo
	addr := netip.AddrPortFrom(netip.MustParseAddr(ip), 443)
	nd := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return nd.DialContext(ctx, "tcp", addr.String())
		},
		TLSClientConfig:     &tls.Config{ServerName: "one.one.one.one"},
		TLSHandshakeTimeout: 6 * time.Second,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	body, resp, err := get(ctx, cl, "https://one.one.one.one/cdn-cgi/trace")
	e.meter.note(int64(len(body)))
	ti.Method = "https://one.one.one.one/cdn-cgi/trace via " + ip
	recv := time.Now()
	if err != nil {
		var ve *tls.CertificateVerificationError
		if errors.As(err, &ve) || strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "tls:") {
			ti.Error = "TLS verification failed: " + err.Error()
		} else {
			ti.Error = err.Error()
		}
		// Fall back to plain HTTP so we still learn the public IP.
		addr80 := netip.AddrPortFrom(addr.Addr(), 80)
		tr2 := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return nd.DialContext(ctx, "tcp", addr80.String())
		}}
		defer tr2.CloseIdleConnections()
		body, resp, err = get(ctx, &http.Client{Transport: tr2, Timeout: 6 * time.Second}, "http://one.one.one.one/cdn-cgi/trace")
		e.meter.note(int64(len(body)))
		recv = time.Now()
		if err == nil {
			ti.Method = "http://one.one.one.one/cdn-cgi/trace via " + ip + " (HTTPS failed)"
		}
	}
	if err == nil {
		ti.OK = true
		kv := map[string]string{}
		for _, l := range strings.Split(body, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				kv[k] = strings.TrimSpace(v)
			}
		}
		ti.IP, ti.Colo, ti.Loc, ti.Warp, ti.TLS = kv["ip"], kv["colo"], kv["loc"], kv["warp"], kv["tls"]
		if ts, perr := strconv.ParseFloat(kv["ts"], 64); perr == nil && strings.HasPrefix(ti.Method, "https://") && ti.Error == "" {
			server := time.Unix(0, int64(ts*1e9))
			ti.ClockSkew = round2(recv.Sub(server).Seconds())
			ti.ClockKnown = true
		}
		if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			ti.CertIssuer = c.Issuer.CommonName
		}
		return ti
	}
	// Last resort: ask Cloudflare's DNS who we are (CHAOS whoami).
	q := dnswire.NewQuery("whoami.cloudflare", dnswire.TypeTXT, dnswire.QueryOpts{Class: dnswire.ClassCHAOS})
	r := dnsclient.Exchange(ctx, dnsclient.Endpoint{Addr: netip.AddrPortFrom(addr.Addr(), 53), Proto: dnsclient.UDP}, q, e.cfg.Timeout)
	if r.OK() && len(r.Msg.TXT()) > 0 {
		ti.OK = true
		ti.IP = r.Msg.TXT()[0]
		ti.Method = "DNS whoami.cloudflare CH TXT via " + ip + " (HTTP failed)"
		return ti
	}
	if !familyWorking && ti.Error == "" {
		ti.Error = "no connectivity for this address family"
	}
	return ti
}

func get(ctx context.Context, cl *http.Client, url string) (string, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "SAdns")
	resp, err := cl.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != 200 {
		return "", resp, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(b), resp, err
}

var osLookupSet = []struct{ name, purpose, expect string }{
	{"example.com", "baseline (A + AAAA)", "v4+v6"},
	{"www.google.com", "popular dual-stack site", "v4+v6"},
	{"cloudflare.com", "popular dual-stack site", "v4+v6"},
	{"github.com", "IPv4-only site", "v4"},
	{"ipv6.google.com", "IPv6-only name", "v6"},
	{"www.wikipedia.org", "popular dual-stack site", "v4+v6"},
	{"localhost", "local name (hosts file)", "local"},
}

// osLookups resolves names through the operating system's resolver path
// (getaddrinfo / DnsQuery / mDNSResponder), as applications do.
func (e *Engine) osLookups(ctx context.Context) []model.OSLookup {
	set := append([]struct{ name, purpose, expect string }{}, osLookupSet...)
	set = append(set, struct{ name, purpose, expect string }{"sadns-nx-" + dnswire.RandomLabel(14) + ".com", "non-existent name (must fail)", "nxdomain"})
	out := make([]model.OSLookup, len(set))
	var wg sync.WaitGroup
	for i, s := range set {
		wg.Add(1)
		go func(i int, name, purpose, expect string) {
			defer wg.Done()
			l := model.OSLookup{Name: name, Purpose: purpose, Expected: expect}
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			start := time.Now()
			addrs, err := net.DefaultResolver.LookupNetIP(cctx, "ip", name)
			l.MS = ms(time.Since(start))
			if err != nil {
				l.Error = err.Error()
				var de *net.DNSError
				if expect == "nxdomain" && errors.As(err, &de) && de.IsNotFound {
					l.OK = true
				}
			} else {
				l.Resolved = true
				for _, a := range addrs {
					a = a.Unmap()
					l.Addrs = append(l.Addrs, a.String())
					if a.Is4() {
						l.HasV4 = true
					} else {
						l.HasV6 = true
					}
				}
				l.OK, l.Missing = evalFamilies(expect, l.HasV4, l.HasV6)
			}
			out[i] = l
		}(i, s.name, s.purpose, s.expect)
	}
	wg.Wait()
	return out
}

// evalFamilies checks a successful lookup against the record families the
// name is known to publish. A name expected to be dual-stack that comes back
// IPv4-only is NOT a pass: it means AAAA records are being filtered or lost.
func evalFamilies(expect string, v4, v6 bool) (bool, string) {
	switch expect {
	case "nxdomain":
		return false, "" // it resolved, but must not
	case "v4+v6":
		switch {
		case !v4 && !v6:
			return false, "A, AAAA"
		case !v6:
			return false, "AAAA"
		case !v4:
			return false, "A"
		}
	case "v4":
		if !v4 {
			return false, "A"
		}
	case "v6":
		if !v6 {
			return false, "AAAA"
		}
	}
	return true, ""
}

var dualStackHosts = []string{"www.google.com", "cloudflare.com", "www.wikipedia.org"}

func (e *Engine) dualStack(ctx context.Context, lookups []model.OSLookup) []model.DualStack {
	var out []model.DualStack
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range dualStackHosts {
		var l *model.OSLookup
		for i := range lookups {
			if lookups[i].Name == h {
				l = &lookups[i]
			}
		}
		if l == nil || !l.Resolved {
			continue
		}
		wg.Add(1)
		go func(l model.OSLookup) {
			defer wg.Done()
			d := model.DualStack{Host: l.Name, HasA: l.HasV4, HasAAAA: l.HasV6}
			var v4, v6 netip.Addr
			for _, s := range l.Addrs {
				a, _ := netip.ParseAddr(s)
				if a.Is4() && !v4.IsValid() {
					v4 = a
				}
				if a.Is6() && !v6.IsValid() {
					v6 = a
				}
			}
			if v4.IsValid() {
				p := e.tcpProbe(ctx, v4, 443, l.Name)
				d.V4 = &p
			}
			if v6.IsValid() {
				p := e.tcpProbe(ctx, v6, 443, l.Name)
				d.V6 = &p
			}
			mu.Lock()
			out = append(out, d)
			mu.Unlock()
		}(*l)
	}
	wg.Wait()
	return out
}

// routeChoice asks the kernel which source address/interface it would use.
func (e *Engine) routeChoice(dest netip.Addr, label string) model.RouteChoice {
	rc := model.RouteChoice{Dest: dest.String(), Label: label}
	rc.OnLink, _ = e.sys.OnLink(dest)
	c, err := net.Dial("udp", netip.AddrPortFrom(dest, 53).String())
	if err != nil {
		rc.Error = err.Error()
		return rc
	}
	defer c.Close()
	la, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return rc
	}
	rc.LocalAddr = la.Addr().WithZone("").String()
	if ifc := e.sys.InterfaceForIP(la.Addr()); ifc != nil {
		rc.Interface = ifc.Name
		rc.VPN = ifc.LikelyVPN
	}
	return rc
}

// bogonProbes send DNS queries to documentation addresses that cannot host a
// DNS server. Any answer proves a middlebox is intercepting port 53.
func (e *Engine) bogonProbes(ctx context.Context) []model.TestResult {
	var out []model.TestResult
	// Pick documentation addresses that are not on a local subnet (some
	// networks, including lab VMs, actually use TEST-NET ranges internally).
	var cands []string
	for _, a := range []string{"192.0.2.53", "198.51.100.53", "203.0.113.53"} {
		if on, _ := e.sys.OnLink(netip.MustParseAddr(a)); !on {
			cands = append(cands, a)
			break
		}
	}
	if on, _ := e.sys.OnLink(netip.MustParseAddr("2001:db8::53")); !on {
		cands = append(cands, "2001:db8::53")
	}
	for _, a := range cands {
		ap := netip.AddrPortFrom(netip.MustParseAddr(a), 53)
		q := dnswire.NewQuery(nameBasic, dnswire.TypeA, dnswire.QueryOpts{})
		r := dnsclient.Exchange(ctx, dnsclient.Endpoint{Addr: ap, Proto: dnsclient.UDP}, q, 2500*time.Millisecond)
		t := toTest("bogon_"+strings.ReplaceAll(a, ":", "_"), "DNS to non-existent server "+a, nameBasic+" A @"+a, r)
		if r.OK() {
			t.Status = model.Fail
			t.Detail = "a reply came back from an address that cannot run DNS — port 53 traffic is being transparently intercepted/redirected"
		} else {
			t.Status = model.Pass
			t.Detail = "no reply (" + r.ErrClass + ") — no transparent DNS interception detected on this path"
		}
		out = append(out, t)
	}
	return out
}

// asnLookup resolves an IP's origin ASN via Team Cymru's DNS service.
func (e *Engine) asnLookup(ctx context.Context, via netip.AddrPort, ip string) (asn, name string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	suffix := "origin.asn.cymru.com."
	if a.Unmap().Is6() {
		suffix = "origin6.asn.cymru.com."
	}
	ep := dnsclient.Endpoint{Addr: via, Proto: dnsclient.UDP}
	r := dnsclient.Exchange(ctx, ep, dnswire.NewQuery(dnswire.ReverseName(a, suffix), dnswire.TypeTXT, dnswire.QueryOpts{EDNS: true}), e.cfg.Timeout)
	if !r.OK() || len(r.Msg.TXT()) == 0 {
		return
	}
	asn, ok := parseCymruOrigin(r.Msg.TXT()[0])
	if !ok {
		return "", ""
	}
	r = dnsclient.Exchange(ctx, ep, dnswire.NewQuery("AS"+asn+".asn.cymru.com", dnswire.TypeTXT, dnswire.QueryOpts{EDNS: true}), e.cfg.Timeout)
	if r.OK() && len(r.Msg.TXT()) > 0 {
		parts := strings.Split(r.Msg.TXT()[0], "|")
		if len(parts) >= 5 {
			name = strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return asn, name
}

// parseCymruOrigin extracts the first origin ASN from a Team Cymru answer such
// as "13335 | 172.68.0.0/16 | US | arin | 2014-03-28". Anything malformed is
// treated as "unknown", never trusted and never allowed to panic.
func parseCymruOrigin(txt string) (string, bool) {
	first, _, _ := strings.Cut(txt, "|")
	f := strings.Fields(first) // multi-origin prefixes list several ASNs
	if len(f) == 0 || len(f[0]) > 10 {
		return "", false
	}
	for _, c := range f[0] {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return f[0], true
}

// scopeOf classifies a hop address.
func scopeOf(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return sysinfo.Classify(a)
}
