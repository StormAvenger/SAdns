package probe

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/dnsclient"
	"github.com/StormAvenger/SAdns/internal/dnswire"
	"github.com/StormAvenger/SAdns/internal/model"
)

// target is a resolver address to test.
type target struct {
	label   string
	role    string // system, stub, gateway, public, custom
	addr    netip.AddrPort
	primary bool
	prov    *Provider
	iface   string
	skipWhy string
}

func (t target) family() int {
	if t.addr.Addr().Unmap().Is4() {
		return 4
	}
	return 6
}

func ms(d time.Duration) float64 { return math.Round(float64(d.Microseconds())/10) / 100 }

func (e *Engine) query(ctx context.Context, ep dnsclient.Endpoint, name string, qtype uint16, o dnswire.QueryOpts) (dnsclient.Response, *dnswire.Msg) {
	q := dnswire.NewQuery(name, qtype, o)
	return dnsclient.Exchange(ctx, ep, q, e.cfg.Timeout), q
}

// toTest converts a response to a TestResult with a default status.
func toTest(id, title, query string, r dnsclient.Response) model.TestResult {
	t := model.TestResult{ID: id, Name: title, Query: query, RTTMS: ms(r.RTT), Size: r.Size}
	if r.Msg != nil {
		t.Rcode = dnswire.RcodeString(r.Msg.Rcode)
		t.Flags = r.Msg.FlagString()
		t.Answers = r.Msg.AnswerStrings()
		for _, x := range r.Msg.EDEs() {
			t.EDE = append(t.EDE, x.String())
		}
	}
	if r.Err != nil {
		t.Error = r.ErrClass + ": " + r.Err.Error()
	}
	return t
}

func (e *Engine) runResolver(ctx context.Context, t target) model.ResolverResult {
	res := model.ResolverResult{
		Label:     t.label,
		Role:      t.role,
		Addr:      t.addr.String(),
		Family:    t.family(),
		Primary:   t.primary,
		Interface: t.iface,
		DNSSEC:    "n/a",
		Filtering: "unknown",
		NXDOMAIN:  "unknown",
		Identity:  map[string]string{},
	}
	if t.prov != nil {
		res.Provider = t.prov.Name
		res.ProviderKey = t.prov.Key
	} else {
		res.Provider = map[string]string{"system": "OS-configured", "stub": "Local stub resolver", "gateway": "Default gateway", "custom": "User-specified"}[t.role]
	}
	if ok, ifn := e.sys.OnLink(t.addr.Addr()); ok {
		res.OnLink = true
		if res.Interface == "" {
			res.Interface = ifn
		}
	}
	if t.skipWhy != "" {
		res.Tests = append(res.Tests, model.TestResult{ID: "udp_a", Name: "UDP query (A)", Status: model.Skip, Detail: t.skipWhy})
		return res
	}

	udp := dnsclient.Endpoint{Addr: t.addr, Proto: dnsclient.UDP}
	tcp := dnsclient.Endpoint{Addr: t.addr, Proto: dnsclient.TCP}

	// 1. Basic reachability: A over UDP with EDNS + NSID (one retry).
	r, _ := e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, NSID: true})
	if !r.OK() {
		r2, _ := e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, NSID: true})
		if r2.OK() {
			r = r2
			res.Latency.Sent++ // count the lost first try
		} else if r2.Msg != nil {
			r = r2
		}
	}
	if r.LocalAddr != "" {
		res.LocalAddr = r.LocalAddr
		if ap, err := netip.ParseAddrPort(r.LocalAddr); err == nil {
			if ifc := e.sys.InterfaceForIP(ap.Addr()); ifc != nil {
				res.Interface = ifc.Name
			}
		}
	}
	tr := toTest("udp_a", "UDP/53 query (A "+nameBasic+")", nameBasic+" A", r)
	switch {
	case r.OK() && r.Msg.Rcode == dnswire.RcodeSuccess && len(r.Msg.Addrs()) > 0:
		tr.Status, tr.Detail = model.Pass, fmt.Sprintf("answered in %.1f ms", tr.RTTMS)
		res.Reachable = true
	case r.OK() && r.Msg.Rcode == dnswire.RcodeRefused:
		tr.Status, tr.Detail = model.Fail, "server answered but REFUSED recursion for this client"
		res.Reachable = true
	case r.OK():
		tr.Status, tr.Detail = model.Warn, "server answered with "+tr.Rcode+" and no usable address"
		res.Reachable = true
	default:
		tr.Status, tr.Detail = model.Fail, "no response over UDP/53 ("+r.ErrClass+")"
	}
	res.Tests = append(res.Tests, tr)
	var basic *dnswire.Msg
	if r.OK() {
		basic = r.Msg
	}

	// 2. TCP/53 (always tried, even if UDP failed — distinguishes UDP blocking).
	rt, _ := e.query(ctx, tcp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	tt := toTest("tcp", "TCP/53 query", nameBasic+" A", rt)
	switch {
	case rt.OK() && rt.Msg.Rcode == dnswire.RcodeSuccess:
		tt.Status, tt.Detail = model.Pass, fmt.Sprintf("answered in %.1f ms (connect %.1f ms)", tt.RTTMS, ms(rt.Connect))
		if !res.Reachable {
			res.Reachable = true
			tt.Detail += " — TCP works while UDP does not"
		}
	case rt.OK():
		tt.Status, tt.Detail = model.Warn, "TCP answered with "+tt.Rcode
	default:
		tt.Status, tt.Detail = model.Warn, "TCP/53 failed ("+rt.ErrClass+") — responses larger than the UDP limit will fail"
	}
	res.Tests = append(res.Tests, tt)

	if !res.Reachable {
		for _, id := range []string{"udp_aaaa", "latency", "edns", "tc_fallback", "edns_large", "dnssec", "nxdomain", "filtering", "identity", "egress"} {
			res.Tests = append(res.Tests, model.TestResult{ID: id, Name: id, Status: model.Skip, Detail: "resolver unreachable"})
		}
		if t.prov != nil && e.cfg.Encrypted {
			e.encryptedTests(ctx, t, &res)
		}
		return res
	}

	// 3. AAAA.
	r6, _ := e.query(ctx, udp, nameBasic, dnswire.TypeAAAA, dnswire.QueryOpts{EDNS: true})
	t6 := toTest("udp_aaaa", "AAAA query", nameBasic+" AAAA", r6)
	switch {
	case r6.OK() && r6.Msg.Rcode == dnswire.RcodeSuccess && len(r6.Msg.Addrs()) > 0:
		t6.Status, t6.Detail = model.Pass, "IPv6 records returned"
	case r6.OK() && r6.Msg.Rcode == dnswire.RcodeSuccess:
		t6.Status, t6.Detail = model.Warn, "NOERROR but no AAAA records (AAAA filtering?)"
	case r6.OK():
		t6.Status, t6.Detail = model.Warn, "AAAA query returned "+t6.Rcode
	default:
		t6.Status, t6.Detail = model.Warn, "AAAA query failed ("+r6.ErrClass+")"
	}
	res.Tests = append(res.Tests, t6)

	// 4. Latency (cached) + one uncached lookup.
	var samples []float64
	for i := 0; i < e.cfg.Samples; i++ {
		res.Latency.Sent++
		rr, _ := e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		if rr.OK() {
			samples = append(samples, ms(rr.RTT))
		}
		time.Sleep(40 * time.Millisecond)
	}
	res.Latency = stats(res.Latency.Sent, samples)
	rc, _ := e.query(ctx, udp, dnswire.RandomLabel(12)+"."+nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	if rc.OK() {
		res.ColdMS = ms(rc.RTT)
	}
	lt := model.TestResult{ID: "latency", Name: "Latency (cached queries)", Status: model.Pass,
		Detail: fmt.Sprintf("%d/%d answered, median %.1f ms, p90 %.1f ms, jitter %.1f ms; uncached lookup %.1f ms",
			res.Latency.Received, res.Latency.Sent, res.Latency.MedianMS, res.Latency.P90MS, res.Latency.JitterMS, res.ColdMS)}
	if res.Latency.LossPct > 0 {
		lt.Status = model.Warn
	}
	res.Tests = append(res.Tests, lt)

	// 5. EDNS support (from the basic response).
	et := model.TestResult{ID: "edns", Name: "EDNS0 support"}
	if basic != nil && basic.EDNS != nil {
		et.Status = model.Pass
		et.Detail = fmt.Sprintf("EDNS%d, server UDP payload %d", basic.EDNS.Version, basic.EDNS.UDPSize)
		if n := basic.NSID(); n != "" {
			res.Identity["nsid"] = n
			et.Detail += ", NSID=" + n
		}
		if !basic.RA {
			et.Detail += "; RA flag NOT set (server says recursion unavailable)"
			et.Status = model.Warn
		}
	} else if basic != nil {
		et.Status, et.Detail = model.Warn, "no OPT record in response — server or a middlebox strips EDNS (breaks DNSSEC and large answers)"
	} else {
		et.Status, et.Detail = model.Skip, "no basic response to inspect"
	}
	res.Tests = append(res.Tests, et)

	// 6. Truncation + TCP fallback, and large UDP delivery.
	rs, _ := e.query(ctx, udp, ".", dnswire.TypeDNSKEY, dnswire.QueryOpts{EDNS: true, DO: true, UDPSize: 512})
	rl, _ := e.query(ctx, tcp, ".", dnswire.TypeDNSKEY, dnswire.QueryOpts{EDNS: true, DO: true})
	tc := toTest("tc_fallback", "Truncation → TCP fallback", ". DNSKEY +dnssec bufsize=512", rs)
	tc.Size = rs.Size
	switch {
	case !rl.OK():
		tc.Status, tc.Detail = model.Fail, "large answer could not be fetched over TCP ("+rl.ErrClass+"); clients cannot recover from truncated UDP answers"
	case rs.OK() && rs.Msg.TC:
		tc.Status, tc.Detail = model.Pass, fmt.Sprintf("UDP answer truncated at 512-byte limit (TC=1); TCP retry returned %d bytes", rl.Size)
	case rs.OK() && rs.Size > 512:
		tc.Status, tc.Detail = model.Warn, fmt.Sprintf("server sent %d bytes over UDP despite a 512-byte limit (ignores EDNS buffer size)", rs.Size)
	case rs.OK():
		tc.Status, tc.Detail = model.Pass, fmt.Sprintf("answer fit in 512 bytes (%d); TCP retry returned %d bytes", rs.Size, rl.Size)
	default:
		tc.Status, tc.Detail = model.Warn, fmt.Sprintf("small-buffer UDP query failed (%s) but TCP returned %d bytes", rs.ErrClass, rl.Size)
	}
	res.Tests = append(res.Tests, tc)

	rb, _ := e.query(ctx, udp, ".", dnswire.TypeDNSKEY, dnswire.QueryOpts{EDNS: true, DO: true, UDPSize: 4096})
	lb := toTest("edns_large", "Large UDP response (>1 KB)", ". DNSKEY +dnssec bufsize=4096", rb)
	switch {
	case rb.OK() && !rb.Msg.TC:
		lb.Status, lb.Detail = model.Pass, fmt.Sprintf("received %d-byte UDP response intact", rb.Size)
	case rb.OK():
		lb.Status, lb.Detail = model.Pass, fmt.Sprintf("server capped UDP size and set TC (%d bytes) — safe behaviour", rb.Size)
	default:
		lb.Status, lb.Detail = model.Warn, "large UDP response never arrived ("+rb.ErrClass+") while small ones do — a firewall/middlebox drops big or fragmented DNS packets"
	}
	res.Tests = append(res.Tests, lb)

	// 7. DNSSEC validation.
	rg, _ := e.query(ctx, udp, nameDNSSECGood, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, DO: true, AD: true})
	rx, _ := e.query(ctx, udp, nameDNSSECBad, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, AD: true})
	dt := toTest("dnssec", "DNSSEC validation", nameDNSSECGood+" (signed) / "+nameDNSSECBad+" (bogus)", rx)
	adGood := rg.OK() && rg.Msg.AD
	switch {
	case rx.OK() && rx.Msg.Rcode == dnswire.RcodeServFail && adGood:
		res.DNSSEC, dt.Status, dt.Detail = "validating", model.Pass, "bogus zone rejected (SERVFAIL) and valid zone marked authentic (AD=1)"
	case rx.OK() && rx.Msg.Rcode == dnswire.RcodeServFail:
		res.DNSSEC, dt.Status, dt.Detail = "validating", model.Pass, "bogus zone rejected (SERVFAIL); AD bit not returned for valid zone"
	case rx.OK() && rx.Msg.Rcode == dnswire.RcodeSuccess && len(rx.Msg.Addrs()) > 0:
		res.DNSSEC, dt.Status, dt.Detail = "not-validating", model.Info, "returned addresses for a domain with broken signatures — resolver does not validate DNSSEC"
		if adGood {
			res.DNSSEC = "inconsistent"
			dt.Status, dt.Detail = model.Warn, "AD bit set on valid zone but bogus zone accepted — AD bit is being passed through without validation"
		}
	default:
		res.DNSSEC, dt.Status, dt.Detail = "inconclusive", model.Info, "bogus test zone returned "+dt.Rcode+dt.Error
	}
	if rg.Msg != nil {
		dt.Detail += fmt.Sprintf(" [signed zone: %s, flags %q]", dnswire.RcodeString(rg.Msg.Rcode), rg.Msg.FlagString())
	}
	res.Tests = append(res.Tests, dt)

	// 8. NXDOMAIN integrity.
	nxName := "sadns-nx-" + dnswire.RandomLabel(14) + ".com"
	rn, _ := e.query(ctx, udp, nxName, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	nt := toTest("nxdomain", "NXDOMAIN integrity", nxName+" A", rn)
	basicOK := tr.Status == model.Pass
	switch {
	case rn.OK() && rn.Msg.Rcode == dnswire.RcodeNXDomain && !basicOK:
		nt.Status, nt.Detail = model.Info, "inconclusive: this resolver also fails the control name "+nameBasic
	case rn.OK() && rn.Msg.Rcode == dnswire.RcodeNXDomain:
		res.NXDOMAIN, nt.Status, nt.Detail = "correct", model.Pass, "non-existent domain correctly returned NXDOMAIN"
	case rn.OK() && rn.Msg.Rcode == dnswire.RcodeSuccess && len(rn.Msg.Addrs()) > 0:
		res.NXDOMAIN, nt.Status, nt.Detail = "hijacked", model.Warn, "non-existent domain resolved to "+joinAddrs(rn.Msg.Addrs())+" — NXDOMAIN is being rewritten (ISP search/ads page or filter)"
	case rn.OK():
		nt.Status, nt.Detail = model.Info, "unexpected "+nt.Rcode
	default:
		nt.Status, nt.Detail = model.Warn, "query failed ("+rn.ErrClass+")"
	}
	res.Tests = append(res.Tests, nt)

	// 9. Ad/tracker filtering.
	ft := model.TestResult{ID: "filtering", Name: "Ad/tracker filtering", Status: model.Info, Query: strings.Join(adNames, ", ")}
	blocked, checked := 0, 0
	var fdet []string
	for _, n := range adNames {
		ra, _ := e.query(ctx, udp, n, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		if !ra.OK() {
			fdet = append(fdet, n+": "+ra.ErrClass)
			continue
		}
		checked++
		b, why := looksBlocked(ra.Msg)
		if b {
			blocked++
		}
		fdet = append(fdet, n+": "+why)
	}
	switch {
	case checked == 0:
		res.Filtering = "unknown"
	case !basicOK:
		res.Filtering = "unknown"
		fdet = append(fdet, "inconclusive: control name "+nameBasic+" does not resolve either")
	case blocked > 0:
		res.Filtering = "blocks-ads"
	default:
		res.Filtering = "no-ad-blocking"
	}
	ft.Detail = res.Filtering + " (" + strings.Join(fdet, "; ") + ")"
	res.Tests = append(res.Tests, ft)

	// 10. Server identity (CHAOS class) — fingerprints dnsmasq, Unbound, BIND, PoPs.
	var ids []string
	for _, n := range []string{"version.bind", "hostname.bind", "id.server"} {
		ri, _ := e.query(ctx, udp, n, dnswire.TypeTXT, dnswire.QueryOpts{Class: dnswire.ClassCHAOS, NoRD: true})
		if ri.OK() && ri.Msg.Rcode == dnswire.RcodeSuccess {
			if txt := ri.Msg.TXT(); len(txt) > 0 && txt[0] != "" {
				res.Identity[n] = txt[0]
				ids = append(ids, n+"="+txt[0])
			}
		}
	}
	res.Software = fingerprint(res.Identity)
	it := model.TestResult{ID: "identity", Name: "Server identity (CHAOS)", Status: model.Info, Detail: "no identity disclosed"}
	if len(ids) > 0 {
		it.Detail = strings.Join(ids, "; ")
	}
	if res.Software != "" {
		it.Detail += " → " + res.Software
	}
	res.Tests = append(res.Tests, it)

	// 11. Egress: which IP does this resolver use to reach authoritative servers?
	eg := model.TestResult{ID: "egress", Name: "Upstream egress address", Status: model.Info}
	rgo, _ := e.query(ctx, udp, nameGoogleEcho, dnswire.TypeTXT, dnswire.QueryOpts{EDNS: true})
	if rgo.OK() {
		for _, s := range rgo.Msg.TXT() {
			if strings.HasPrefix(s, "edns0-client-subnet") {
				res.Egress.ECS = strings.TrimSpace(strings.TrimPrefix(s, "edns0-client-subnet"))
			} else if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				res.Egress.IP = a.String()
				res.Egress.Method = nameGoogleEcho + " TXT"
			}
		}
	}
	if res.Egress.IP == "" {
		ra, _ := e.query(ctx, udp, nameAkamaiEcho, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		if ra.OK() && len(ra.Msg.Addrs()) > 0 {
			res.Egress.IP = ra.Msg.Addrs()[0].String()
			res.Egress.Method = nameAkamaiEcho + " A"
		}
	}
	if res.Egress.IP != "" {
		eg.Detail = "authoritative servers see queries from " + res.Egress.IP
		if res.Egress.ECS != "" {
			eg.Detail += " (sends EDNS Client Subnet " + res.Egress.ECS + ")"
		}
	} else {
		eg.Detail = "could not determine (echo names did not answer)"
	}
	res.Tests = append(res.Tests, eg)

	// 12. Encrypted transports for public providers.
	if t.prov != nil && e.cfg.Encrypted {
		e.encryptedTests(ctx, t, &res)
	}
	return res
}

func (e *Engine) encryptedTests(ctx context.Context, t target, res *model.ResolverResult) {
	p := t.prov
	if p.DoTName != "" {
		ep := dnsclient.Endpoint{Addr: netip.AddrPortFrom(t.addr.Addr(), 853), Proto: dnsclient.DoT, TLSName: p.DoTName}
		r, _ := e.query(ctx, ep, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		tt := toTest("dot", "DNS-over-TLS (853)", ep.String(), r)
		if r.OK() && r.Msg.Rcode == dnswire.RcodeSuccess {
			tt.Status = model.Pass
			tt.Detail = fmt.Sprintf("answered in %.1f ms incl. TLS handshake", tt.RTTMS)
			if r.TLS != nil {
				tt.Detail += fmt.Sprintf(" (%s, cert %s by %s)", r.TLS.Version, r.TLS.PeerSubject, r.TLS.PeerIssuer)
			}
		} else {
			tt.Status = model.Warn
			tt.Detail = "DoT failed (" + r.ErrClass + ")"
			if r.ErrClass == "tls" {
				tt.Detail += " — certificate/TLS problem: possible TLS interception or wrong clock"
			}
		}
		res.Tests = append(res.Tests, tt)
	} else {
		res.Tests = append(res.Tests, model.TestResult{ID: "dot", Name: "DNS-over-TLS (853)", Status: model.Skip, Detail: p.Name + " does not offer DoT"})
	}
	if p.DoHHost != "" {
		ep := dnsclient.Endpoint{Addr: netip.AddrPortFrom(t.addr.Addr(), 443), Proto: dnsclient.DoH, TLSName: p.DoHHost, DoHPath: p.DoHPath}
		r, _ := e.query(ctx, ep, nameBasic, dnswire.TypeA, dnswire.QueryOpts{})
		tt := toTest("doh", "DNS-over-HTTPS (443)", ep.String(), r)
		if r.OK() && r.Msg.Rcode == dnswire.RcodeSuccess {
			tt.Status = model.Pass
			tt.Detail = fmt.Sprintf("answered in %.1f ms incl. TLS handshake", tt.RTTMS)
			if r.TLS != nil {
				tt.Detail += fmt.Sprintf(" (%s, %s)", r.TLS.HTTPProto, r.TLS.Version)
			}
		} else {
			tt.Status = model.Warn
			tt.Detail = "DoH failed (" + r.ErrClass + ")"
		}
		res.Tests = append(res.Tests, tt)
	}
}

// looksBlocked decides whether a response for an ad domain looks filtered.
func looksBlocked(m *dnswire.Msg) (bool, string) {
	for _, x := range m.EDEs() {
		switch x.Code {
		case 15, 16, 17, 18:
			return true, "blocked (" + x.String() + ")"
		}
	}
	switch m.Rcode {
	case dnswire.RcodeNXDomain:
		return true, "NXDOMAIN"
	case dnswire.RcodeRefused:
		return true, "REFUSED"
	}
	addrs := m.Addrs()
	if len(addrs) == 0 {
		if len(m.Answer) == 0 {
			return true, "empty answer"
		}
		return false, "CNAME only"
	}
	sink := true
	for _, a := range addrs {
		if !(a.IsUnspecified() || a.IsLoopback() || a.IsPrivate()) {
			sink = false
		}
	}
	if sink {
		return true, "sinkholed to " + joinAddrs(addrs)
	}
	return false, "resolved to " + joinAddrs(addrs)
}

func joinAddrs(a []netip.Addr) string {
	var s []string
	for i, x := range a {
		if i == 4 {
			s = append(s, "…")
			break
		}
		s = append(s, x.String())
	}
	return strings.Join(s, ", ")
}

// fingerprint guesses resolver software from CHAOS answers.
func fingerprint(id map[string]string) string {
	v := strings.ToLower(id["version.bind"])
	switch {
	case strings.Contains(v, "dnsmasq-pi-hole"), strings.Contains(v, "pi-hole"):
		return "Pi-hole FTL (dnsmasq)"
	case strings.Contains(v, "dnsmasq"):
		return "dnsmasq (common on UniFi, OpenWrt, DD-WRT, Pi-hole, many ISP routers)"
	case strings.Contains(v, "unbound"):
		return "Unbound"
	case strings.Contains(v, "powerdns"):
		return "PowerDNS Recursor"
	case strings.Contains(v, "knot"):
		return "Knot Resolver"
	case strings.Contains(v, "adguard"):
		return "AdGuard Home"
	case strings.Contains(v, "technitium"):
		return "Technitium DNS"
	case strings.Contains(v, "microsoft"):
		return "Microsoft DNS"
	case v != "" && (strings.HasPrefix(v, "9.") || strings.Contains(v, "bind")):
		return "BIND"
	}
	return ""
}

func stats(sent int, samples []float64) model.Latency {
	l := model.Latency{Sent: sent, Received: len(samples)}
	if sent > 0 {
		l.LossPct = math.Round(float64(sent-len(samples))/float64(sent)*1000) / 10
	}
	if len(samples) == 0 {
		return l
	}
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	l.MinMS = s[0]
	l.MaxMS = s[len(s)-1]
	l.AvgMS = round2(sum / float64(len(s)))
	l.MedianMS = s[len(s)/2]
	if len(s)%2 == 0 {
		l.MedianMS = round2((s[len(s)/2-1] + s[len(s)/2]) / 2)
	}
	l.P90MS = s[int(math.Ceil(0.9*float64(len(s))))-1]
	if len(samples) > 1 {
		j := 0.0
		for i := 1; i < len(samples); i++ {
			j += math.Abs(samples[i] - samples[i-1])
		}
		l.JitterMS = round2(j / float64(len(samples)-1))
	}
	return l
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
