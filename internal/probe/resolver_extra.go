package probe

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/dnsclient"
	"github.com/StormAvenger/SAdns/internal/dnswire"
	"github.com/StormAvenger/SAdns/internal/model"
)

const (
	nameCanaryDoH   = "use-application-dns.net"
	nameCanaryRelay = "mask.icloud.com"
	nameDDR         = "_dns.resolver.arpa"
	nameHTTPSRR     = "cloudflare.com" // publishes HTTPS records: a known-positive control
	publicCtrlIP    = "93.184.215.14"  // any public address works as a wildcard-DNS control
)

// Wildcard DNS services that map names containing an IP to that IP. Two
// independent services so one being down is not mistaken for a resolver trait.
var wildcardSvcs = []string{"nip.io", "sslip.io"}

// burstMu serialises burst tests so parallel resolver suites never stack
// their bursts onto the same router (which would cause false drops).
var burstMu sync.Mutex

// sleepCtx sleeps unless the context ends first; false means cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// randomCase applies DNS 0x20 mixed-case encoding to a name.
func randomCase(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && rand.IntN(2) == 0 {
			b[i] = c - 32
		}
	}
	return string(b)
}

func positive(r dnsclient.Response) bool {
	return r.OK() && r.Msg.Rcode == dnswire.RcodeSuccess && len(r.Msg.Addrs()) > 0
}

// ---------------------------------------------------------------- DNSSEC

// dnssecTest only claims validation when the evidence supports it:
//   - the signed control (ietf.org) must resolve, otherwise nothing is known;
//   - SERVFAIL for the bogus zone counts as validation only when it is
//     explained by DNSSEC: a DNSSEC Extended DNS Error, or the same query with
//     Checking Disabled (CD=1) succeeding, or the AD bit on the signed control;
//   - an unexplained SERVFAIL is retried and otherwise reported inconclusive,
//     because a broken upstream also returns SERVFAIL.
func (e *Engine) dnssecTest(ctx context.Context, udp dnsclient.Endpoint, res *model.ResolverResult) {
	t := model.TestResult{ID: "dnssec", Name: "DNSSEC validation", Query: nameDNSSECGood + " (signed) / " + nameDNSSECBad + " (bogus), with and without CD"}
	good, _ := e.query(ctx, udp, nameDNSSECGood, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, DO: true, AD: true})
	bad, _ := e.query(ctx, udp, nameDNSSECBad, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, AD: true})
	badCD, _ := e.query(ctx, udp, nameDNSSECBad, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, CD: true, DO: true})
	servfail := func(r dnsclient.Response) bool { return r.OK() && r.Msg.Rcode == dnswire.RcodeServFail }
	if servfail(bad) && !positive(badCD) {
		// Unexplained SERVFAIL: give a slow upstream one more chance.
		sleepCtx(ctx, 300*time.Millisecond)
		bad, _ = e.query(ctx, udp, nameDNSSECBad, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, AD: true})
		badCD, _ = e.query(ctx, udp, nameDNSSECBad, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, CD: true, DO: true})
	}
	tr := toTest("dnssec", "", "", bad)
	t.Rcode, t.Flags, t.EDE, t.Answers, t.Error, t.RTTMS = tr.Rcode, tr.Flags, tr.EDE, tr.Answers, tr.Error, tr.RTTMS

	var ev []string
	adGood := positive(good) && good.Msg.AD
	if positive(good) {
		ev = append(ev, fmt.Sprintf("signed control: NOERROR, AD=%v", good.Msg.AD))
	} else {
		ev = append(ev, "signed control: "+rcodeOrErr(good))
	}
	dnssecEDE := false
	if bad.Msg != nil {
		for _, x := range bad.Msg.EDEs() {
			if x.Code >= 1 && x.Code <= 12 && x.Code != 3 {
				dnssecEDE = true
				ev = append(ev, "bogus zone: "+x.String())
			}
		}
	}
	ev = append(ev, "bogus zone: "+rcodeOrErr(bad), "bogus zone with CD=1: "+rcodeOrErr(badCD))
	cdBypass := servfail(bad) && positive(badCD)

	switch {
	case !positive(good):
		res.DNSSEC, res.DNSSECConfidence, t.Status = "inconclusive", "inconclusive", model.Info
		t.Detail = "the signed control domain did not resolve, so validation cannot be judged"
	case servfail(bad) && (dnssecEDE || cdBypass):
		res.DNSSEC, res.DNSSECConfidence, t.Status = "validating", "confirmed", model.Pass
		t.Detail = "bogus zone rejected and the rejection is attributable to DNSSEC"
	case servfail(bad) && adGood:
		res.DNSSEC, res.DNSSECConfidence, t.Status = "validating", "suspected", model.Pass
		t.Detail = "bogus zone rejected and signed zone marked authentic; CD=1 not honoured, so the SERVFAIL cause is not independently confirmed"
	case servfail(bad):
		res.DNSSEC, res.DNSSECConfidence, t.Status = "inconclusive", "inconclusive", model.Info
		t.Detail = "SERVFAIL for the bogus zone, but no AD bit, no DNSSEC error code and CD=1 did not bypass it — could be an upstream failure rather than validation"
	case positive(bad) && adGood:
		res.DNSSEC, res.DNSSECConfidence, t.Status = "inconsistent", "confirmed", model.Warn
		t.Detail = "AD bit set on the signed zone but the bogus zone was accepted — AD is passed through without validation"
	case positive(bad):
		res.DNSSEC, res.DNSSECConfidence, t.Status = "not-validating", "confirmed", model.Info
		t.Detail = "returned addresses for a zone with broken signatures — this resolver does not validate DNSSEC"
	default:
		res.DNSSEC, res.DNSSECConfidence, t.Status = "inconclusive", "inconclusive", model.Info
		t.Detail = "unexpected answer for the bogus zone"
	}
	t.Detail += " [" + strings.Join(ev, "; ") + "]"
	res.Tests = append(res.Tests, t)
}

func rcodeOrErr(r dnsclient.Response) string {
	switch {
	case r.Msg != nil && r.Err == nil:
		s := dnswire.RcodeString(r.Msg.Rcode)
		if n := len(r.Msg.Addrs()); n > 0 {
			s += fmt.Sprintf(" (%d addresses)", n)
		}
		return s
	case r.Err != nil:
		return "no answer (" + r.ErrClass + ")"
	}
	return "no answer"
}

// ---------------------------------------------------------------- filtering

func (e *Engine) filterTest(ctx context.Context, udp dnsclient.Endpoint, res *model.ResolverResult, basicOK bool) {
	ft := model.TestResult{ID: "filtering", Name: "Ad/tracker filtering", Status: model.Info, Query: strings.Join(adNames, ", ")}
	blocked, checked := 0, 0
	how := map[string]int{}
	var det []string
	for _, n := range adNames {
		ra, _ := e.query(ctx, udp, n, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		if !ra.OK() {
			det = append(det, n+": "+ra.ErrClass)
			continue
		}
		checked++
		b, why := looksBlocked(ra.Msg)
		if b {
			blocked++
			how[strings.Fields(why)[0]]++
		}
		det = append(det, n+": "+why)
	}
	switch {
	case checked == 0 || !basicOK:
		res.Filtering = "unknown"
		if !basicOK {
			det = append(det, "inconclusive: the control name "+nameBasic+" does not resolve either")
		}
	case blocked*2 > checked:
		res.Filtering = "blocks-ads"
	case blocked > 0:
		res.Filtering = "partial"
	default:
		res.Filtering = "no-ad-blocking"
	}
	var mech []string
	for k, v := range how {
		mech = append(mech, fmt.Sprintf("%s×%d", k, v))
	}
	sort.Strings(mech)
	ft.Detail = fmt.Sprintf("%s — %d/%d blocked", res.Filtering, blocked, checked)
	if len(mech) > 0 {
		ft.Detail += " via " + strings.Join(mech, ", ")
	}
	ft.Detail += " (" + strings.Join(det, "; ") + ")"
	res.Tests = append(res.Tests, ft)
}

// ---------------------------------------------------------------- uncached lookups + caching

// coldCacheTest resolves three never-before-seen names (forcing full
// recursion), then repeats each. Comparing the repeat time with the plain
// network round-trip separates a local cache from a cache further upstream.
func (e *Engine) coldCacheTest(ctx context.Context, res *model.ResolverResult, udp dnsclient.Endpoint, netRTT time.Duration) {
	t := model.TestResult{ID: "cache", Name: "Uncached lookups & caching", Status: model.Info}
	res.Caching = "unknown"
	var svc string
	var cold, warm []float64
	var det []string
	for _, cand := range wildcardSvcs {
		name := fmt.Sprintf("sadns-%s.%s.%s", dnswire.RandomLabel(10), publicCtrlIP, cand)
		r, _ := e.query(ctx, udp, name, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		if positive(r) {
			svc = cand
			cold = append(cold, ms(r.RTT))
			if w, _ := e.query(ctx, udp, name, dnswire.TypeA, dnswire.QueryOpts{EDNS: true}); positive(w) {
				warm = append(warm, ms(w.RTT))
			}
			break
		}
		det = append(det, cand+": "+rcodeOrErr(r))
	}
	if svc == "" {
		t.Detail = "inconclusive: the wildcard test names did not resolve (" + strings.Join(det, "; ") + ")"
		res.Tests = append(res.Tests, t)
		return
	}
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("sadns-%s.%s.%s", dnswire.RandomLabel(10), publicCtrlIP, svc)
		r, _ := e.query(ctx, udp, name, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		if !positive(r) {
			continue
		}
		cold = append(cold, ms(r.RTT))
		if w, _ := e.query(ctx, udp, name, dnswire.TypeA, dnswire.QueryOpts{EDNS: true}); positive(w) {
			warm = append(warm, ms(w.RTT))
		}
	}
	cs, ws := stats(len(cold), cold), stats(len(warm), warm)
	res.ColdMS, res.ColdP90MS = cs.MedianMS, cs.P90MS
	net := ms(netRTT)
	t.Query = fmt.Sprintf("%d unique *.%s.%s names, each asked twice", len(cold), publicCtrlIP, svc)
	t.RTTMS = cs.MedianMS
	base := fmt.Sprintf("first lookup median %.1f ms (p90 %.1f), repeat median %.1f ms, network RTT %.1f ms", cs.MedianMS, cs.P90MS, ws.MedianMS, net)
	switch {
	case len(warm) < 2:
		t.Detail = "inconclusive: too few successful repeat lookups — " + base
	case ws.MedianMS <= net*1.5+2 && cs.MedianMS > ws.MedianMS+5:
		res.Caching = "local-cache"
		t.Status = model.Pass
		t.Detail = "repeat answers come back at network speed: this resolver caches — " + base
	case ws.MedianMS < cs.MedianMS*0.6 && cs.MedianMS-ws.MedianMS > 5:
		res.Caching = "upstream-cache"
		t.Detail = "repeats are faster but slower than the network round-trip: this resolver forwards without (effective) local caching and a cache further upstream answers — " + base
	case cs.MedianMS-ws.MedianMS <= 5 && cs.MedianMS > net*1.5+5:
		res.Caching = "no-cache"
		t.Detail = "repeats are as slow as first lookups: no caching anywhere in the path — " + base
	default:
		t.Detail = "inconclusive: first lookups are already close to network speed — " + base
	}
	res.Tests = append(res.Tests, t)
}

// ---------------------------------------------------------------- compliance & behaviour

// extraTests runs protocol-compliance and behaviour checks beyond "does it answer".
func (e *Engine) extraTests(ctx context.Context, t target, res *model.ResolverResult, udp dnsclient.Endpoint) {
	res.Rebind, res.Cookies, res.Case0x20, res.HTTPSRR = "unknown", "no", "unknown", "unknown"
	res.CanaryDoH, res.CanaryRelay = "unknown", "unknown"

	// 0x20 case preservation.
	mixed := randomCase(nameBasic) + "."
	r, _ := e.query(ctx, udp, mixed, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	ct := toTest("case_0x20", "Query-name case preserved (0x20)", mixed+" A", r)
	switch {
	case !r.OK():
		ct.Status, ct.Detail = model.Info, "no response ("+r.ErrClass+")"
	case len(r.Msg.Question) == 0:
		ct.Status, ct.Detail = model.Info, "response carried no question section"
	case r.Msg.Question[0].Name == mixed:
		res.Case0x20 = "preserved"
		ct.Status, ct.Detail = model.Pass, "question echoed with identical letter case"
	default:
		res.Case0x20 = "broken"
		ct.Status, ct.Detail = model.Warn, fmt.Sprintf("sent %q, got back %q — something rewrites query names (breaks 0x20 anti-spoofing used by Unbound/Google)", mixed, r.Msg.Question[0].Name)
	}
	res.Tests = append(res.Tests, ct)

	// EDNS version negotiation (RFC 6891 §6.1.3: unknown version → BADVERS).
	r, _ = e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{Version: 1})
	vt := toTest("edns_version", "EDNS version negotiation", nameBasic+" A +edns=1", r)
	switch {
	case r.OK() && r.Msg.Rcode == dnswire.RcodeBadVers:
		vt.Status, vt.Detail = model.Pass, "unknown EDNS version correctly answered with BADVERS"
	case r.OK() && r.Msg.Rcode == dnswire.RcodeFormErr:
		vt.Status, vt.Detail = model.Info, "FORMERR for EDNS version 1 (old EDNS implementation)"
	case r.OK():
		vt.Status, vt.Detail = model.Info, "answered "+vt.Rcode+" instead of BADVERS (ignores EDNS version — harmless today, non-compliant)"
	default:
		vt.Status, vt.Detail = model.Warn, "query with EDNS version 1 was dropped ("+r.ErrClass+") — server or firewall silently discards unusual EDNS, which will break future DNS features"
	}
	res.Tests = append(res.Tests, vt)

	// DNS Cookies (RFC 7873): obtain a server cookie, then present it.
	cc := dnswire.RandomBytes(8)
	r, _ = e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, Cookie: cc})
	kt := toTest("cookie", "DNS Cookies (RFC 7873)", nameBasic+" A +cookie, then +cookie=<server cookie>", r)
	kt.Status = model.Info
	if !r.OK() {
		kt.Detail = "no response (" + r.ErrClass + ")"
	} else if c := r.Msg.Cookie(); len(c) >= 16 && len(c) <= 40 && string(c[:8]) == string(cc) {
		r2, _ := e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, Cookie: c})
		switch {
		case r2.OK() && r2.Msg.Rcode == dnswire.RcodeSuccess:
			res.Cookies = "yes"
			kt.Status = model.Pass
			kt.Detail = fmt.Sprintf("server issued a %d-byte cookie and accepted it on the next query (spoofing protection works)", len(c)-8)
		case r2.OK() && r2.Msg.Rcode == 23:
			res.Cookies = "broken"
			kt.Detail = "server issued a cookie but rejected it on the next query (BADCOOKIE)"
		default:
			res.Cookies = "partial"
			kt.Detail = "server issued a cookie; the follow-up query failed (" + rcodeOrErr(r2) + ")"
		}
	} else if len(c) > 0 {
		kt.Detail = "cookie option returned but malformed or not echoing our client cookie"
	} else {
		kt.Detail = "no cookie support (common for home routers; not a fault)"
	}
	res.Tests = append(res.Tests, kt)

	// Modern record types: HTTPS (type 65). cloudflare.com publishes HTTPS
	// records, so an empty NOERROR here means records are stripped somewhere.
	r, _ = e.query(ctx, udp, nameHTTPSRR, dnswire.TypeHTTPS, dnswire.QueryOpts{EDNS: true})
	ht := toTest("https_rr", "HTTPS/SVCB record type (RFC 9460)", nameHTTPSRR+" HTTPS (known to exist)", r)
	switch {
	case r.OK() && r.Msg.Rcode == dnswire.RcodeSuccess && len(r.Msg.SVCBTargets()) > 0:
		res.HTTPSRR = "records"
		ht.Status, ht.Detail = model.Pass, fmt.Sprintf("returned %d HTTPS record(s)", len(r.Msg.SVCBTargets()))
	case r.OK() && r.Msg.Rcode == dnswire.RcodeSuccess:
		res.HTTPSRR = "empty"
		ht.Status, ht.Detail = model.Info, "NOERROR but no HTTPS records for a name that publishes them — compared against public resolvers in the findings"
	case r.OK():
		res.HTTPSRR = "error"
		ht.Status, ht.Detail = model.Warn, "HTTPS-type query returned "+ht.Rcode+" — Safari, Chrome and iOS request these for every site and may stall or fall back"
	default:
		res.HTTPSRR = "error"
		ht.Status, ht.Detail = model.Warn, "HTTPS-type query got no answer ("+r.ErrClass+") — an old router/firewall is dropping unknown record types"
	}
	res.Tests = append(res.Tests, ht)

	// Bursts: a small baseline, then two larger rounds (one burst at a time globally).
	burstMu.Lock()
	b5 := e.burst(ctx, udp, 5)
	b20a := e.burst(ctx, udp, 20)
	sleepCtx(ctx, 200*time.Millisecond)
	b20b := e.burst(ctx, udp, 20)
	burstMu.Unlock()
	worst20 := min(b20a.ok, b20b.ok)
	bt := model.TestResult{ID: "burst", Name: "Parallel query bursts", Query: nameBasic + " A ×5, ×20, ×20", RTTMS: ms(max(b20a.slowest, b20b.slowest)),
		Detail: fmt.Sprintf("5-burst %d/5, 20-burst %d/20 and %d/20 (slowest %.1f ms)", b5.ok, b20a.ok, b20b.ok, ms(max(b20a.slowest, b20b.slowest)))}
	switch {
	case b5.ok < 5:
		bt.Status = model.Warn
		bt.Detail += " — losses even at 5 parallel queries: general packet loss or a strict rate limit"
	case worst20 < 18:
		bt.Status = model.Warn
		bt.Detail += " — fine at 5, drops at 20 in a repeatable way: rate limiting or an undersized concurrent-query table"
	case worst20 < 20:
		bt.Status = model.Info
		bt.Detail += " — occasional loss under load"
	default:
		bt.Status = model.Pass
	}
	res.Tests = append(res.Tests, bt)

	// DNS rebinding protection, with a public-IP control on the same service.
	rbt := model.TestResult{ID: "rebind", Name: "DNS rebinding protection", Status: model.Info}
	var tried []string
	for _, svc := range wildcardSvcs {
		ctrl, _ := e.query(ctx, udp, publicCtrlIP+"."+svc, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		if !positive(ctrl) {
			tried = append(tried, svc+" control: "+rcodeOrErr(ctrl))
			continue
		}
		name := "10.0.0.1." + svc
		priv, _ := e.query(ctx, udp, name, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
		rbt.Query = name + " (control " + publicCtrlIP + "." + svc + " resolved)"
		rbt.Rcode, rbt.Answers = toTest("", "", "", priv).Rcode, toTest("", "", "", priv).Answers
		switch {
		case !priv.OK():
			rbt.Detail = "no response for the private-IP name (" + priv.ErrClass + ")"
		case len(priv.Msg.Addrs()) > 0 && priv.Msg.Addrs()[0].IsPrivate():
			res.Rebind = "off"
			rbt.Detail = "public names may resolve to private IPs (no rebinding protection)"
		default:
			res.Rebind = "on"
			rbt.Detail = "the control resolved but the private-IP answer was suppressed (" + rcodeOrErr(priv) + ") — rebinding protection is active"
		}
		break
	}
	if rbt.Detail == "" {
		rbt.Detail = "inconclusive: control names did not resolve (" + strings.Join(tried, "; ") + ")"
	}
	res.Tests = append(res.Tests, rbt)

	if t.role == "public" {
		return
	}

	// DDR: does the resolver advertise an encrypted endpoint? (RFC 9462)
	r, _ = e.query(ctx, udp, nameDDR, dnswire.TypeSVCB, dnswire.QueryOpts{EDNS: true})
	dt := toTest("ddr", "Discovery of Designated Resolvers (DDR)", nameDDR+" SVCB", r)
	dt.Status = model.Info
	if r.OK() && len(r.Msg.SVCBTargets()) > 0 {
		res.DDR = r.Msg.SVCBTargets()
		dt.Detail = "advertises encrypted DNS: " + strings.Join(res.DDR, ", ") + " (Windows 11/macOS/iOS may upgrade to it automatically)"
	} else {
		dt.Detail = "no encrypted resolver advertised"
	}
	res.Tests = append(res.Tests, dt)

	// Canary domains (only meaningful when the resolver answers normal names).
	negative := func(m *dnswire.Msg) bool { return m.Rcode != dnswire.RcodeSuccess || len(m.Addrs()) == 0 }
	r, _ = e.query(ctx, udp, nameCanaryDoH, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	c1 := toTest("canary_doh", "Browser-DoH canary (use-application-dns.net)", nameCanaryDoH+" A", r)
	c1.Status = model.Info
	switch {
	case !r.OK():
		c1.Detail = "no response (" + r.ErrClass + ")"
	case negative(r.Msg):
		res.CanaryDoH = "disables-doh"
		c1.Detail = "negative answer — Firefox will NOT auto-enable DNS-over-HTTPS on this network (typical for Pi-hole/filtering setups)"
	default:
		res.CanaryDoH = "allows-doh"
		c1.Detail = "resolves normally — Firefox may switch itself to DoH and bypass this resolver"
	}
	res.Tests = append(res.Tests, c1)
	r, _ = e.query(ctx, udp, nameCanaryRelay, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	c2 := toTest("canary_relay", "iCloud Private Relay canary (mask.icloud.com)", nameCanaryRelay+" A", r)
	c2.Status = model.Info
	switch {
	case !r.OK():
		c2.Detail = "no response (" + r.ErrClass + ")"
	case negative(r.Msg):
		res.CanaryRelay = "blocks-relay"
		c2.Detail = "negative answer — Apple devices are told Private Relay is unavailable on this network"
	default:
		res.CanaryRelay = "allows-relay"
		c2.Detail = "resolves — iCloud Private Relay works (Apple devices using it bypass this resolver for Safari)"
	}
	res.Tests = append(res.Tests, c2)

	// Encrypted-DNS ports on the local resolver.
	var open []string
	for _, port := range []int{853, 443} {
		ap := netip.AddrPortFrom(t.addr.Addr(), uint16(port))
		d := net.Dialer{Timeout: 1200 * time.Millisecond}
		if c, err := d.DialContext(ctx, "tcp", ap.String()); err == nil {
			c.Close()
			res.OpenPorts = append(res.OpenPorts, port)
			open = append(open, fmt.Sprint(port))
		}
	}
	pt := model.TestResult{ID: "enc_ports", Name: "Encrypted-DNS ports on this resolver", Status: model.Info, Query: "TCP 853 (DoT), 443 (DoH)"}
	if len(open) > 0 {
		pt.Detail = "open: TCP " + strings.Join(open, ", ") + " (443 may just be the router's web UI)"
	} else {
		pt.Detail = "TCP 853 and 443 closed — resolver offers plain DNS only"
	}
	res.Tests = append(res.Tests, pt)
}

type burstResult struct {
	ok      int
	slowest time.Duration
}

func (e *Engine) burst(ctx context.Context, udp dnsclient.Endpoint, n int) burstResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var b burstResult
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr, _ := e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
			mu.Lock()
			defer mu.Unlock()
			if rr.OK() {
				b.ok++
				b.slowest = max(b.slowest, rr.RTT)
			}
		}()
	}
	wg.Wait()
	return b
}
