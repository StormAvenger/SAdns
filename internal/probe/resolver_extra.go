package probe

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/dnsclient"
	"github.com/StormAvenger/SAdns/internal/dnswire"
	"github.com/StormAvenger/SAdns/internal/model"
)

const (
	nameRebind      = "10.0.0.1.nip.io" // public name that resolves to a private IP
	nameCanaryDoH   = "use-application-dns.net"
	nameCanaryRelay = "mask.icloud.com"
	nameDDR         = "_dns.resolver.arpa"
	nameHTTPSRR     = "cloudflare.com"
	burstSize       = 20
)

// burstMu serialises burst tests so parallel resolver suites never stack
// their bursts onto the same router (which would cause false drops).
var burstMu sync.Mutex

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

func firstTTL(m *dnswire.Msg, t uint16) (uint32, bool) {
	if m == nil {
		return 0, false
	}
	for _, rr := range m.Answer {
		if rr.Type == t {
			return rr.TTL, true
		}
	}
	return 0, false
}

// extraTests runs the protocol-compliance and behaviour checks that go beyond
// "does it answer": 0x20, EDNS versioning, cookies, modern RR types, bursts,
// rebinding protection, DDR, canary domains, open encrypted-DNS ports.
func (e *Engine) extraTests(ctx context.Context, t target, res *model.ResolverResult, udp dnsclient.Endpoint) {
	res.Rebind, res.Caching, res.Cookies, res.Case0x20 = "unknown", "unknown", "no", "unknown"
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

	// DNS Cookies (RFC 7873).
	cc := dnswire.RandomBytes(8)
	r, _ = e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true, Cookie: cc})
	kt := toTest("cookie", "DNS Cookies (RFC 7873)", nameBasic+" A +cookie", r)
	kt.Status = model.Info
	switch c := []byte(nil); {
	case !r.OK():
		kt.Detail = "no response (" + r.ErrClass + ")"
	default:
		c = r.Msg.Cookie()
		switch {
		case len(c) >= 16 && string(c[:8]) == string(cc):
			res.Cookies = "yes"
			kt.Status, kt.Detail = model.Pass, fmt.Sprintf("server returned a %d-byte server cookie (spoofing protection)", len(c)-8)
		case len(c) > 0:
			kt.Detail = "cookie option echoed without a valid server cookie"
		default:
			kt.Detail = "no cookie support (common for home routers; not a fault)"
		}
	}
	res.Tests = append(res.Tests, kt)

	// Modern record types: HTTPS (type 65), queried by Safari/Chrome/iOS for every site.
	r, _ = e.query(ctx, udp, nameHTTPSRR, dnswire.TypeHTTPS, dnswire.QueryOpts{EDNS: true})
	ht := toTest("https_rr", "HTTPS/SVCB record type (RFC 9460)", nameHTTPSRR+" HTTPS", r)
	switch {
	case r.OK() && r.Msg.Rcode == dnswire.RcodeSuccess:
		ht.Status = model.Pass
		ht.Detail = fmt.Sprintf("NOERROR with %d HTTPS record(s)", len(r.Msg.Answer))
	case r.OK():
		ht.Status, ht.Detail = model.Warn, "HTTPS-type query returned "+ht.Rcode+" — browsers that request HTTPS records (Safari, Chrome, iOS) may see delays or fall back"
	default:
		ht.Status, ht.Detail = model.Warn, "HTTPS-type query got no answer ("+r.ErrClass+") — an old router/firewall is dropping unknown record types"
	}
	res.Tests = append(res.Tests, ht)

	// Burst handling: 20 parallel queries (one burst at a time, globally).
	burstMu.Lock()
	var wg sync.WaitGroup
	var mu sync.Mutex
	okN := 0
	var worst time.Duration
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr, _ := e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
			mu.Lock()
			defer mu.Unlock()
			if rr.OK() {
				okN++
				if rr.RTT > worst {
					worst = rr.RTT
				}
			}
		}()
	}
	wg.Wait()
	burstMu.Unlock()
	bt := model.TestResult{ID: "burst", Name: fmt.Sprintf("Burst of %d parallel queries", burstSize), Query: nameBasic + " A ×" + fmt.Sprint(burstSize), RTTMS: ms(worst)}
	switch {
	case okN == burstSize:
		bt.Status, bt.Detail = model.Pass, fmt.Sprintf("all %d answered, slowest %.1f ms", okN, ms(worst))
	case okN >= burstSize*9/10:
		bt.Status, bt.Detail = model.Info, fmt.Sprintf("%d/%d answered (minor loss under load)", okN, burstSize)
	default:
		bt.Status, bt.Detail = model.Warn, fmt.Sprintf("only %d/%d answered — rate limiting or an undersized query table; page loads that fire many lookups will stall", okN, burstSize)
	}
	res.Tests = append(res.Tests, bt)

	// DNS rebinding protection.
	r, _ = e.query(ctx, udp, nameRebind, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	rt := toTest("rebind", "DNS rebinding protection", nameRebind+" A (public name → 10.0.0.1)", r)
	rt.Status = model.Info
	switch {
	case !r.OK():
		rt.Detail = "no response (" + r.ErrClass + ")"
	case len(r.Msg.Addrs()) > 0 && r.Msg.Addrs()[0].IsPrivate():
		res.Rebind = "off"
		rt.Detail = "public names may resolve to private IPs (no rebinding protection)"
	case r.Msg.Rcode == dnswire.RcodeSuccess || r.Msg.Rcode == dnswire.RcodeNXDomain || r.Msg.Rcode == dnswire.RcodeRefused:
		res.Rebind = "on"
		rt.Detail = "private-IP answer for a public name was suppressed (" + rt.Rcode + ", no address) — rebinding protection active"
	default:
		rt.Detail = "inconclusive: " + rt.Rcode
	}
	res.Tests = append(res.Tests, rt)

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

	// Canary domains.
	negative := func(m *dnswire.Msg) bool {
		return m.Rcode != dnswire.RcodeSuccess || len(m.Addrs()) == 0
	}
	r, _ = e.query(ctx, udp, nameCanaryDoH, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	c1 := toTest("canary_doh", "Browser-DoH canary (use-application-dns.net)", nameCanaryDoH+" A", r)
	c1.Status = model.Info
	if r.OK() && negative(r.Msg) {
		res.CanaryDoH = "disables-doh"
		c1.Detail = "negative answer — Firefox will NOT auto-enable DNS-over-HTTPS on this network (typical for Pi-hole/filtering setups)"
	} else if r.OK() {
		res.CanaryDoH = "allows-doh"
		c1.Detail = "resolves normally — Firefox may switch itself to DoH and bypass this resolver"
	} else {
		c1.Detail = "no response (" + r.ErrClass + ")"
	}
	res.Tests = append(res.Tests, c1)
	r, _ = e.query(ctx, udp, nameCanaryRelay, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	c2 := toTest("canary_relay", "iCloud Private Relay canary (mask.icloud.com)", nameCanaryRelay+" A", r)
	c2.Status = model.Info
	if r.OK() && negative(r.Msg) {
		res.CanaryRelay = "blocks-relay"
		c2.Detail = "negative answer — Apple devices are told Private Relay is unavailable on this network"
	} else if r.OK() {
		res.CanaryRelay = "allows-relay"
		c2.Detail = "resolves — iCloud Private Relay works (Apple devices using it bypass this resolver for Safari)"
	} else {
		c2.Detail = "no response (" + r.ErrClass + ")"
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

// cacheTest compares the TTL seen at the start of the suite with one seen now.
func (e *Engine) cacheTest(ctx context.Context, res *model.ResolverResult, udp dnsclient.Endpoint, ttl1 uint32, t1 time.Time) {
	if wait := 1100*time.Millisecond - time.Since(t1); wait > 0 {
		time.Sleep(wait)
	}
	r, _ := e.query(ctx, udp, nameBasic, dnswire.TypeA, dnswire.QueryOpts{EDNS: true})
	ct := toTest("cache", "Answer caching (TTL decay)", nameBasic+" A, twice", r)
	ct.Status = model.Info
	ttl2, ok := firstTTL(r.Msg, dnswire.TypeA)
	switch {
	case !ok:
		ct.Detail = "second answer missing"
	case ttl2 < ttl1:
		res.Caching = "yes"
		ct.Status = model.Pass
		ct.Detail = fmt.Sprintf("TTL fell from %d to %d over %.1fs — answers are served from cache", ttl1, ttl2, time.Since(t1).Seconds())
	case ttl2 == ttl1:
		res.Caching = "no"
		ct.Detail = fmt.Sprintf("TTL stayed at %d — no local cache, or a pinned TTL (every lookup goes upstream)", ttl1)
	default:
		res.Caching = "yes"
		ct.Detail = fmt.Sprintf("TTL rose from %d to %d — load-balanced/anycast cache pool", ttl1, ttl2)
	}
	res.Tests = append(res.Tests, ct)
}
