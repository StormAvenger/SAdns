package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/execx"
	"github.com/StormAvenger/SAdns/internal/model"
)

// netHealth runs link-quality and service checks concurrently.
func (e *Engine) netHealth(ctx context.Context, conn model.Connectivity) model.NetHealth {
	var nh model.NetHealth
	var mu sync.Mutex
	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }

	// Pings: gateway(s) and the internet.
	type pt struct {
		ip    string
		label string
		fam   int
	}
	var pts []pt
	for _, g := range e.sys.Gateways {
		a, err := netip.ParseAddr(g.Gateway)
		if err != nil || (a.IsLinkLocalUnicast() && a.Zone() == "") {
			continue
		}
		if (g.Family == 4 && !e.cfg.IPv4) || (g.Family == 6 && !e.cfg.IPv6) {
			continue
		}
		pts = append(pts, pt{g.Gateway, fmt.Sprintf("Default gateway (IPv%d) — LAN / Wi-Fi quality", g.Family), g.Family})
	}
	if e.cfg.IPv4 && conn.IPv4.Working {
		pts = append(pts, pt{"1.1.1.1", "Internet (IPv4) — Cloudflare anycast", 4})
	}
	if e.cfg.IPv6 && conn.IPv6.Working {
		pts = append(pts, pt{"2606:4700:4700::1111", "Internet (IPv6) — Cloudflare anycast", 6})
	}
	count := 10
	if e.cfg.Quick {
		count = 5
	}
	nh.Pings = make([]model.Ping, len(pts))
	for i, p := range pts {
		run(func() { nh.Pings[i] = e.ping(ctx, p.ip, p.label, p.fam, count) })
	}

	// Path MTU.
	if e.cfg.IPv4 && conn.IPv4.Working {
		run(func() {
			m := e.pathMTU(ctx, "1.1.1.1", 4)
			mu.Lock()
			nh.MTU = append(nh.MTU, m)
			mu.Unlock()
		})
	}
	if e.cfg.IPv6 && conn.IPv6.Working && runtime.GOOS == "linux" {
		run(func() {
			m := e.pathMTU(ctx, "2606:4700:4700::1111", 6)
			mu.Lock()
			nh.MTU = append(nh.MTU, m)
			mu.Unlock()
		})
	}

	// NTP.
	type ns struct{ name, addr string }
	servers := []ns{}
	if e.cfg.IPv4 {
		servers = append(servers, ns{"time.cloudflare.com", "162.159.200.1"}, ns{"time.google.com", "216.239.35.0"})
	}
	if e.cfg.IPv6 && conn.IPv6.Working {
		servers = append(servers, ns{"time.cloudflare.com", "2606:4700:f1::123"})
	}
	nh.NTP = make([]model.NTPResult, len(servers))
	for i, s := range servers {
		run(func() { nh.NTP[i] = sntp(ctx, s.name, s.addr) })
	}

	// Captive portal / transparent proxy checks.
	checks := []struct{ name, url, expect string }{
		{"Google (Android/Chrome)", "http://connectivitycheck.gstatic.com/generate_204", "204"},
		{"Apple (iOS/macOS)", "http://captive.apple.com/hotspot-detect.html", "Success"},
		{"Microsoft (Windows NCSI)", "http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"},
	}
	nh.HTTP = make([]model.HTTPCheck, len(checks))
	for i, c := range checks {
		run(func() { nh.HTTP[i] = httpCheck(ctx, c.name, c.url, c.expect) })
	}

	// NAT64 / DNS64.
	run(func() {
		n := nat64(ctx)
		mu.Lock()
		nh.NAT64 = n
		mu.Unlock()
	})

	// Local names.
	run(func() {
		l := e.localNames(ctx)
		mu.Lock()
		nh.Local = l
		mu.Unlock()
	})

	wg.Wait()
	sort.Slice(nh.MTU, func(i, j int) bool { return nh.MTU[i].Family < nh.MTU[j].Family })
	return nh
}

// ---------------------------------------------------------------- ping

var pingRTT = regexp.MustCompile(`[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b`)

// pingCmd builds a platform ping command. size<=0 uses the default payload.
func pingCmd(fam int, ip string, count, size int, df bool) (string, []string) {
	c := strconv.Itoa(count)
	switch runtime.GOOS {
	case "windows":
		args := []string{"-n", c, "-w", "1000"}
		if fam == 6 {
			args = append(args, "-6")
		} else {
			args = append(args, "-4")
			if df {
				args = append(args, "-f")
			}
		}
		if size > 0 {
			args = append(args, "-l", strconv.Itoa(size))
		}
		return "ping", append(args, ip)
	case "darwin":
		name := "ping"
		args := []string{"-c", c}
		if fam == 6 {
			name = "ping6"
		} else {
			args = append(args, "-W", "1000")
			if df {
				args = append(args, "-D")
			}
		}
		if size > 0 {
			args = append(args, "-s", strconv.Itoa(size))
		}
		return name, append(args, ip)
	default:
		args := []string{"-n", "-c", c, "-W", "1"}
		if count > 1 {
			args = append(args, "-i", "0.2")
		}
		if fam == 6 {
			args = append(args, "-6")
		}
		if df {
			args = append(args, "-M", "do")
		}
		if size > 0 {
			args = append(args, "-s", strconv.Itoa(size))
		}
		return "ping", append(args, ip)
	}
}

// parsePing extracts per-reply RTTs. Only lines naming the target count, so
// summary lines (which are localised on Windows) are ignored.
func parsePing(out, ip string) []float64 {
	host := ip
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	var rtts []float64
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, host) {
			continue
		}
		m := pingRTT.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", "."), 64)
		if err == nil {
			rtts = append(rtts, v)
		}
	}
	return rtts
}

func (e *Engine) ping(ctx context.Context, ip, label string, fam, count int) model.Ping {
	p := model.Ping{Target: ip, Label: label, Family: fam, Sent: count}
	name, args := pingCmd(fam, ip, count, 0, false)
	if !execx.Exists(name) {
		p.Error = name + " command not available"
		p.Sent = 0
		return p
	}
	out := execx.Run(ctx, time.Duration(count+5)*time.Second, name, args...)
	p.Raw = &out
	rtts := parsePing(out.Output, ip)
	p.Received = len(rtts)
	p.LossPct = math.Round(float64(count-len(rtts))/float64(count)*1000) / 10
	if len(rtts) == 0 {
		p.Error = strings.TrimSpace(firstLine(out.Error + " " + lastLine(out.Output)))
		return p
	}
	l := stats(count, rtts)
	p.MinMS, p.AvgMS, p.MaxMS, p.JitterMS = l.MinMS, l.AvgMS, l.MaxMS, l.JitterMS
	return p
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// ---------------------------------------------------------------- path MTU

// pathMTU binary-searches the largest don't-fragment ICMP echo that gets a reply.
func (e *Engine) pathMTU(ctx context.Context, ip string, fam int) model.PathMTU {
	m := model.PathMTU{Target: ip, Family: fam}
	hdr, lo, hi := 28, 1200, 1472 // IPv4 + ICMP headers; 1500-byte Ethernet ceiling
	if fam == 6 {
		hdr, lo, hi = 48, 1180, 1452
	}
	name, _ := pingCmd(fam, ip, 1, 0, true)
	if !execx.Exists(name) {
		m.Error = name + " command not available"
		return m
	}
	try := func(size int) bool {
		n, args := pingCmd(fam, ip, 1, size, true)
		out := execx.Run(ctx, 4*time.Second, n, args...)
		ok := len(parsePing(out.Output, ip)) > 0
		m.Probes = append(m.Probes, fmt.Sprintf("%d-byte packet: %s", size+hdr, map[bool]string{true: "ok", false: "no reply"}[ok]))
		return ok
	}
	if try(hi) {
		m.MTU = hi + hdr
	} else if !try(lo) {
		m.Error = fmt.Sprintf("even %d-byte don't-fragment packets got no reply (ICMP filtered, or MTU is very small)", lo+hdr)
		return m
	} else {
		good, bad := lo, hi
		for bad-good > 1 {
			mid := (good + bad) / 2
			if try(mid) {
				good = mid
			} else {
				bad = mid
			}
		}
		m.MTU = good + hdr
	}
	switch {
	case m.MTU >= 1500:
		m.Detail = "full 1500-byte Ethernet MTU end-to-end"
	case m.MTU == 1492:
		m.Detail = "1492 bytes — classic PPPoE overhead (DSL/fiber with PPPoE)"
	case m.MTU == 1480 || m.MTU == 1476:
		m.Detail = fmt.Sprintf("%d bytes — tunnel overhead (6in4/GRE)", m.MTU)
	case m.MTU == 1460:
		m.Detail = "1460 bytes — DS-Lite / IPv4-in-IPv6 tunnel"
	case m.MTU <= 1440:
		m.Detail = fmt.Sprintf("%d bytes — VPN or heavily encapsulated path", m.MTU)
	default:
		m.Detail = fmt.Sprintf("%d bytes — reduced MTU somewhere on the path", m.MTU)
	}
	return m
}

// ---------------------------------------------------------------- NTP

const ntpEpochOffset = 2208988800

func ntpTime(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b)
	frac := binary.BigEndian.Uint32(b[4:])
	nsec := (int64(frac) * 1e9) >> 32
	return time.Unix(int64(sec)-ntpEpochOffset, nsec)
}

func putNTPTime(b []byte, t time.Time) {
	sec := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32((int64(t.Nanosecond()) << 32) / 1e9)
	binary.BigEndian.PutUint32(b, sec)
	binary.BigEndian.PutUint32(b[4:], frac)
}

// sntp performs one RFC 4330 SNTP exchange on UDP/123.
func sntp(ctx context.Context, name, addr string) model.NTPResult {
	r := model.NTPResult{Server: name, Addr: addr}
	ap := netip.AddrPortFrom(netip.MustParseAddr(addr), 123)
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "udp", ap.String())
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	req := make([]byte, 48)
	req[0] = 0x23 // LI=0, VN=4, Mode=3 (client)
	t1 := time.Now()
	putNTPTime(req[40:], t1)
	if _, err := c.Write(req); err != nil {
		r.Error = err.Error()
		return r
	}
	resp := make([]byte, 128)
	n, err := c.Read(resp)
	t4 := time.Now()
	if err != nil {
		r.Error = "no reply on UDP/123 (" + err.Error() + ")"
		return r
	}
	if n < 48 || resp[0]&0x7 != 4 {
		r.Error = "malformed NTP reply"
		return r
	}
	r.Stratum = int(resp[1])
	if r.Stratum == 0 {
		r.Error = "kiss-of-death (" + strings.TrimRight(string(resp[12:16]), "\x00") + ")"
		return r
	}
	t2, t3 := ntpTime(resp[32:]), ntpTime(resp[40:])
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	delay := t4.Sub(t1) - t3.Sub(t2)
	r.OK = true
	r.OffsetMS = ms(offset)
	r.RTTMS = ms(delay)
	return r
}

// ---------------------------------------------------------------- HTTP / captive portal

func httpCheck(ctx context.Context, name, url, expect string) model.HTTPCheck {
	h := model.HTTPCheck{Name: name, URL: url, Expect: expect}
	cl := &http.Client{
		Timeout:   7 * time.Second,
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "SAdns connectivity check")
	start := time.Now()
	resp, err := cl.Do(req)
	h.MS = ms(time.Since(start))
	if err != nil {
		h.Error = err.Error()
		h.Detail = "request failed: " + err.Error()
		return h
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	h.Status = resp.StatusCode
	var px []string
	for _, k := range []string{"Via", "X-Cache", "X-Squid-Error", "Proxy-Connection", "X-Forwarded-For"} {
		if v := resp.Header.Get(k); v != "" {
			px = append(px, k+": "+v)
		}
	}
	h.Proxy = strings.Join(px, "; ")
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		h.Detail = fmt.Sprintf("redirected (%d) to %s — captive portal or HTTP interception", resp.StatusCode, resp.Header.Get("Location"))
	case expect == "204" && resp.StatusCode == 204:
		h.OK, h.Detail = true, "204 No Content as expected"
	case expect != "204" && resp.StatusCode == 200 && strings.Contains(string(body), expect):
		h.OK, h.Detail = true, "expected body returned"
	default:
		snip := strings.TrimSpace(string(body))
		if len(snip) > 120 {
			snip = snip[:120] + "…"
		}
		h.Detail = fmt.Sprintf("unexpected response %d (%q) — captive portal, filter page or proxy", resp.StatusCode, snip)
	}
	return h
}

// ---------------------------------------------------------------- NAT64

func nat64(ctx context.Context) model.NAT64 {
	n := model.NAT64{}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(cctx, "ip6", "ipv4only.arpa")
	if err != nil || len(addrs) == 0 {
		n.Detail = "no AAAA for ipv4only.arpa — no DNS64 on this network (normal for dual-stack/IPv4 networks)"
		return n
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		if !a.Is6() {
			continue
		}
		b := a.As16()
		var p [16]byte
		copy(p[:12], b[:12])
		pfx := netip.PrefixFrom(netip.AddrFrom16(p), 96).String()
		if !seen[pfx] {
			seen[pfx] = true
			n.Prefixes = append(n.Prefixes, pfx)
		}
	}
	n.Detected = len(n.Prefixes) > 0
	if n.Detected {
		n.Detail = "DNS64 synthesises AAAA records; NAT64 prefix " + strings.Join(n.Prefixes, ", ") + " (IPv6-mostly network)"
	}
	return n
}

// ---------------------------------------------------------------- local names

func (e *Engine) localNames(ctx context.Context) []model.OSLookup {
	var out []model.OSLookup
	look := func(name, purpose, expect string) {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		l := model.OSLookup{Name: name, Purpose: purpose, Expected: expect}
		start := time.Now()
		addrs, err := net.DefaultResolver.LookupNetIP(cctx, "ip", name)
		l.MS = ms(time.Since(start))
		if err != nil {
			l.Error = err.Error()
			l.OK = expect == "absent"
		} else {
			for _, a := range addrs {
				l.Addrs = append(l.Addrs, a.Unmap().String())
				if a.Unmap().Is4() {
					l.HasV4 = true
				} else {
					l.HasV6 = true
				}
			}
			l.OK = expect != "absent"
		}
		out = append(out, l)
	}
	ptr := func(ip, purpose string) {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		l := model.OSLookup{Name: ip, Purpose: purpose, Expected: "ptr"}
		start := time.Now()
		names, err := net.DefaultResolver.LookupAddr(cctx, ip)
		l.MS = ms(time.Since(start))
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				l.Error = "no PTR record"
			} else {
				l.Error = err.Error()
			}
		} else {
			l.OK = true
			l.Addrs = names
		}
		out = append(out, l)
	}
	if h := e.sys.Hostname; h != "" {
		look(h, "this computer's own name", "local")
		for _, d := range e.sys.SearchDomains {
			if !strings.Contains(h, ".") {
				look(h+"."+d, "this computer's name in search domain "+d, "local")
			}
			break
		}
	}
	look("wpad", "WPAD proxy auto-discovery (should NOT exist)", "absent")
	for _, ifc := range e.sys.Interfaces {
		if !ifc.Up || ifc.Loopback {
			continue
		}
		done := false
		for _, a := range ifc.Addrs {
			if a.Family == 4 && a.Scope == "private" {
				ptr(a.IP, "reverse lookup of this computer's IP ("+ifc.Name+")")
				done = true
				break
			}
		}
		if done {
			break
		}
	}
	for _, g := range e.sys.Gateways {
		if g.Family == 4 {
			ptr(g.Gateway, "reverse lookup of the default gateway")
			break
		}
	}
	return out
}
