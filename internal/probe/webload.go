package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
)

// webSites are single HTTPS resources used as a baseline. This is NOT a full
// browser page load (no subresources, cache or connection reuse); it isolates
// the per-connection phases every page load is made of.
var webSites = []string{
	"https://www.google.com/generate_204",
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://www.wikipedia.org/",
	"https://github.com/robots.txt",
}

const (
	// MaxCustomURLs bounds user-specified website tests per scan.
	MaxCustomURLs  = 5
	maxRedirects   = 5
	baselineBody   = 512 << 10 // read at most this much from baseline sites
	customBody     = 20 << 20  // and this much from user-specified URLs (images, downloads)
	webSampleCount = 3
)

// NormalizeURL validates a user-supplied website/resource address.
func NormalizeURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty URL")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", errors.New("only http(s) URLs with a host are supported")
	}
	if len(s) > 2000 {
		return "", errors.New("URL too long")
	}
	return u.String(), nil
}

// webLoads measures, for each site and address family, several fresh
// connections: DNS (through the OS resolver, as a browser would), TCP
// connect, TLS handshake, time to first byte and body transfer.
func (e *Engine) webLoads(ctx context.Context, conn model.Connectivity) []model.WebTiming {
	type job struct {
		url    string
		custom bool
	}
	var jobs []job
	for _, u := range webSites {
		jobs = append(jobs, job{u, false})
	}
	for i, u := range e.cfg.URLs {
		if i >= MaxCustomURLs {
			break
		}
		jobs = append(jobs, job{u, true})
	}
	results := make([][]model.WebTiming, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = e.webLoad(ctx, j.url, j.custom, conn)
		}()
	}
	wg.Wait()
	var out []model.WebTiming
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

func lookupFamily(ctx context.Context, host string, fam int) (netip.Addr, float64, error) {
	dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupNetIP(dctx, "ip", host)
	d := ms(time.Since(start))
	if err != nil {
		return netip.Addr{}, d, err
	}
	for _, a := range addrs {
		a = a.Unmap()
		if (fam == 4 && a.Is4()) || (fam == 6 && a.Is6()) {
			return a, d, nil
		}
	}
	return netip.Addr{}, d, nil
}

func (e *Engine) webLoad(ctx context.Context, rawURL string, custom bool, conn model.Connectivity) []model.WebTiming {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	// One up-front lookup: this is the DNS time a first visit experiences.
	_, dnsMS, err := lookupFamily(ctx, host, 4)
	if err != nil {
		return []model.WebTiming{{URL: rawURL, Host: host, Custom: custom, DNSMS: dnsMS, Runs: 1, Error: "DNS lookup failed: " + err.Error()}}
	}
	samples := webSampleCount
	if e.cfg.Quick {
		samples = 2
	}
	var res []model.WebTiming
	for _, fam := range []int{4, 6} {
		if (fam == 4 && (!e.cfg.IPv4 || !conn.IPv4.Working)) || (fam == 6 && (!e.cfg.IPv6 || !conn.IPv6.Working)) {
			continue
		}
		if ip, _, _ := lookupFamily(ctx, host, fam); !ip.IsValid() {
			continue // site has no address of this family
		}
		var runs []model.WebTiming
		for i := 0; i < samples && ctx.Err() == nil; i++ {
			runs = append(runs, e.fetchFollow(ctx, rawURL, fam, custom))
			sleepCtx(ctx, 150*time.Millisecond)
		}
		if len(runs) == 0 {
			continue
		}
		w := summarizeRuns(runs)
		w.URL, w.Host, w.Family, w.Custom, w.DNSMS = rawURL, host, fam, custom, dnsMS
		w.TotalMS = round2(dnsMS + w.ElapsedMS)
		res = append(res, w)
	}
	return res
}

// summarizeRuns picks the run with the median wall-clock time among the
// successful ones as the representative (so its phases belong together and
// do add up), and keeps every run's total and error.
func summarizeRuns(runs []model.WebTiming) model.WebTiming {
	var ok []model.WebTiming
	var firstErr string
	rep := runs[0]
	for _, r := range runs {
		rep.RunTotalsMS = append(rep.RunTotalsMS, r.ElapsedMS)
		if r.OK {
			ok = append(ok, r)
		} else if firstErr == "" {
			firstErr = r.Error
		}
	}
	totals := rep.RunTotalsMS
	if len(ok) > 0 {
		sort.Slice(ok, func(i, j int) bool { return ok[i].ElapsedMS < ok[j].ElapsedMS })
		rep = ok[len(ok)/2]
		rep.RunTotalsMS = totals
		rep.MinElapsedMS, rep.MaxElapsedMS = ok[0].ElapsedMS, ok[len(ok)-1].ElapsedMS
	}
	rep.Runs, rep.OKRuns = len(runs), len(ok)
	rep.OK = len(ok) == len(runs)
	if !rep.OK {
		rep.Error = firstErr
		if len(ok) > 0 {
			rep.Error = fmt.Sprintf("%d of %d attempts failed: %s", len(runs)-len(ok), len(runs), firstErr)
		}
	}
	return rep
}

// fetchFollow loads a URL over one address family, following redirects
// manually (each hop is resolved and pinned to that family). The reported
// phases are those of the final response; time spent on redirect hops is
// reported separately and included in the wall-clock total.
func (e *Engine) fetchFollow(ctx context.Context, rawURL string, fam int, custom bool) model.WebTiming {
	limit := int64(baselineBody)
	if custom {
		limit = customBody
	}
	start := time.Now()
	cur := rawURL
	var w model.WebTiming
	redirects := 0
	var redirectMS float64
	for {
		u, err := url.Parse(cur)
		if err != nil {
			w = model.WebTiming{Error: "bad redirect target: " + err.Error()}
			break
		}
		ip, _, err := lookupFamily(ctx, u.Hostname(), fam)
		if err != nil || !ip.IsValid() {
			w = model.WebTiming{Error: fmt.Sprintf("redirected to %s, which has no IPv%d address", u.Hostname(), fam)}
			if err != nil {
				w.Error = "DNS lookup of " + u.Hostname() + " failed: " + err.Error()
			}
			break
		}
		var next string
		w, next = e.fetchTimed(ctx, cur, ip, limit)
		if next == "" {
			break
		}
		redirects++
		redirectMS += w.ElapsedMS
		if redirects > maxRedirects {
			w.OK, w.Error = false, fmt.Sprintf("more than %d redirects", maxRedirects)
			break
		}
		nu, err := u.Parse(next)
		if err != nil || (nu.Scheme != "http" && nu.Scheme != "https") {
			w.OK, w.Error = false, "unusable redirect target "+next
			break
		}
		cur = nu.String()
	}
	w.Redirects, w.RedirectMS = redirects, round2(redirectMS)
	if redirects > 0 {
		w.FinalURL = cur
	}
	w.ElapsedMS = ms(time.Since(start))
	return w
}

// fetchTimed performs one GET to a fixed IP on a fresh connection. It returns
// the redirect target (if the response is a redirect) instead of following it.
func (e *Engine) fetchTimed(ctx context.Context, rawURL string, ip netip.Addr, limit int64) (model.WebTiming, string) {
	w := model.WebTiming{IP: ip.String()}
	d := &net.Dialer{Timeout: 6 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 8 * time.Second,
		DisableKeepAlives:   true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Trace hooks may run on transport goroutines (HTTP/2), so guard them.
	var tmu sync.Mutex
	var tConnStart, tConnDone, tTLSStart, tTLSDone, tWrote, tFirst time.Time
	mark := func(t *time.Time) func() {
		return func() { tmu.Lock(); *t = time.Now(); tmu.Unlock() }
	}
	trace := &httptrace.ClientTrace{
		ConnectStart:         func(string, string) { mark(&tConnStart)() },
		ConnectDone:          func(string, string, error) { mark(&tConnDone)() },
		TLSHandshakeStart:    mark(&tTLSStart),
		TLSHandshakeDone:     func(tls.ConnectionState, error) { mark(&tTLSDone)() },
		WroteRequest:         func(httptrace.WroteRequestInfo) { mark(&tWrote)() },
		GotFirstResponseByte: mark(&tFirst),
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, rawURL, nil)
	if err != nil {
		w.Error = err.Error()
		return w, ""
	}
	req.Header.Set("User-Agent", "SAdns web timing (+https://github.com/StormAvenger/SAdns)")
	start := time.Now()
	resp, err := cl.Do(req)
	tmu.Lock()
	cs, cd, ts, td, wr, fb := tConnStart, tConnDone, tTLSStart, tTLSDone, tWrote, tFirst
	tmu.Unlock()
	span := func(a, b time.Time) float64 {
		if a.IsZero() || b.IsZero() || b.Before(a) {
			return 0
		}
		return ms(b.Sub(a))
	}
	w.ConnectMS = span(cs, cd)
	w.TLSMS = span(ts, td)
	w.TTFBMS = span(wr, fb)
	if err != nil {
		w.Error = err.Error()
		w.ElapsedMS = ms(time.Since(start))
		return w, ""
	}
	defer resp.Body.Close()
	w.Status, w.Proto = resp.StatusCode, resp.Proto
	if resp.TLS != nil {
		w.TLSVersion = tls.VersionName(resp.TLS.Version)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			w.ElapsedMS = ms(time.Since(start))
			return w, loc
		}
	}
	n, cerr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	end := time.Now()
	w.Bytes = n
	w.DownloadMS = span(fb, end)
	w.ElapsedMS = ms(end.Sub(start))
	w.Truncated = n >= limit
	if w.DownloadMS >= 50 && n >= 100<<10 {
		w.RateKbps = round2(float64(n) * 8 / 1000 / (w.DownloadMS / 1000))
	}
	switch {
	case cerr != nil:
		w.Error = fmt.Sprintf("transfer interrupted after %d bytes: %v", n, cerr)
	case !w.Truncated && resp.ContentLength >= 0 && n != resp.ContentLength:
		w.Error = fmt.Sprintf("incomplete body: received %d of %d bytes", n, resp.ContentLength)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		w.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	default:
		w.OK = true
	}
	return w, ""
}
