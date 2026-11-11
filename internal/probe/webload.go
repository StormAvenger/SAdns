package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
)

// webSites are fetched to break real page loads into phases. Small, stable,
// globally anycast/CDN-hosted pages.
var webSites = []string{
	"https://www.google.com/generate_204",
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://www.wikipedia.org/",
	"https://github.com/robots.txt",
}

// webLoads measures DNS (through the OS resolver, as a browser would), TCP
// connect, TLS handshake, time to first byte and download — separately over
// IPv4 and IPv6 — so slow browsing can be attributed to the right layer.
func (e *Engine) webLoads(ctx context.Context, conn model.Connectivity) []model.WebTiming {
	var out []model.WebTiming
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, u := range webSites {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			res := e.webLoad(ctx, u, conn)
			mu.Lock()
			out = append(out, res...)
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	// Stable order: site, then family.
	order := map[string]int{}
	for i, u := range webSites {
		order[u] = i
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && (order[out[j].URL] < order[out[j-1].URL] || (out[j].URL == out[j-1].URL && out[j].Family < out[j-1].Family)); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (e *Engine) webLoad(ctx context.Context, rawURL string, conn model.Connectivity) []model.WebTiming {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	host := req.URL.Hostname()
	dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupNetIP(dctx, "ip", host)
	dnsMS := ms(time.Since(start))
	cancel()
	if err != nil {
		return []model.WebTiming{{URL: rawURL, Host: host, DNSMS: dnsMS, Error: "DNS lookup failed: " + err.Error()}}
	}
	var res []model.WebTiming
	for _, fam := range []int{4, 6} {
		if (fam == 4 && (!e.cfg.IPv4 || !conn.IPv4.Working)) || (fam == 6 && (!e.cfg.IPv6 || !conn.IPv6.Working)) {
			continue
		}
		var ip netip.Addr
		for _, a := range addrs {
			a = a.Unmap()
			if (fam == 4 && a.Is4()) || (fam == 6 && a.Is6()) {
				ip = a
				break
			}
		}
		if !ip.IsValid() {
			continue // site has no address of this family
		}
		w := e.fetchTimed(ctx, rawURL, ip)
		w.Host, w.Family, w.DNSMS = host, fam, dnsMS
		w.TotalMS = round2(w.DNSMS + w.ConnectMS + w.TLSMS + w.TTFBMS + w.DownloadMS)
		res = append(res, w)
	}
	return res
}

// fetchTimed performs one GET to a fixed IP with a fresh connection.
func (e *Engine) fetchTimed(ctx context.Context, rawURL string, ip netip.Addr) model.WebTiming {
	w := model.WebTiming{URL: rawURL, IP: ip.String()}
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
	cl := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

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
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, rawURL, nil)
	req.Header.Set("User-Agent", "SAdns web timing (+https://github.com/StormAvenger/SAdns)")
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
		return w
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 512<<10))
	w.DownloadMS = span(fb, time.Now())
	w.OK = resp.StatusCode < 400
	w.Status, w.Proto, w.Bytes = resp.StatusCode, resp.Proto, n
	if resp.TLS != nil {
		w.TLSVersion = tls.VersionName(resp.TLS.Version)
	}
	return w
}
