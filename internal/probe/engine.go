// Package probe runs the SAdns test suite and assembles a model.Report.
package probe

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

// Config controls a run.
type Config struct {
	Samples     int
	Timeout     time.Duration
	Providers   []string // provider keys; empty = all
	Extra       []string // extra resolvers ("ip" or "ip:port")
	Quick       bool     // primary address per provider/family only, fewer samples
	Traceroute  bool
	Encrypted   bool // DoT/DoH tests
	IPv4        bool
	IPv6        bool
	Concurrency int
}

// DefaultConfig is the full-scope configuration.
func DefaultConfig() Config {
	return Config{Samples: 5, Timeout: 2 * time.Second, Traceroute: true, Encrypted: true, IPv4: true, IPv6: true, Concurrency: 8}
}

// Event is a progress notification for the CLI and web UI.
type Event struct {
	Type     string                `json:"type"` // phase, log, resolver, done, error
	Phase    string                `json:"phase,omitempty"`
	Message  string                `json:"message,omitempty"`
	Progress float64               `json:"progress"`
	Resolver *model.ResolverResult `json:"resolver,omitempty"`
	Report   *model.Report         `json:"report,omitempty"`
}

// Engine executes a run.
type Engine struct {
	cfg  Config
	sys  *sysinfo.Info
	emit func(Event)
	mu   sync.Mutex
	prog float64
}

// New creates an engine. emit may be nil.
func New(cfg Config, emit func(Event)) *Engine {
	if cfg.Samples <= 0 {
		cfg.Samples = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if !cfg.IPv4 && !cfg.IPv6 {
		cfg.IPv4, cfg.IPv6 = true, true
	}
	if emit == nil {
		emit = func(Event) {}
	}
	return &Engine{cfg: cfg, emit: emit}
}

func (e *Engine) phase(p float64, name, msg string) {
	e.mu.Lock()
	e.prog = p
	e.mu.Unlock()
	e.emit(Event{Type: "phase", Phase: name, Message: msg, Progress: p})
}

func (e *Engine) log(msg string) {
	e.mu.Lock()
	p := e.prog
	e.mu.Unlock()
	e.emit(Event{Type: "log", Message: msg, Progress: p})
}

// Run executes the full suite. Analysis is applied by the caller (analyze.Run)
// so the engine stays free of policy.
func (e *Engine) Run(ctx context.Context) *model.Report {
	rep := &model.Report{Schema: "sadns/report/v1", StartedAt: time.Now()}
	rep.Options = model.Options{
		Samples: e.cfg.Samples, TimeoutMS: e.cfg.Timeout.Milliseconds(), Providers: e.cfg.Providers,
		Extra: e.cfg.Extra, Quick: e.cfg.Quick, Traceroute: e.cfg.Traceroute, Encrypted: e.cfg.Encrypted,
		IPv4: e.cfg.IPv4, IPv6: e.cfg.IPv6,
	}

	e.phase(0.02, "system", "Reading network configuration (interfaces, routes, OS resolvers)")
	e.sys = sysinfo.Collect(ctx)
	rep.System = e.sys
	e.log(fmt.Sprintf("%s %s: %d interfaces, %d gateways, %d configured resolvers", e.sys.OS, e.sys.OSVersion, len(e.sys.Interfaces), len(e.sys.Gateways), len(e.sys.Resolvers)+len(e.sys.StubResolvers)))

	e.phase(0.10, "connectivity", "Testing raw IPv4/IPv6 internet connectivity")
	rep.Connectivity = e.connectivity(ctx)
	e.log(fmt.Sprintf("IPv4 working=%v, IPv6 working=%v", rep.Connectivity.IPv4.Working, rep.Connectivity.IPv6.Working))

	// Traceroutes are slow; run them in the background.
	var traceWG sync.WaitGroup
	if e.cfg.Traceroute {
		traceWG.Add(1)
		go func() {
			defer traceWG.Done()
			rep.Routing.Traces = e.traces(ctx, rep.Connectivity)
		}()
	}

	e.phase(0.16, "public-ip", "Finding public IP addresses and checking the clock")
	rep.PublicIP = e.publicIP(ctx, rep.Connectivity)

	e.phase(0.22, "os-resolver", "Resolving names through the operating system resolver path")
	rep.OSLookups = e.osLookups(ctx)
	rep.DualStack = e.dualStack(ctx, rep.OSLookups)

	// Network-health checks (ping, MTU, NTP, captive portal, NAT64, local names)
	// run alongside the resolver suite.
	var nhWG sync.WaitGroup
	nhWG.Add(1)
	go func() {
		defer nhWG.Done()
		rep.Network = e.netHealth(ctx, rep.Connectivity)
		e.log(fmt.Sprintf("network health: %d ping series, %d MTU probes, %d NTP servers, %d HTTP checks", len(rep.Network.Pings), len(rep.Network.MTU), len(rep.Network.NTP), len(rep.Network.HTTP)))
	}()

	targets := e.targets(rep.Connectivity)
	e.phase(0.30, "resolvers", fmt.Sprintf("Testing %d resolver addresses", len(targets)))
	rep.Resolvers = make([]model.ResolverResult, len(targets))
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	var doneN int
	var dmu sync.Mutex
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := e.runResolver(ctx, t)
			rep.Resolvers[i] = r
			dmu.Lock()
			doneN++
			p := 0.30 + 0.55*float64(doneN)/float64(len(targets))
			dmu.Unlock()
			rc := r
			e.emit(Event{Type: "resolver", Message: fmt.Sprintf("%s (%s): reachable=%v", r.Label, r.Addr, r.Reachable), Progress: p, Resolver: &rc})
		}(i, t)
	}
	wg.Wait()

	e.phase(0.86, "interception", "Checking for DNS interception and identifying upstream networks")
	rep.Interception.BogonProbes = e.bogonProbes(ctx)
	for _, b := range rep.Interception.BogonProbes {
		if b.Status == model.Fail {
			rep.Interception.Detected = true
		}
	}
	e.egressASNs(ctx, rep)

	nhWG.Wait()
	rep.Failover = e.failover(rep)
	rep.Routing.Choices = e.routeChoices(rep)

	if e.cfg.Traceroute {
		e.phase(0.92, "routing", "Waiting for traceroutes to finish")
		traceWG.Wait()
	}
	rep.FinishedAt = time.Now()
	rep.DurationSec = round2(rep.FinishedAt.Sub(rep.StartedAt).Seconds())
	return rep
}

// targets builds the ordered list of resolver addresses to test.
func (e *Engine) targets(conn model.Connectivity) []target {
	var out []target
	seen := map[string]bool{}
	add := func(t target) {
		k := t.addr.String()
		if seen[k] {
			return
		}
		fam := t.family()
		if (fam == 4 && !e.cfg.IPv4) || (fam == 6 && !e.cfg.IPv6) {
			return
		}
		seen[k] = true
		out = append(out, t)
	}
	parse := func(s string, def uint16) (netip.AddrPort, bool) {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			return ap, true
		}
		if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
			return netip.AddrPortFrom(a, def), true
		}
		return netip.AddrPort{}, false
	}

	for i, r := range e.sys.StubResolvers {
		if ap, ok := parse(r.Addr, 53); ok {
			add(target{label: fmt.Sprintf("OS stub resolver #%d", i+1), role: "stub", addr: ap, primary: i == 0})
		}
	}
	for i, r := range e.sys.Resolvers {
		if ap, ok := parse(r.Addr, 53); ok {
			add(target{label: fmt.Sprintf("System DNS #%d", i+1), role: "system", addr: ap, primary: i == 0, iface: r.Interface})
		}
	}
	for _, g := range e.sys.Gateways {
		if ap, ok := parse(g.Gateway, 53); ok {
			t := target{label: fmt.Sprintf("Gateway (IPv%d)", g.Family), role: "gateway", addr: ap, iface: g.Interface}
			if ap.Addr().IsLinkLocalUnicast() && ap.Addr().Zone() == "" {
				continue // link-local without zone cannot be addressed reliably
			}
			add(t)
		}
	}
	for i, x := range e.cfg.Extra {
		if ap, ok := parse(x, 53); ok {
			add(target{label: fmt.Sprintf("Custom #%d", i+1), role: "custom", addr: ap})
		}
	}

	provs := Providers
	if len(e.cfg.Providers) > 0 {
		provs = nil
		for _, k := range e.cfg.Providers {
			if p := ProviderByKey(k); p != nil {
				provs = append(provs, *p)
			}
		}
	}
	for pi := range provs {
		p := &provs[pi]
		for fam, list := range map[int][]string{4: p.V4, 6: p.V6} {
			for i, a := range list {
				if e.cfg.Quick && i > 0 {
					continue
				}
				ap := netip.AddrPortFrom(netip.MustParseAddr(a), 53)
				which := "primary"
				if i > 0 {
					which = "secondary"
				}
				t := target{label: fmt.Sprintf("%s %s IPv%d", p.Name, which, fam), role: "public", addr: ap, primary: i == 0, prov: p}
				if fam == 6 && !conn.IPv6.Working {
					t.skipWhy = "skipped: this host has no working IPv6 internet connectivity"
				}
				if fam == 4 && !conn.IPv4.Working {
					t.skipWhy = "skipped: this host has no working IPv4 internet connectivity"
				}
				add(t)
			}
		}
	}
	// Stable order: roles first, then provider, then family.
	roleRank := map[string]int{"stub": 0, "system": 1, "gateway": 2, "custom": 3, "public": 4}
	sort.SliceStable(out, func(i, j int) bool {
		if roleRank[out[i].role] != roleRank[out[j].role] {
			return roleRank[out[i].role] < roleRank[out[j].role]
		}
		if out[i].role == "public" {
			pi, pj := provIndex(out[i].prov), provIndex(out[j].prov)
			if pi != pj {
				return pi < pj
			}
			if out[i].family() != out[j].family() {
				return out[i].family() < out[j].family()
			}
			return out[i].primary && !out[j].primary
		}
		return false
	})
	return out
}

func provIndex(p *Provider) int {
	for i := range Providers {
		if p != nil && Providers[i].Key == p.Key {
			return i
		}
	}
	return 99
}

// egressASNs annotates each resolver's egress IP with its origin ASN, using
// Team Cymru's DNS service through the first resolver that can answer it.
func (e *Engine) egressASNs(ctx context.Context, rep *model.Report) {
	var vias []netip.AddrPort
	for _, role := range []string{"public", "system", "stub", "custom", "gateway"} {
		for _, r := range rep.Resolvers {
			if r.Role != role || !r.Reachable {
				continue
			}
			if t := r.Test("udp_a"); t == nil || t.Status != model.Pass {
				continue
			}
			if ap, err := netip.ParseAddrPort(r.Addr); err == nil {
				vias = append(vias, ap)
			}
		}
	}
	if len(vias) > 4 {
		vias = vias[:4]
	}
	cache := map[string][2]string{}
	for i := range rep.Resolvers {
		r := &rep.Resolvers[i]
		if r.Egress.IP == "" {
			continue
		}
		v, ok := cache[r.Egress.IP]
		if !ok {
			for _, via := range vias {
				if a, n := e.asnLookup(ctx, via, r.Egress.IP); a != "" {
					v = [2]string{a, n}
					break
				}
			}
			cache[r.Egress.IP] = v
		}
		r.Egress.ASN, r.Egress.ASName = v[0], v[1]
		r.Egress.Matches = "unknown"
		if p := ProviderByKey(r.ProviderKey); p != nil && len(p.ASNs) > 0 && r.Egress.ASN != "" {
			r.Egress.Matches = "no"
			for _, want := range p.ASNs {
				if want == r.Egress.ASN {
					r.Egress.Matches = "yes"
				}
			}
		}
	}
}

// failover models how the OS behaves when the primary resolver is dead.
func (e *Engine) failover(rep *model.Report) model.Failover {
	f := model.Failover{}
	hosts := map[string]bool{}
	for _, r := range rep.Resolvers {
		if r.Role != "system" {
			continue
		}
		f.ConfiguredCount++
		if r.Reachable {
			f.WorkingCount++
		}
		ap, err := netip.ParseAddrPort(r.Addr)
		if err == nil {
			hosts[ap.Addr().String()] = true
		}
	}
	f.DistinctHosts = len(hosts)
	opts := e.sys.ResolverOptions
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd", "netbsd":
		if strings.Contains(e.sys.ResolverManager, "systemd-resolved") {
			f.Model = "systemd-resolved: on failure it switches to the next server and keeps using it (sticky) until that one fails"
			f.WorstCaseSec = 5
		} else {
			to, at := 5.0, 2.0
			if v, err := strconv.ParseFloat(opts["timeout"], 64); err == nil {
				to = v
			}
			if v, err := strconv.ParseFloat(opts["attempts"], 64); err == nil {
				at = v
			}
			_, rotate := opts["rotate"]
			f.Model = fmt.Sprintf("glibc stub: tries servers in order with timeout:%gs attempts:%g (rotate=%v). A dead primary adds ~%gs to EVERY lookup.", to, at, rotate, to)
			f.WorstCaseSec = to * at * float64(max(1, f.ConfiguredCount))
		}
	case "windows":
		f.Model = "Windows DNS Client: primary server on preferred adapter, then all servers on all adapters after ~1s, up to ~10s total; a responding server is preferred for 15 minutes"
		f.WorstCaseSec = 10
	case "darwin":
		f.Model = "macOS mDNSResponder: queries the first server, retries others after a short timeout and remembers responsiveness"
		f.WorstCaseSec = 3
	}
	if f.ConfiguredCount == 1 {
		f.Notes = append(f.Notes, "only one system resolver configured — no DNS failover exists")
	}
	if f.ConfiguredCount > 1 && f.DistinctHosts == 1 {
		f.Notes = append(f.Notes, "all configured resolvers are the same host — no real redundancy")
	}
	return f
}

func (e *Engine) routeChoices(rep *model.Report) []model.RouteChoice {
	var out []model.RouteChoice
	seen := map[string]bool{}
	add := func(s, label string) {
		ap, err := netip.ParseAddrPort(s)
		var a netip.Addr
		if err == nil {
			a = ap.Addr()
		} else if a, err = netip.ParseAddr(s); err != nil {
			return
		}
		if seen[a.String()] {
			return
		}
		seen[a.String()] = true
		out = append(out, e.routeChoice(a, label))
	}
	for _, r := range rep.Resolvers {
		if r.Role != "public" {
			add(r.Addr, r.Label)
		}
	}
	add("1.1.1.1", "Internet (IPv4 reference)")
	add("2606:4700:4700::1111", "Internet (IPv6 reference)")
	return out
}

func (e *Engine) traces(ctx context.Context, conn model.Connectivity) []model.Trace {
	type tt struct {
		a     netip.Addr
		label string
	}
	var list []tt
	if e.cfg.IPv4 {
		list = append(list, tt{netip.MustParseAddr("1.1.1.1"), "Internet path (IPv4) to Cloudflare 1.1.1.1"})
	}
	if e.cfg.IPv6 && (conn.IPv6.Working || e.sys.HasGlobalV6()) {
		list = append(list, tt{netip.MustParseAddr("2606:4700:4700::1111"), "Internet path (IPv6) to Cloudflare 2606:4700:4700::1111"})
	}
	for _, r := range e.sys.Resolvers {
		a, err := netip.ParseAddr(r.Addr)
		if err != nil || a.IsLoopback() {
			continue
		}
		if on, _ := e.sys.OnLink(a); on {
			continue
		}
		list = append(list, tt{a, "Path to system resolver " + a.String() + " (not on the local subnet)"})
		break
	}
	out := make([]model.Trace, len(list))
	var wg sync.WaitGroup
	for i, t := range list {
		wg.Add(1)
		go func(i int, t tt) {
			defer wg.Done()
			out[i] = e.traceroute(ctx, t.a, t.label)
			e.log(fmt.Sprintf("traceroute to %s: %d hops, reached=%v", t.a, len(out[i].Hops), out[i].Reached))
		}(i, t)
	}
	wg.Wait()
	return out
}
