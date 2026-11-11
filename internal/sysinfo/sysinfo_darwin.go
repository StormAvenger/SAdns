//go:build darwin

package sysinfo

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/execx"
)

func collectOS(ctx context.Context, info *Info) {
	info.ResolverManager = "macOS configd (scutil --dns)"
	if o := execx.Run(ctx, 5*time.Second, "sw_vers"); o.Error == "" {
		var name, ver string
		for _, l := range strings.Split(o.Output, "\n") {
			k, v, _ := strings.Cut(l, ":")
			switch strings.TrimSpace(k) {
			case "ProductName":
				name = strings.TrimSpace(v)
			case "ProductVersion":
				ver = strings.TrimSpace(v)
			}
		}
		info.OSVersion = strings.TrimSpace(name + " " + ver)
	}

	o := execx.Run(ctx, 8*time.Second, "scutil", "--dns")
	info.addRaw(o)
	if o.Error == "" {
		parseScutil(o.Output, info)
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		info.addRaw(execx.Output{Command: "cat /etc/resolv.conf", Output: strings.TrimSpace(string(b))})
		if len(info.Resolvers) == 0 {
			servers, search, opts := ParseResolvConf(string(b))
			for _, s := range servers {
				info.Resolvers = append(info.Resolvers, Resolver{Addr: s, Source: "/etc/resolv.conf"})
			}
			info.SearchDomains = append(info.SearchDomains, search...)
			for k, v := range opts {
				info.ResolverOptions[k] = v
			}
		}
	}

	for _, fam := range []struct {
		f    int
		args []string
	}{{4, []string{"-n", "get", "default"}}, {6, []string{"-n", "get", "-inet6", "default"}}} {
		o := execx.Run(ctx, 5*time.Second, "route", fam.args...)
		info.addRaw(o)
		var gw, ifc string
		for _, l := range strings.Split(o.Output, "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), ":")
			switch strings.TrimSpace(k) {
			case "gateway":
				gw = strings.TrimSpace(v)
			case "interface":
				ifc = strings.TrimSpace(v)
			}
		}
		if gw != "" {
			info.Gateways = append(info.Gateways, Gateway{Family: fam.f, Gateway: gw, Interface: ifc, Source: "route get default"})
		}
	}
	info.addRaw(execx.Run(ctx, 8*time.Second, "netstat", "-rn"))
}

// parseScutil reads `scutil --dns`. Resolvers without a "domain" are the
// default resolvers; resolvers with a domain are split-DNS scopes.
func parseScutil(out string, info *Info) {
	type block struct {
		servers []string
		domain  string
		ifname  string
		search  []string
	}
	var blocks []block
	var cur *block
	scoped := false
	flush := func() {
		if cur != nil {
			blocks = append(blocks, *cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "DNS configuration (for scoped queries)") {
			flush()
			scoped = true
			continue
		}
		if strings.HasPrefix(line, "resolver #") {
			flush()
			cur = &block{}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch {
		case strings.HasPrefix(k, "nameserver["):
			cur.servers = append(cur.servers, v)
		case k == "domain":
			cur.domain = v
		case strings.HasPrefix(k, "search domain["):
			cur.search = append(cur.search, v)
		case k == "if_index":
			if i := strings.Index(v, "("); i >= 0 {
				cur.ifname = strings.TrimSuffix(v[i+1:], ")")
			}
		}
	}
	flush()
	_ = scoped
	for _, b := range blocks {
		info.SearchDomains = append(info.SearchDomains, b.search...)
		for _, s := range b.servers {
			r := Resolver{Addr: stripZone(s), Interface: b.ifname, Domain: b.domain, Source: "scutil --dns"}
			switch {
			case b.domain == "local" || strings.HasSuffix(b.domain, ".arpa"):
				// mDNS / reverse zones: not interesting for upstream tests
			case b.domain != "":
				info.SplitResolvers = append(info.SplitResolvers, r)
			default:
				info.Resolvers = append(info.Resolvers, r)
			}
		}
	}
}

func stripZone(s string) string {
	if i := strings.Index(s, "%"); i >= 0 {
		return s[:i]
	}
	return s
}
