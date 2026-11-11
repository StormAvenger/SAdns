package sysinfo

import (
	"net/netip"
	"strings"
)

// keepZone strips decorations from a resolver address but keeps the %zone of
// IPv6 link-local addresses, which are unusable without it.
func keepZone(s string) string {
	if i := strings.Index(s, "#"); i >= 0 { // resolvectl "1.1.1.1#cloudflare-dns.com"
		s = s[:i]
	}
	if i := strings.Index(s, "%"); i >= 0 {
		if a, err := netip.ParseAddr(s[:i]); err == nil && !a.IsLinkLocalUnicast() {
			s = s[:i]
		}
	}
	return s
}

// parseScutil reads `scutil --dns`. In the main section, resolvers without a
// "domain" are the default resolvers and those with one are split-DNS scopes.
// The "for scoped queries" section lists per-interface resolvers: they only
// serve apps bound to that interface, so they are recorded as scoped (split)
// rather than as global DNS unless the same server is also global.
func parseScutil(out string, info *Info) {
	type block struct {
		servers []string
		domain  string
		ifname  string
		search  []string
		scoped  bool
		order   int
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
			cur = &block{scoped: scoped}
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
		case k == "search_order" || k == "order":
			cur.order = len(blocks)
		}
	}
	flush()
	global := map[string]bool{}
	for _, b := range blocks {
		if !b.scoped && b.domain == "" {
			for _, s := range b.servers {
				global[keepZone(s)] = true
			}
		}
	}
	for _, b := range blocks {
		if !b.scoped {
			info.SearchDomains = append(info.SearchDomains, b.search...)
		}
		for _, s := range b.servers {
			addr := keepZone(s)
			r := Resolver{Addr: addr, Interface: b.ifname, Domain: b.domain, Source: "scutil --dns"}
			switch {
			case b.domain == "local" || strings.HasSuffix(b.domain, ".arpa"):
				// mDNS / reverse zones: not interesting for upstream tests
			case b.scoped && b.domain == "":
				if !global[addr] {
					r.Domain = "(scoped to " + b.ifname + ")"
					r.Source = "scutil --dns (scoped query section)"
					info.SplitResolvers = append(info.SplitResolvers, r)
				}
			case b.domain != "":
				info.SplitResolvers = append(info.SplitResolvers, r)
			default:
				info.Resolvers = append(info.Resolvers, r)
			}
		}
	}
}
