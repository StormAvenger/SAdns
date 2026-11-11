package sysinfo

import (
	"net/netip"
	"regexp"
	"strings"
)

var resolvectlKey = regexp.MustCompile(`^([A-Za-z][A-Za-z .]*):\s*(.*)$`)

// parseResolvectl reads `resolvectl status`, keeping each link's servers and
// routing domains together. A link's servers are only "default" DNS if the
// link carries +DefaultRoute (or the global section lists servers); links
// with only ~routing domains are split DNS (typical for VPNs), and are
// recorded as split resolvers instead of being flattened into one list.
func parseResolvectl(out string, info *Info) {
	type link struct {
		name         string
		servers      []string
		domains      []string
		defaultRoute bool
		hasProtocols bool
	}
	var links []*link
	cur := &link{name: "", defaultRoute: true} // Global section
	links = append(links, cur)
	lastKey := ""
	addServers := func(key, val string) {
		for _, s := range strings.Fields(val) {
			s = keepZone(s)
			if _, err := netip.ParseAddr(s); err != nil {
				continue
			}
			switch key {
			case "DNS Servers", "Current DNS Server":
				cur.servers = append(cur.servers, s)
			case "Fallback DNS Servers":
				info.note("systemd-resolved fallback DNS server configured: " + s + " (used only if no other DNS is known)")
			}
		}
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "Global" {
			cur, lastKey = links[0], ""
			continue
		}
		if strings.HasPrefix(line, "Link ") {
			name := ""
			if i := strings.Index(line, "("); i >= 0 {
				name = strings.TrimSuffix(line[i+1:], ")")
			}
			cur = &link{name: name}
			links = append(links, cur)
			lastKey = ""
			continue
		}
		if m := resolvectlKey.FindStringSubmatch(line); m != nil && (strings.Contains(m[1], " ") || m[1] == "Protocols") {
			lastKey = strings.TrimSpace(m[1])
			val := strings.TrimSpace(m[2])
			switch lastKey {
			case "Protocols":
				cur.hasProtocols = true
				if strings.Contains(val, "+DefaultRoute") {
					cur.defaultRoute = true
				}
			case "DNS Domain":
				cur.domains = append(cur.domains, strings.Fields(val)...)
			default:
				addServers(lastKey, val)
			}
			continue
		}
		if lastKey == "DNS Domain" {
			cur.domains = append(cur.domains, strings.Fields(line)...)
			continue
		}
		addServers(lastKey, line) // continuation of the previous key
	}
	for _, l := range links {
		var search, routing []string
		catchAll := false
		for _, d := range l.domains {
			switch {
			case d == "~.":
				catchAll = true
			case strings.HasPrefix(d, "~"):
				routing = append(routing, strings.TrimPrefix(d, "~"))
			default:
				search = append(search, d)
			}
		}
		info.SearchDomains = append(info.SearchDomains, search...)
		// Older systemd lacks the +DefaultRoute flag: then a link is default
		// unless it only has routing domains.
		isDefault := l.defaultRoute || catchAll || (!l.hasProtocols && len(routing) == 0)
		src := "resolvectl"
		if l.name != "" {
			src += " link " + l.name
		} else {
			src += " global"
		}
		for _, s := range l.servers {
			if isDefault {
				info.Resolvers = append(info.Resolvers, Resolver{Addr: s, Interface: l.name, Source: src})
			} else {
				dom := strings.Join(append(routing, search...), ", ")
				if dom == "" {
					dom = "(link " + l.name + ", not default route)"
				}
				info.SplitResolvers = append(info.SplitResolvers, Resolver{Addr: s, Interface: l.name, Domain: dom, Source: src + " (split DNS)"})
			}
		}
	}
}
