// Package sysinfo discovers the host's network configuration: interfaces,
// addresses, default gateways and the DNS resolvers the OS is configured to
// use. OS-specific discovery lives in sysinfo_<os>.go.
package sysinfo

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/StormAvenger/SAdns/internal/execx"
)

// IfAddr is one interface address with a coarse classification.
type IfAddr struct {
	CIDR   string `json:"cidr"`
	IP     string `json:"ip"`
	Family int    `json:"family"` // 4 or 6
	Scope  string `json:"scope"`  // public, private, cgnat, link-local, ula, loopback, ...
}

// Interface is a network interface.
type Interface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MTU       int      `json:"mtu"`
	HWAddr    string   `json:"hwaddr,omitempty"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	LikelyVPN bool     `json:"likely_vpn"`
	Flags     string   `json:"flags"`
	Addrs     []IfAddr `json:"addrs"`
}

// Gateway is a default route.
type Gateway struct {
	Family    int    `json:"family"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface,omitempty"`
	Metric    int    `json:"metric,omitempty"`
	Source    string `json:"source"`
}

// Resolver is a DNS server the OS is configured to use.
type Resolver struct {
	Addr      string `json:"addr"`
	Interface string `json:"interface,omitempty"`
	Domain    string `json:"domain,omitempty"` // non-empty for split-DNS (scoped) resolvers
	Source    string `json:"source"`
}

// Info is everything discovered about the host.
type Info struct {
	OS              string            `json:"os"`
	OSVersion       string            `json:"os_version"`
	Arch            string            `json:"arch"`
	Hostname        string            `json:"hostname"`
	Interfaces      []Interface       `json:"interfaces"`
	Gateways        []Gateway         `json:"default_gateways"`
	Resolvers       []Resolver        `json:"resolvers"`       // effective upstream resolvers the OS uses
	StubResolvers   []Resolver        `json:"stub_resolvers"`  // local stubs (127.0.0.53, etc.) the OS points at
	SplitResolvers  []Resolver        `json:"split_resolvers"` // domain-scoped resolvers (VPN split DNS etc.)
	SearchDomains   []string          `json:"search_domains"`
	ResolverOptions map[string]string `json:"resolver_options,omitempty"`
	ResolverManager string            `json:"resolver_manager,omitempty"` // systemd-resolved, scutil, Windows DNS Client, ...
	Notes           []string          `json:"notes,omitempty"`
	Raw             []execx.Output    `json:"raw,omitempty"`

	mu sync.Mutex
}

func (i *Info) addRaw(o execx.Output) {
	i.mu.Lock()
	i.Raw = append(i.Raw, o)
	i.mu.Unlock()
}

func (i *Info) note(s string) {
	i.mu.Lock()
	i.Notes = append(i.Notes, s)
	i.mu.Unlock()
}

// Collect gathers host information. It never fails; problems become Notes.
func Collect(ctx context.Context) *Info {
	info := &Info{OS: runtime.GOOS, Arch: runtime.GOARCH, ResolverOptions: map[string]string{}}
	info.Hostname, _ = os.Hostname()
	info.Interfaces = interfaces()
	collectOS(ctx, info)
	info.Resolvers = dedupeResolvers(info.Resolvers)
	info.StubResolvers = dedupeResolvers(info.StubResolvers)
	info.SplitResolvers = dedupeResolvers(info.SplitResolvers)
	info.SearchDomains = dedupeStrings(info.SearchDomains)
	return info
}

func interfaces() []Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Interface
	for _, ifc := range ifs {
		it := Interface{
			Name:      ifc.Name,
			Index:     ifc.Index,
			MTU:       ifc.MTU,
			HWAddr:    ifc.HardwareAddr.String(),
			Up:        ifc.Flags&net.FlagUp != 0,
			Loopback:  ifc.Flags&net.FlagLoopback != 0,
			Flags:     ifc.Flags.String(),
			LikelyVPN: likelyVPN(ifc.Name),
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr()
			fam := 4
			if ip.Is6() && !ip.Is4In6() {
				fam = 6
			}
			it.Addrs = append(it.Addrs, IfAddr{CIDR: pfx.String(), IP: ip.String(), Family: fam, Scope: Classify(ip)})
		}
		out = append(out, it)
	}
	return out
}

func likelyVPN(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"tun", "tap", "utun", "wg", "tailscale", "zt", "ppp", "ipsec", "vpn", "wireguard", "nordlynx", "proton", "mullvad", "openvpn", "cloudflare warp", "warp"} {
		if strings.HasPrefix(n, p) || strings.Contains(n, p) {
			return true
		}
	}
	return false
}

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	testNet1  = netip.MustParsePrefix("192.0.2.0/24")
	testNet2  = netip.MustParsePrefix("198.51.100.0/24")
	testNet3  = netip.MustParsePrefix("203.0.113.0/24")
	doc6      = netip.MustParsePrefix("2001:db8::/32")
	siteLocal = netip.MustParsePrefix("fec0::/10")
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
)

// Classify gives a coarse scope label for an address.
func Classify(ip netip.Addr) string {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid():
		return "invalid"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsMulticast():
		return "multicast"
	case cgnat.Contains(ip):
		return "cgnat"
	case testNet1.Contains(ip), testNet2.Contains(ip), testNet3.Contains(ip), doc6.Contains(ip):
		return "documentation"
	case siteLocal.Contains(ip):
		return "site-local-deprecated"
	case nat64.Contains(ip):
		return "nat64"
	case ip.Is6() && ip.IsPrivate():
		return "ula"
	case ip.IsPrivate():
		return "private"
	}
	return "public"
}

// IsLocalScope is true for addresses that never leave the site.
func IsLocalScope(scope string) bool {
	switch scope {
	case "loopback", "link-local", "private", "ula", "site-local-deprecated":
		return true
	}
	return false
}

// HasAddr reports whether the host has a usable address of the given family
// (excluding loopback and link-local).
func (i *Info) HasAddr(family int) bool {
	for _, ifc := range i.Interfaces {
		if !ifc.Up || ifc.Loopback {
			continue
		}
		for _, a := range ifc.Addrs {
			if a.Family == family && a.Scope != "link-local" && a.Scope != "loopback" {
				return true
			}
		}
	}
	return false
}

// HasGlobalV6 reports whether a public (GUA) IPv6 address is configured.
func (i *Info) HasGlobalV6() bool {
	for _, ifc := range i.Interfaces {
		if !ifc.Up {
			continue
		}
		for _, a := range ifc.Addrs {
			if a.Family == 6 && a.Scope == "public" {
				return true
			}
		}
	}
	return false
}

// HasGateway reports whether a default route exists for the family.
func (i *Info) HasGateway(family int) bool {
	for _, g := range i.Gateways {
		if g.Family == family {
			return true
		}
	}
	return false
}

// InterfaceForIP returns the interface owning a local IP, if any.
func (i *Info) InterfaceForIP(ip netip.Addr) *Interface {
	ip = ip.Unmap().WithZone("")
	for k := range i.Interfaces {
		for _, a := range i.Interfaces[k].Addrs {
			if p, err := netip.ParseAddr(a.IP); err == nil && p.WithZone("") == ip {
				return &i.Interfaces[k]
			}
		}
	}
	return nil
}

// OnLink reports whether ip is inside one of the host's directly connected subnets.
func (i *Info) OnLink(ip netip.Addr) (bool, string) {
	ip = ip.Unmap().WithZone("")
	if ip.IsLinkLocalUnicast() {
		return true, ""
	}
	for _, ifc := range i.Interfaces {
		for _, a := range ifc.Addrs {
			p, err := netip.ParsePrefix(a.CIDR)
			if err != nil || p.Bits() == p.Addr().BitLen() {
				continue
			}
			if p.Masked().Contains(ip) {
				return true, ifc.Name
			}
		}
	}
	return false, ""
}

// IsLocalIP reports whether ip is assigned to this host.
func (i *Info) IsLocalIP(ip netip.Addr) bool { return i.InterfaceForIP(ip) != nil }

func dedupeResolvers(in []Resolver) []Resolver {
	seen := map[string]int{}
	var out []Resolver
	for _, r := range in {
		r.Addr = normalizeAddr(r.Addr)
		if r.Addr == "" {
			continue
		}
		key := r.Addr + "|" + r.Domain
		if idx, ok := seen[key]; ok {
			if out[idx].Interface == "" && r.Interface != "" {
				out[idx].Interface = r.Interface
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, r)
	}
	return out
}

func normalizeAddr(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "[]")
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String()
	}
	return ""
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ParseResolvConf parses resolv.conf-format content.
func ParseResolvConf(content string) (servers, search []string, opts map[string]string) {
	opts = map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			servers = append(servers, f[1])
		case "search", "domain":
			search = append(search, f[1:]...)
		case "options":
			for _, o := range f[1:] {
				k, v, _ := strings.Cut(o, ":")
				opts[k] = v
			}
		}
	}
	return
}

// IsStub reports whether addr is a loopback stub resolver.
func IsStub(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return a.IsLoopback()
}

// SortedInterfaces returns interfaces with up, non-loopback ones first.
func (i *Info) SortedInterfaces() []Interface {
	out := append([]Interface(nil), i.Interfaces...)
	sort.SliceStable(out, func(a, b int) bool {
		ra := rank(out[a])
		rb := rank(out[b])
		return ra < rb
	})
	return out
}

func rank(i Interface) int {
	switch {
	case i.Up && !i.Loopback && len(i.Addrs) > 0:
		return 0
	case i.Up && !i.Loopback:
		return 1
	case i.Loopback:
		return 3
	}
	return 2
}
