package report

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

// Redactor masks personally identifying network data in rendered output:
// public IPv4 addresses belonging to the user, the user's IPv6 prefixes,
// MAC addresses and the hostname. Resolver/provider addresses are kept,
// since they are needed for diagnosis and identify nobody.
type Redactor struct {
	exact  []string
	v6nets []netip.Prefix
	keep   map[string]bool
}

var (
	v6Token  = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[\w.\-]+)?`)
	macToken = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
)

// NewRedactor builds a redactor from what the report reveals about the user.
func NewRedactor(r *model.Report) *Redactor {
	rd := &Redactor{keep: map[string]bool{}}
	if r.System != nil && len(r.System.Hostname) >= 3 {
		rd.exact = append(rd.exact, r.System.Hostname)
	}
	addV6 := func(a netip.Addr) {
		if p, err := a.Prefix(56); err == nil {
			rd.v6nets = append(rd.v6nets, p)
		}
	}
	for _, s := range []string{r.PublicIP.IPv4.IP, r.PublicIP.IPv6.IP} {
		if a, err := netip.ParseAddr(s); err == nil {
			if a.Is4() {
				rd.exact = append(rd.exact, a.String())
			} else {
				addV6(a)
			}
		}
	}
	if r.System != nil {
		for _, ifc := range r.System.Interfaces {
			for _, ad := range ifc.Addrs {
				a, err := netip.ParseAddr(ad.IP)
				if err != nil || ad.Scope != "public" {
					continue
				}
				if a.Is4() {
					rd.exact = append(rd.exact, a.String())
				} else {
					addV6(a)
				}
			}
		}
	}
	for _, x := range r.Resolvers {
		if x.Egress.ECS != "" {
			rd.exact = append(rd.exact, x.Egress.ECS)
		}
		if ap, err := netip.ParseAddrPort(x.Addr); err == nil {
			rd.keep[ap.Addr().String()] = true // never redact resolvers under test
		}
	}
	// Longest first so substrings don't break longer matches.
	sort.Slice(rd.exact, func(i, j int) bool { return len(rd.exact[i]) > len(rd.exact[j]) })
	return rd
}

// Apply returns s with sensitive data replaced.
func (rd *Redactor) Apply(s string) string {
	for _, e := range rd.exact {
		if e == "" || rd.keep[e] {
			continue
		}
		rep := "[redacted]"
		if a, err := netip.ParseAddr(e); err == nil && a.Is4() {
			rep = "[public-ipv4]"
		} else if strings.Contains(e, "/") {
			rep = "[client-subnet]"
		} else {
			rep = "[hostname]"
		}
		s = replaceWord(s, e, rep)
	}
	s = macToken.ReplaceAllString(s, "[mac]")
	if len(rd.v6nets) > 0 {
		s = v6Token.ReplaceAllStringFunc(s, func(tok string) string {
			a, err := netip.ParseAddr(tok)
			if err != nil {
				return tok
			}
			a = a.WithZone("")
			if rd.keep[a.String()] || sysinfo.Classify(a) != "public" {
				return tok
			}
			for _, p := range rd.v6nets {
				if p.Contains(a) {
					return "[user-ipv6]"
				}
			}
			return tok
		})
	}
	return s
}

// replaceWord replaces whole-token occurrences (not inside longer IPs/words).
func replaceWord(s, old, rep string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, old)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		before := byte(' ')
		if i > 0 {
			before = s[i-1]
		}
		after := byte(' ')
		if i+len(old) < len(s) {
			after = s[i+len(old)]
		}
		if isTokenChar(before) || isTokenChar(after) {
			b.WriteString(s[:i+len(old)])
		} else {
			b.WriteString(s[:i])
			b.WriteString(rep)
		}
		s = s[i+len(old):]
	}
}

func isTokenChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-' || c == '_'
}
