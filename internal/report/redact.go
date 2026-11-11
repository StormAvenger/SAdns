package report

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

// Privacy levels for shared reports.
const (
	// PrivacyFull keeps everything (for your own use).
	PrivacyFull = "full"
	// PrivacyTechnical masks identifiers that point at you or your device —
	// public IPs, your IPv6 prefix, hostname, MACs, ECS subnet — but keeps the
	// LAN layout an expert needs (private IPs, interface names, domains).
	PrivacyTechnical = "technical"
	// PrivacyPublic additionally replaces private/LAN addresses with
	// consistent placeholders ([lan-ip-1] is always the same host) and masks
	// internal domain names, so a report can be posted publicly.
	PrivacyPublic = "public"
)

// ParsePrivacy normalises a privacy level, defaulting to technical.
func ParsePrivacy(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case PrivacyFull, "none", "off":
		return PrivacyFull
	case PrivacyPublic, "public-safe", "max":
		return PrivacyPublic
	}
	return PrivacyTechnical
}

// Redactor rewrites rendered output. It works on the final Markdown/JSON
// text on purpose: that also covers raw command output (ipconfig, scutil,
// resolvectl, traceroute) that a model-level redaction would miss.
type Redactor struct {
	level   string
	exact   map[string]string // literal → placeholder (hostname, public IPv4, ECS, domains)
	v6nets  []netip.Prefix    // user's IPv6 prefixes
	keep    map[string]bool   // addresses that must stay (public resolvers under test)
	lan     map[string]string // private address → [lan-ip-N] (public level)
	lanNext int
}

var (
	v6Token  = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[\w.\-]+)?`)
	v4Token  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	macToken = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
)

// NewRedactor builds a redactor for the given privacy level.
func NewRedactor(r *model.Report, level string) *Redactor {
	rd := &Redactor{level: ParsePrivacy(level), exact: map[string]string{}, keep: map[string]bool{}, lan: map[string]string{}}
	if rd.level == PrivacyFull {
		return rd
	}
	if r.System != nil && len(r.System.Hostname) >= 3 {
		rd.exact[r.System.Hostname] = "[hostname]"
	}
	addV6 := func(a netip.Addr) {
		if p, err := a.Prefix(56); err == nil {
			rd.v6nets = append(rd.v6nets, p)
		}
	}
	for _, s := range []string{r.PublicIP.IPv4.IP, r.PublicIP.IPv6.IP} {
		if a, err := netip.ParseAddr(s); err == nil {
			if a.Is4() {
				rd.exact[a.String()] = "[public-ipv4]"
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
					rd.exact[a.String()] = "[public-ipv4]"
				} else {
					addV6(a)
				}
			}
		}
	}
	for _, x := range r.Resolvers {
		if x.Egress.ECS != "" {
			rd.exact[x.Egress.ECS] = "[client-subnet]"
		}
		if ap, err := netip.ParseAddrPort(x.Addr); err == nil && (x.Role == "public" || x.ProviderKey != "") {
			rd.keep[ap.Addr().String()] = true // well-known resolvers identify nobody
		}
		// A local resolver's egress is usually the ISP resolver near you.
		if rd.level == PrivacyPublic && x.Role != "public" && x.Egress.IP != "" {
			rd.exact[x.Egress.IP] = "[isp-resolver-ip]"
		}
	}
	if rd.level == PrivacyPublic && r.System != nil {
		n := 0
		var doms []string
		doms = append(doms, r.System.SearchDomains...)
		for _, s := range r.System.SplitResolvers {
			if s.Domain != "" && !strings.HasPrefix(s.Domain, "(") {
				doms = append(doms, strings.Split(s.Domain, ", ")...)
			}
		}
		for _, d := range doms {
			d = strings.TrimSuffix(strings.TrimSpace(d), ".")
			if len(d) < 3 || rd.exact[d] != "" {
				continue
			}
			n++
			rd.exact[d] = fmt.Sprintf("[internal-domain-%d]", n)
		}
	}
	return rd
}

// Level reports the effective privacy level.
func (rd *Redactor) Level() string { return rd.level }

// Apply returns s with identifiers replaced according to the privacy level.
func (rd *Redactor) Apply(s string) string {
	if rd.level == PrivacyFull {
		return s
	}
	keys := make([]string, 0, len(rd.exact))
	for k := range rd.exact {
		keys = append(keys, k)
	}
	// Longest first so substrings don't break longer matches.
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		if !rd.keep[k] {
			s = replaceWord(s, k, rd.exact[k])
		}
	}
	s = macToken.ReplaceAllString(s, "[mac]")
	s = v6Token.ReplaceAllStringFunc(s, func(tok string) string {
		a, err := netip.ParseAddr(tok)
		if err != nil {
			return tok
		}
		bare := a.WithZone("")
		if rd.keep[bare.String()] {
			return tok
		}
		scope := sysinfo.Classify(bare)
		if scope == "public" {
			for _, p := range rd.v6nets {
				if p.Contains(bare) {
					return "[user-ipv6]"
				}
			}
			return tok
		}
		if rd.level == PrivacyPublic && (scope == "ula" || scope == "link-local") {
			return rd.lanName(bare.String(), "lan-ipv6")
		}
		return tok
	})
	if rd.level == PrivacyPublic {
		var b strings.Builder
		last := 0
		for _, m := range v4Token.FindAllStringIndex(s, -1) {
			tok := s[m[0]:m[1]]
			// Part of a hostname such as 10.0.0.1.nip.io: leave it.
			if m[1]+1 < len(s) && s[m[1]] == '.' && (s[m[1]+1] >= 'a' && s[m[1]+1] <= 'z') {
				continue
			}
			a, err := netip.ParseAddr(tok)
			if err != nil || rd.keep[tok] {
				continue
			}
			if sc := sysinfo.Classify(a); sc == "private" || sc == "cgnat" || sc == "link-local" {
				b.WriteString(s[last:m[0]])
				b.WriteString(rd.lanName(tok, "lan-ip"))
				last = m[1]
			}
		}
		b.WriteString(s[last:])
		s = b.String()
	}
	return s
}

// lanName maps a private address to a stable placeholder so relationships
// (gateway == DNS server) survive anonymisation.
func (rd *Redactor) lanName(addr, kind string) string {
	if v, ok := rd.lan[addr]; ok {
		return v
	}
	rd.lanNext++
	v := fmt.Sprintf("[%s-%d]", kind, rd.lanNext)
	rd.lan[addr] = v
	return v
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
		// A trailing '.' followed by a non-word character is sentence/FQDN
		// punctuation, not part of a longer token.
		afterIsDot := after == '.' && (i+len(old)+1 >= len(s) || !isTokenChar(s[i+len(old)+1]))
		if isTokenChar(before) || (isTokenChar(after) && !afterIsDot) {
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
