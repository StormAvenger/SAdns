package probe

import (
	"context"
	"net/netip"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/execx"
	"github.com/StormAvenger/SAdns/internal/model"
)

// traceroute runs the platform's own traceroute tool (no root needed) and
// parses its output into hops.
func (e *Engine) traceroute(ctx context.Context, dest netip.Addr, label string) model.Trace {
	fam := 4
	if dest.Is6() && !dest.Is4In6() {
		fam = 6
	}
	t := model.Trace{Target: dest.String(), Label: label, Family: fam}
	ip := dest.String()
	var name string
	var args []string
	switch runtime.GOOS {
	case "windows":
		name = "tracert"
		args = []string{"-d", "-h", "20", "-w", "600"}
		if fam == 6 {
			args = append(args, "-6")
		} else {
			args = append(args, "-4")
		}
		args = append(args, ip)
	case "darwin":
		if fam == 6 {
			name, args = "traceroute6", []string{"-n", "-q", "1", "-w", "1", "-m", "20", ip}
		} else {
			name, args = "traceroute", []string{"-n", "-q", "1", "-w", "1", "-m", "20", ip}
		}
	default:
		switch {
		case execx.Exists("traceroute"):
			name = "traceroute"
			args = []string{"-n", "-q", "1", "-w", "1", "-m", "20"}
			if fam == 6 {
				args = append(args, "-6")
			}
			args = append(args, ip)
		case execx.Exists("tracepath"):
			name = "tracepath"
			args = []string{"-n", "-m", "20"}
			if fam == 6 {
				args = append(args, "-6")
			}
			args = append(args, ip)
		}
	}
	if name == "" || !execx.Exists(name) {
		t.Error = "no traceroute tool found on this system (install traceroute or tracepath for path analysis)"
		return t
	}
	t.Tool = name
	out := execx.Run(ctx, 75*time.Second, name, args...)
	t.Raw = &out
	t.Hops = parseTrace(out.Output)
	for _, h := range t.Hops {
		switch h.Scope {
		case "private", "ula":
			t.PrivateHops++
		case "cgnat":
			t.CGNATHops++
		}
		if h.Addr == ip {
			t.Reached = true
		}
	}
	if out.Error != "" && len(t.Hops) == 0 {
		t.Error = out.Error
	}
	return t
}

var (
	hopLine = regexp.MustCompile(`^\s*(\d+)[\s:?]`)
	rttRe   = regexp.MustCompile(`<?(\d+(?:\.\d+)?)\s*ms`)
)

// parseTrace handles traceroute, traceroute6, tracepath and tracert formats.
func parseTrace(out string) []model.Hop {
	byTTL := map[int]*model.Hop{}
	var order []int
	for _, line := range strings.Split(out, "\n") {
		m := hopLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ttl, _ := strconv.Atoi(m[1])
		if ttl <= 0 || ttl > 64 {
			continue
		}
		rest := line[len(m[0]):]
		h, ok := byTTL[ttl]
		if !ok {
			h = &model.Hop{TTL: ttl, Timeout: true}
			byTTL[ttl] = h
			order = append(order, ttl)
		}
		if h.Addr == "" {
			for _, f := range strings.Fields(rest) {
				f = strings.Trim(f, "()[],:")
				if a, err := netip.ParseAddr(f); err == nil {
					h.Addr = a.String()
					h.Scope = scopeOf(h.Addr)
					h.Timeout = false
					break
				}
			}
		}
		if h.RTTMS == 0 {
			if r := rttRe.FindStringSubmatch(rest); r != nil {
				h.RTTMS, _ = strconv.ParseFloat(r[1], 64)
			}
		}
	}
	var hops []model.Hop
	for _, t := range order {
		hops = append(hops, *byTTL[t])
	}
	return hops
}
