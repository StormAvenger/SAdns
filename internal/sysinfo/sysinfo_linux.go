//go:build linux

package sysinfo

import (
	"bufio"
	"context"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/execx"
)

func collectOS(ctx context.Context, info *Info) {
	info.OSVersion = linuxVersion()

	// resolv.conf
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		info.addRaw(execx.Output{Command: "cat /etc/resolv.conf", Output: strings.TrimSpace(string(b))})
		servers, search, opts := ParseResolvConf(string(b))
		info.SearchDomains = append(info.SearchDomains, search...)
		for k, v := range opts {
			info.ResolverOptions[k] = v
		}
		stub := false
		info.ResolverManager = "/etc/resolv.conf (glibc-style stub)"
		for _, s := range servers {
			if IsStub(s) {
				stub = true
				info.StubResolvers = append(info.StubResolvers, Resolver{Addr: s, Source: "/etc/resolv.conf"})
			} else {
				info.Resolvers = append(info.Resolvers, Resolver{Addr: s, Source: "/etc/resolv.conf"})
			}
		}
		if link, err := os.Readlink("/etc/resolv.conf"); err == nil {
			info.note("/etc/resolv.conf is a symlink to " + link)
		}
		if stub {
			info.ResolverManager = "local stub (likely systemd-resolved)"
			for _, p := range []string{"/run/systemd/resolve/resolv.conf"} {
				if b, err := os.ReadFile(p); err == nil {
					info.addRaw(execx.Output{Command: "cat " + p, Output: strings.TrimSpace(string(b))})
					up, s2, _ := ParseResolvConf(string(b))
					info.ResolverManager = "systemd-resolved"
					for _, s := range up {
						info.Resolvers = append(info.Resolvers, Resolver{Addr: s, Source: p + " (systemd-resolved upstream)"})
					}
					info.SearchDomains = append(info.SearchDomains, s2...)
				}
			}
		}
	} else {
		info.note("could not read /etc/resolv.conf: " + err.Error())
	}

	// Gateways from procfs (no external tools needed).
	info.Gateways = append(info.Gateways, procRoute4()...)
	info.Gateways = append(info.Gateways, procRoute6()...)

	// Best-effort raw context.
	type c struct {
		name string
		args []string
	}
	cmds := []c{
		{"ip", []string{"-4", "route", "show", "table", "all"}},
		{"ip", []string{"-6", "route", "show", "table", "all"}},
		{"ip", []string{"rule", "show"}},
		{"resolvectl", []string{"status", "--no-pager"}},
		{"nmcli", []string{"-t", "-f", "IP4.DNS,IP6.DNS,IP4.GATEWAY,IP6.GATEWAY,GENERAL.DEVICE", "device", "show"}},
	}
	done := make(chan execx.Output, len(cmds))
	n := 0
	for _, cm := range cmds {
		if !execx.Exists(cm.name) {
			continue
		}
		n++
		go func(cm c) { done <- execx.Run(ctx, 8*time.Second, cm.name, cm.args...) }(cm)
	}
	for i := 0; i < n; i++ {
		o := <-done
		info.addRaw(o)
		if strings.HasPrefix(o.Command, "resolvectl") && o.Error == "" {
			parseResolvectl(o.Output, info)
		}
	}
}

func linuxVersion() string {
	var name string
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				name = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		k := strings.TrimSpace(string(b))
		if name == "" {
			return "Linux " + k
		}
		return name + " (kernel " + k + ")"
	}
	return name
}

func procRoute4() []Gateway {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Gateway
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 8 || fl[1] != "00000000" || fl[7] != "00000000" {
			continue
		}
		gw, err := hex.DecodeString(fl[2])
		if err != nil || len(gw) != 4 {
			continue
		}
		metric, _ := strconv.Atoi(fl[6])
		ip := netip.AddrFrom4([4]byte{gw[3], gw[2], gw[1], gw[0]})
		if ip.IsUnspecified() {
			continue // default route without gateway (point-to-point, e.g. VPN)
		}
		out = append(out, Gateway{Family: 4, Gateway: ip.String(), Interface: fl[0], Metric: metric, Source: "/proc/net/route"})
	}
	return out
}

func procRoute6() []Gateway {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Gateway
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 10 || fl[0] != strings.Repeat("0", 32) || fl[1] != "00" {
			continue
		}
		nh, err := hex.DecodeString(fl[4])
		if err != nil || len(nh) != 16 {
			continue
		}
		ip := netip.AddrFrom16([16]byte(nh))
		if ip.IsUnspecified() || fl[9] == "lo" {
			continue
		}
		metric64, _ := strconv.ParseUint(fl[5], 16, 32)
		out = append(out, Gateway{Family: 6, Gateway: ip.String() + "%" + fl[9], Interface: fl[9], Metric: int(metric64), Source: "/proc/net/ipv6_route"})
	}
	return out
}
