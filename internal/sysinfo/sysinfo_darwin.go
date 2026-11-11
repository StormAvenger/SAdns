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
