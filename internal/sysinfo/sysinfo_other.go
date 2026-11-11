//go:build !linux && !darwin && !windows

package sysinfo

import (
	"context"
	"os"
	"strings"

	"github.com/StormAvenger/SAdns/internal/execx"
)

// collectOS for BSDs and other Unix-likes: resolv.conf only.
func collectOS(ctx context.Context, info *Info) {
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		info.addRaw(execx.Output{Command: "cat /etc/resolv.conf", Output: strings.TrimSpace(string(b))})
		servers, search, opts := ParseResolvConf(string(b))
		for _, s := range servers {
			r := Resolver{Addr: s, Source: "/etc/resolv.conf"}
			if IsStub(s) {
				info.StubResolvers = append(info.StubResolvers, r)
			} else {
				info.Resolvers = append(info.Resolvers, r)
			}
		}
		info.SearchDomains = append(info.SearchDomains, search...)
		for k, v := range opts {
			info.ResolverOptions[k] = v
		}
	}
}
