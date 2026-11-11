//go:build linux

package sysinfo

import "testing"

func TestParseResolvectl(t *testing.T) {
	out := `Global
         Protocols: +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub
Fallback DNS Servers: 1.1.1.1#cloudflare-dns.com

Link 2 (eth0)
    Current Scopes: DNS
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1
                    fd00::1
        DNS Domain: lan ~.
`
	info := &Info{ResolverOptions: map[string]string{}}
	parseResolvectl(out, info)
	got := dedupeResolvers(info.Resolvers)
	if len(got) != 2 || got[0].Addr != "192.168.1.1" || got[1].Addr != "fd00::1" || got[0].Interface != "eth0" {
		t.Fatalf("unexpected resolvers: %+v", got)
	}
	if len(info.SearchDomains) != 1 || info.SearchDomains[0] != "lan" {
		t.Fatalf("search: %v", info.SearchDomains)
	}
	if len(info.Notes) != 1 {
		t.Fatalf("notes: %v", info.Notes)
	}
}
