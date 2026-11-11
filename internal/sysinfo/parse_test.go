package sysinfo

import "testing"

// Audit scenario: macOS with a VPN split-DNS domain and an interface-scoped resolver.
func TestParseScutilScopes(t *testing.T) {
	out := `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  if_index : 6 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : corp.example.com
  nameserver[0] : 10.8.0.1
  if_index : 18 (utun3)

resolver #3
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)

resolver #2
  nameserver[0] : 10.8.0.53
  if_index : 18 (utun3)
`
	info := &Info{ResolverOptions: map[string]string{}}
	parseScutil(out, info)
	info.Resolvers = dedupeResolvers(info.Resolvers)
	info.SplitResolvers = dedupeResolvers(info.SplitResolvers)
	if len(info.Resolvers) != 2 || info.Resolvers[0].Addr != "192.168.1.1" || info.Resolvers[1].Addr != "fe80::1%en0" {
		t.Fatalf("global resolvers: %+v (link-local zone must be kept)", info.Resolvers)
	}
	if len(info.SplitResolvers) != 2 {
		t.Fatalf("split resolvers: %+v", info.SplitResolvers)
	}
	if info.SplitResolvers[0].Domain != "corp.example.com" || info.SplitResolvers[1].Addr != "10.8.0.53" || info.SplitResolvers[1].Domain != "(scoped to utun3)" {
		t.Fatalf("split detail: %+v", info.SplitResolvers)
	}
}

// systemd-resolved with a WireGuard link that only routes ~corp.example.
func TestParseResolvectlSplit(t *testing.T) {
	out := `Global
       Protocols: +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
resolv.conf mode: stub

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1 fe80::1%eth0
        DNS Domain: lan

Link 5 (wg0)
    Current Scopes: DNS
         Protocols: -DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
       DNS Servers: 10.8.0.1
        DNS Domain: ~corp.example
`
	info := &Info{ResolverOptions: map[string]string{}}
	parseResolvectl(out, info)
	info.Resolvers = dedupeResolvers(info.Resolvers)
	if len(info.Resolvers) != 2 || info.Resolvers[1].Addr != "fe80::1%eth0" {
		t.Fatalf("default resolvers: %+v", info.Resolvers)
	}
	if len(info.SplitResolvers) != 1 || info.SplitResolvers[0].Addr != "10.8.0.1" || info.SplitResolvers[0].Domain != "corp.example" {
		t.Fatalf("split: %+v", info.SplitResolvers)
	}
	if len(info.SearchDomains) != 1 || info.SearchDomains[0] != "lan" {
		t.Fatalf("search: %v", info.SearchDomains)
	}
}
