package probe

import "strings"

// Provider is a well-known public resolver service.
type Provider struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	V4      []string `json:"v4"`
	V6      []string `json:"v6"`
	DoTName string   `json:"dot_name,omitempty"` // empty = no DoT offered
	DoHHost string   `json:"doh_host,omitempty"`
	DoHPath string   `json:"doh_path,omitempty"`
	ASNs    []string `json:"asns,omitempty"` // expected egress ASNs (empty = not checked)
	Filters bool     `json:"filters"`        // intentionally blocks ads/trackers
	Note    string   `json:"note,omitempty"`
}

// Providers is the built-in catalog of public resolvers.
var Providers = []Provider{
	{
		Key: "cloudflare", Name: "Cloudflare",
		V4: []string{"1.1.1.1", "1.0.0.1"}, V6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"},
		DoTName: "one.one.one.one", DoHHost: "cloudflare-dns.com", DoHPath: "/dns-query",
		ASNs: []string{"13335"},
	},
	{
		Key: "google", Name: "Google Public DNS",
		V4: []string{"8.8.8.8", "8.8.4.4"}, V6: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
		DoTName: "dns.google", DoHHost: "dns.google", DoHPath: "/dns-query",
		ASNs: []string{"15169"},
	},
	{
		Key: "quad9", Name: "Quad9",
		V4: []string{"9.9.9.9", "149.112.112.112"}, V6: []string{"2620:fe::fe", "2620:fe::9"},
		DoTName: "dns.quad9.net", DoHHost: "dns.quad9.net", DoHPath: "/dns-query",
		ASNs: []string{"19281", "42"}, Note: "blocks known-malicious domains",
	},
	{
		Key: "opendns", Name: "OpenDNS (Cisco)",
		V4: []string{"208.67.222.222", "208.67.220.220"}, V6: []string{"2620:119:35::35", "2620:119:53::53"},
		DoTName: "dns.opendns.com", DoHHost: "dns.opendns.com", DoHPath: "/dns-query",
		ASNs: []string{"36692"},
	},
	{
		Key: "adguard", Name: "AdGuard DNS",
		V4: []string{"94.140.14.14", "94.140.15.15"}, V6: []string{"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"},
		DoTName: "dns.adguard-dns.com", DoHHost: "dns.adguard-dns.com", DoHPath: "/dns-query",
		Filters: true, Note: "blocks ads/trackers by design (acts as a positive control for filter detection)",
	},
	{
		Key: "controld", Name: "Control D (free, unfiltered)",
		V4: []string{"76.76.2.0", "76.76.10.0"}, V6: []string{"2606:1a40::", "2606:1a40:1::"},
		DoTName: "p0.freedns.controld.com", DoHHost: "freedns.controld.com", DoHPath: "/p0",
		ASNs: []string{"398962"},
	},
}

// ProviderByKey looks up a provider.
func ProviderByKey(k string) *Provider {
	k = strings.ToLower(strings.TrimSpace(k))
	for i := range Providers {
		if Providers[i].Key == k {
			return &Providers[i]
		}
	}
	return nil
}

// ProviderForAddr finds the provider owning an address, if any.
func ProviderForAddr(addr string) *Provider {
	for i := range Providers {
		for _, a := range append(append([]string{}, Providers[i].V4...), Providers[i].V6...) {
			if a == addr {
				return &Providers[i]
			}
		}
	}
	return nil
}

// ProviderKeys lists all catalog keys.
func ProviderKeys() []string {
	var k []string
	for _, p := range Providers {
		k = append(k, p.Key)
	}
	return k
}

// Test names used across the suite. Chosen for long-term stability.
const (
	nameBasic      = "example.com"       // IANA-reserved, has A and AAAA
	nameDNSSECGood = "ietf.org"          // DNSSEC-signed, stable
	nameDNSSECBad  = "dnssec-failed.org" // deliberately broken signatures (Comcast-run test zone)
	nameGoogleEcho = "o-o.myaddr.l.google.com"
	nameAkamaiEcho = "whoami.akamai.net"
)

// Ad/tracker hostnames present on virtually every blocklist.
var adNames = []string{"pagead2.googlesyndication.com", "ad.doubleclick.net"}
