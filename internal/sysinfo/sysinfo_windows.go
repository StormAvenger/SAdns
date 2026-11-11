//go:build windows

package sysinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/execx"
)

// One PowerShell invocation gathers everything (each launch costs ~1s).
const psScript = `$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
$up=@{}; Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $up[[int]$_.ifIndex]=$true }
$o.dns=@(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | ForEach-Object { [ordered]@{alias=$_.InterfaceAlias;index=[int]$_.InterfaceIndex;family=[int]$_.AddressFamily;up=[bool]$up[[int]$_.InterfaceIndex];servers=@($_.ServerAddresses)} })
$o.suffix=@((Get-DnsClientGlobalSetting).SuffixSearchList)
$o.connsuffix=@(Get-DnsClient | Where-Object { $_.ConnectionSpecificSuffix } | ForEach-Object { $_.ConnectionSpecificSuffix })
$o.routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' | ForEach-Object { [ordered]@{prefix=$_.DestinationPrefix;nexthop=$_.NextHop;alias=$_.InterfaceAlias;index=[int]$_.InterfaceIndex;metric=[int]$_.RouteMetric} })
$os=Get-CimInstance Win32_OperatingSystem; $o.os="$($os.Caption) $($os.Version)"
$o.doh=@(Get-DnsClientDohServerAddress | ForEach-Object { "$($_.ServerAddress) template=$($_.DohTemplate) autoupgrade=$($_.AutoUpgrade) udpfallback=$($_.AllowFallbackToUdp)" })
$o.nrpt=@(Get-DnsClientNrptPolicy | ForEach-Object { "$($_.Namespace) -> $($_.NameServers -join ',')" })
$o | ConvertTo-Json -Depth 5 -Compress`

type psDNS struct {
	Alias   string   `json:"alias"`
	Index   int      `json:"index"`
	Family  int      `json:"family"`
	Up      bool     `json:"up"`
	Servers flexList `json:"servers"`
}

type psRoute struct {
	Prefix  string `json:"prefix"`
	NextHop string `json:"nexthop"`
	Alias   string `json:"alias"`
	Index   int    `json:"index"`
	Metric  int    `json:"metric"`
}

type psOut struct {
	DNS        []psDNS   `json:"dns"`
	Suffix     flexList  `json:"suffix"`
	ConnSuffix flexList  `json:"connsuffix"`
	Routes     []psRoute `json:"routes"`
	OS         string    `json:"os"`
	DoH        flexList  `json:"doh"`
	NRPT       flexList  `json:"nrpt"`
}

// flexList accepts a JSON string, array of strings, or null.
type flexList []string

func (f *flexList) UnmarshalJSON(b []byte) error {
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		*f = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "" {
			*f = []string{s}
		}
		return nil
	}
	return nil
}

func collectOS(ctx context.Context, info *Info) {
	info.ResolverManager = "Windows DNS Client"
	o := execx.Run(ctx, 25*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	o.Command = "powershell (SAdns network inventory script)"
	info.addRaw(o)
	var ps psOut
	if err := json.Unmarshal([]byte(strings.TrimSpace(o.Output)), &ps); err != nil {
		info.note("could not parse PowerShell network inventory: " + err.Error())
	} else {
		info.OSVersion = ps.OS
		for _, d := range ps.DNS {
			for _, s := range d.Servers {
				r := Resolver{Addr: s, Interface: d.Alias, Source: fmt.Sprintf("Get-DnsClientServerAddress (%s)", d.Alias)}
				if !d.Up {
					continue // stale config on a disconnected adapter
				}
				if strings.HasPrefix(strings.ToLower(s), "fec0:0:0:ffff::") {
					info.note(fmt.Sprintf("Interface %q has the deprecated Windows default IPv6 DNS %s (site-local placeholder, never answers)", d.Alias, s))
				}
				info.Resolvers = append(info.Resolvers, r)
			}
		}
		info.SearchDomains = append(info.SearchDomains, ps.Suffix...)
		info.SearchDomains = append(info.SearchDomains, ps.ConnSuffix...)
		for _, rt := range ps.Routes {
			fam := 4
			if strings.Contains(rt.Prefix, ":") {
				fam = 6
			}
			if rt.NextHop == "" || rt.NextHop == "0.0.0.0" || rt.NextHop == "::" {
				continue
			}
			info.Gateways = append(info.Gateways, Gateway{Family: fam, Gateway: rt.NextHop, Interface: rt.Alias, Metric: rt.Metric, Source: "Get-NetRoute"})
		}
		for _, d := range ps.DoH {
			info.note("Windows DoH server mapping: " + d)
		}
		for _, n := range ps.NRPT {
			info.note("NRPT (split DNS) rule: " + n)
		}
	}
	info.addRaw(execx.Run(ctx, 15*time.Second, "ipconfig", "/all"))
	info.addRaw(execx.Run(ctx, 15*time.Second, "route", "print"))
}
