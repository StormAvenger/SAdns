// Package model defines the report data structure shared by the probe engine,
// the analyzer, the Markdown/JSON renderers and the web UI.
package model

import (
	"time"

	"github.com/StormAvenger/SAdns/internal/execx"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
)

// Status values for tests and findings.
const (
	Pass = "pass"
	Info = "info"
	Warn = "warn"
	Fail = "fail"
	Skip = "skip"
)

// Report is the complete result of a sadns run.
type Report struct {
	Schema       string           `json:"schema"`
	Tool         ToolInfo         `json:"tool"`
	StartedAt    time.Time        `json:"started_at"`
	FinishedAt   time.Time        `json:"finished_at"`
	DurationSec  float64          `json:"duration_sec"`
	Options      Options          `json:"options"`
	Summary      Summary          `json:"summary"`
	Findings     []Finding        `json:"findings"`
	System       *sysinfo.Info    `json:"system"`
	Connectivity Connectivity     `json:"connectivity"`
	PublicIP     PublicIP         `json:"public_ip"`
	OSLookups    []OSLookup       `json:"os_lookups"`
	DualStack    []DualStack      `json:"dual_stack"`
	Resolvers    []ResolverResult `json:"resolvers"`
	Interception Interception     `json:"interception"`
	Failover     Failover         `json:"failover"`
	Routing      Routing          `json:"routing"`
	Network      NetHealth        `json:"network_health"`
	Web          []WebTiming      `json:"web_timings"`
	Privacy      string           `json:"privacy"`             // full, technical, public
	Cancelled    bool             `json:"cancelled,omitempty"` // run stopped early: results incomplete
}

// ToolInfo identifies the build that produced the report.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
	Repo    string `json:"repo"`
}

// Options records how the run was configured.
type Options struct {
	Samples     int      `json:"samples"`
	TimeoutMS   int64    `json:"timeout_ms"`
	Providers   []string `json:"providers"`
	NoProviders bool     `json:"no_public_providers,omitempty"`
	URLs        []string `json:"user_urls,omitempty"`
	Extra       []string `json:"extra_resolvers"`
	Quick       bool     `json:"quick"`
	Traceroute  bool     `json:"traceroute"`
	Encrypted   bool     `json:"encrypted"`
	IPv4        bool     `json:"ipv4"`
	IPv6        bool     `json:"ipv6"`
}

// Summary is the headline result.
type Summary struct {
	Verdict  string `json:"verdict"` // healthy, degraded, broken
	Headline string `json:"headline"`
	Pass     int    `json:"pass"`
	Info     int    `json:"info"`
	Warn     int    `json:"warn"`
	Fail     int    `json:"fail"`
	// Layers summarises the path device → LAN → gateway → internet → DNS →
	// websites. "unknown" means not tested — never shown as healthy.
	Layers []Layer `json:"layers,omitempty"`
	// Coverage lists checks that could not run (missing tools, disabled
	// families, unreachable test services) so a clean result is not mistaken
	// for a complete one.
	Coverage []string `json:"coverage_gaps,omitempty"`
}

// Finding is an analyzed conclusion with evidence and a suggested fix.
type Finding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Detail         string   `json:"detail"`
	Evidence       []string `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	// Confidence: confirmed (independent checks agree), suspected (another
	// cause is possible), inconclusive (evidence missing or contradictory).
	Confidence string `json:"confidence,omitempty"`
	Layer      string `json:"layer,omitempty"` // device, lan, gateway, internet, dns, web
}

// Probe is a single TCP connectivity attempt.
type Probe struct {
	Target    string  `json:"target"`
	Name      string  `json:"name"`
	Family    int     `json:"family"`
	OK        bool    `json:"ok"`
	RTTMS     float64 `json:"rtt_ms"`
	Error     string  `json:"error,omitempty"`
	ErrClass  string  `json:"error_class,omitempty"`
	LocalAddr string  `json:"local_addr,omitempty"`
}

// FamilyConn summarises one IP family.
type FamilyConn struct {
	Disabled   bool    `json:"disabled_by_option,omitempty"`
	HasAddress bool    `json:"has_address"`
	HasGlobal  bool    `json:"has_global_address"`
	HasGateway bool    `json:"has_default_route"`
	Working    bool    `json:"working"`
	Probes     []Probe `json:"probes"`
}

// Connectivity holds raw IPv4/IPv6 reachability.
type Connectivity struct {
	IPv4 FamilyConn `json:"ipv4"`
	IPv6 FamilyConn `json:"ipv6"`
}

// TraceInfo is the result of Cloudflare's /cdn-cgi/trace endpoint.
type TraceInfo struct {
	OK         bool    `json:"ok"`
	Method     string  `json:"method,omitempty"`
	IP         string  `json:"ip,omitempty"`
	Colo       string  `json:"colo,omitempty"`
	Loc        string  `json:"loc,omitempty"`
	Warp       string  `json:"warp,omitempty"`
	TLS        string  `json:"tls,omitempty"`
	CertIssuer string  `json:"cert_issuer,omitempty"`
	ClockSkew  float64 `json:"clock_skew_sec,omitempty"`
	ClockKnown bool    `json:"clock_known"`
	Error      string  `json:"error,omitempty"`
}

// PublicIP holds the internet-facing addresses.
type PublicIP struct {
	IPv4  TraceInfo `json:"ipv4"`
	IPv6  TraceInfo `json:"ipv6"`
	CGNAT bool      `json:"cgnat"`
	Notes []string  `json:"notes,omitempty"`
}

// OSLookup is a lookup through the operating system's resolver API.
type OSLookup struct {
	Name     string   `json:"name"`
	Purpose  string   `json:"purpose"`
	OK       bool     `json:"ok"`
	Addrs    []string `json:"addrs,omitempty"`
	HasV4    bool     `json:"has_v4"`
	HasV6    bool     `json:"has_v6"`
	MS       float64  `json:"ms"`
	Error    string   `json:"error,omitempty"`
	Expected string   `json:"expected,omitempty"`
	Resolved bool     `json:"resolved"`          // the lookup itself succeeded
	Missing  string   `json:"missing,omitempty"` // expected record family absent: "A", "AAAA"
}

// DualStack checks whether a dual-stack host is reachable over both families.
type DualStack struct {
	Host    string `json:"host"`
	HasA    bool   `json:"has_a"`
	HasAAAA bool   `json:"has_aaaa"`
	V4      *Probe `json:"v4,omitempty"`
	V6      *Probe `json:"v6,omitempty"`
}

// TestResult is one check against one resolver.
type TestResult struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail"`
	Query   string   `json:"query,omitempty"`
	RTTMS   float64  `json:"rtt_ms,omitempty"`
	Rcode   string   `json:"rcode,omitempty"`
	Flags   string   `json:"flags,omitempty"`
	Size    int      `json:"size,omitempty"`
	Answers []string `json:"answers,omitempty"`
	EDE     []string `json:"ede,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Latency is a set of repeated cached-query timings.
type Latency struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	MinMS    float64 `json:"min_ms"`
	AvgMS    float64 `json:"avg_ms"`
	MedianMS float64 `json:"median_ms"`
	P90MS    float64 `json:"p90_ms"`
	MaxMS    float64 `json:"max_ms"`
	JitterMS float64 `json:"jitter_ms"`
}

// Egress is the address the resolver uses to reach authoritative servers.
type Egress struct {
	IP      string `json:"ip,omitempty"`
	ASN     string `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	ECS     string `json:"ecs,omitempty"`
	Method  string `json:"method,omitempty"`
	Matches string `json:"matches_provider,omitempty"` // yes, no, unknown
}

// ResolverResult holds every test for one resolver address.
type ResolverResult struct {
	Label            string            `json:"label"`
	Provider         string            `json:"provider"`
	ProviderKey      string            `json:"provider_key"`
	Role             string            `json:"role"` // system, gateway, public, custom
	Addr             string            `json:"addr"`
	Family           int               `json:"family"`
	Primary          bool              `json:"primary"`
	Interface        string            `json:"interface,omitempty"`
	LocalAddr        string            `json:"local_addr,omitempty"`
	OnLink           bool              `json:"on_link"`
	Reachable        bool              `json:"reachable"`
	Latency          Latency           `json:"latency"`
	ColdMS           float64           `json:"uncached_ms,omitempty"`
	DNSSEC           string            `json:"dnssec"`                      // validating, not-validating, inconsistent, inconclusive, n/a
	DNSSECConfidence string            `json:"dnssec_confidence,omitempty"` // confirmed, suspected, inconclusive
	HTTPSRR          string            `json:"https_rr"`                    // records, empty, error, unknown
	ColdP90MS        float64           `json:"uncached_p90_ms,omitempty"`
	Filtering        string            `json:"filtering"` // blocks-ads, no-ad-blocking, unknown
	NXDOMAIN         string            `json:"nxdomain"`  // correct, hijacked, unknown
	Software         string            `json:"software,omitempty"`
	Rebind           string            `json:"rebind_protection"` // on, off, unknown
	Caching          string            `json:"caching"`           // local-cache, upstream-cache, no-cache, unknown
	Cookies          string            `json:"cookies"`           // yes, no
	Case0x20         string            `json:"case_0x20"`         // preserved, broken, unknown
	DDR              []string          `json:"ddr_targets,omitempty"`
	CanaryDoH        string            `json:"canary_doh"`   // disables-doh, allows-doh, unknown
	CanaryRelay      string            `json:"canary_relay"` // blocks-relay, allows-relay, unknown
	OpenPorts        []int             `json:"encrypted_ports_open,omitempty"`
	Identity         map[string]string `json:"identity,omitempty"`
	Egress           Egress            `json:"egress"`
	Tests            []TestResult      `json:"tests"`
}

// Filters reports whether this is a public provider that filters by design.
func (r *ResolverResult) Filters() bool { return r.ProviderKey == "adguard" }

// Test returns the named test, or nil.
func (r *ResolverResult) Test(id string) *TestResult {
	for i := range r.Tests {
		if r.Tests[i].ID == id {
			return &r.Tests[i]
		}
	}
	return nil
}

// Interception holds transparent-proxy / hijack evidence.
type Interception struct {
	BogonProbes []TestResult `json:"bogon_probes"`
	Detected    bool         `json:"detected"`
	Notes       []string     `json:"notes,omitempty"`
}

// Failover describes how the OS would fail over between resolvers.
type Failover struct {
	ConfiguredCount int      `json:"configured_count"`
	WorkingCount    int      `json:"working_count"`
	DistinctHosts   int      `json:"distinct_hosts"`
	WorstCaseSec    float64  `json:"worst_case_sec,omitempty"`
	Model           string   `json:"model,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

// Hop is one traceroute hop.
type Hop struct {
	TTL     int     `json:"ttl"`
	Addr    string  `json:"addr,omitempty"`
	RTTMS   float64 `json:"rtt_ms,omitempty"`
	Timeout bool    `json:"timeout"`
	Scope   string  `json:"scope,omitempty"`
}

// Trace is one traceroute run.
type Trace struct {
	Target      string        `json:"target"`
	Label       string        `json:"label"`
	Family      int           `json:"family"`
	Tool        string        `json:"tool,omitempty"`
	Reached     bool          `json:"reached"`
	PrivateHops int           `json:"private_hops"`
	CGNATHops   int           `json:"cgnat_hops"`
	Hops        []Hop         `json:"hops"`
	Error       string        `json:"error,omitempty"`
	Raw         *execx.Output `json:"raw,omitempty"`
}

// RouteChoice records which local address/interface the kernel picks for a destination.
type RouteChoice struct {
	Dest      string `json:"dest"`
	Label     string `json:"label"`
	LocalAddr string `json:"local_addr,omitempty"`
	Interface string `json:"interface,omitempty"`
	VPN       bool   `json:"via_vpn"`
	OnLink    bool   `json:"on_link"`
	Error     string `json:"error,omitempty"`
}

// Routing holds path information.
type Routing struct {
	Choices []RouteChoice `json:"route_choices"`
	Traces  []Trace       `json:"traceroutes"`
}

// NetHealth holds link/path quality and service checks beyond DNS.
type NetHealth struct {
	Pings []Ping      `json:"pings"`
	MTU   []PathMTU   `json:"path_mtu"`
	NTP   []NTPResult `json:"ntp"`
	HTTP  []HTTPCheck `json:"http_checks"`
	NAT64 NAT64       `json:"nat64"`
	Local []OSLookup  `json:"local_names"`
}

// Ping is an ICMP echo series run via the system ping tool.
type Ping struct {
	Target   string        `json:"target"`
	Label    string        `json:"label"`
	Family   int           `json:"family"`
	Sent     int           `json:"sent"`
	Received int           `json:"received"`
	LossPct  float64       `json:"loss_pct"`
	MinMS    float64       `json:"min_ms"`
	AvgMS    float64       `json:"avg_ms"`
	MaxMS    float64       `json:"max_ms"`
	JitterMS float64       `json:"jitter_ms"`
	Samples  []float64     `json:"samples_ms,omitempty"` // per packet in send order; -1 = lost; absent if order unknown
	Error    string        `json:"error,omitempty"`
	Raw      *execx.Output `json:"raw,omitempty"`
}

// PathMTU is the largest unfragmented packet that reached the target.
type PathMTU struct {
	Target string   `json:"target"`
	Family int      `json:"family"`
	MTU    int      `json:"mtu"`
	Detail string   `json:"detail"`
	Error  string   `json:"error,omitempty"`
	Probes []string `json:"probes,omitempty"`
}

// NTPResult is one SNTP exchange.
type NTPResult struct {
	Server   string  `json:"server"`
	Addr     string  `json:"addr"`
	OK       bool    `json:"ok"`
	OffsetMS float64 `json:"offset_ms"`
	RTTMS    float64 `json:"rtt_ms"`
	Stratum  int     `json:"stratum"`
	Error    string  `json:"error,omitempty"`
}

// HTTPCheck is an OS-style connectivity / captive-portal probe.
type HTTPCheck struct {
	Name   string  `json:"name"`
	URL    string  `json:"url"`
	OK     bool    `json:"ok"`
	Status int     `json:"status"`
	Expect string  `json:"expect"`
	Detail string  `json:"detail"`
	Proxy  string  `json:"proxy_headers,omitempty"`
	MS     float64 `json:"ms"`
	Error  string  `json:"error,omitempty"`
}

// NAT64 reports DNS64/NAT64 detection via ipv4only.arpa (RFC 7050).
type NAT64 struct {
	Detected bool     `json:"detected"`
	Prefixes []string `json:"prefixes,omitempty"`
	Detail   string   `json:"detail"`
}

// WebTiming summarises several fresh loads of one HTTP(S) resource over one
// address family. Phase fields come from one representative run (the median
// by wall-clock time), so they belong together; RunTotalsMS keeps every run.
type WebTiming struct {
	URL          string    `json:"url"`
	Host         string    `json:"host"`
	Custom       bool      `json:"user_specified,omitempty"`
	Family       int       `json:"family"`
	IP           string    `json:"ip,omitempty"`
	OK           bool      `json:"ok"` // every run ended in a complete 2xx response
	Runs         int       `json:"runs"`
	OKRuns       int       `json:"ok_runs"`
	Status       int       `json:"status,omitempty"`
	Proto        string    `json:"proto,omitempty"`
	TLSVersion   string    `json:"tls_version,omitempty"`
	Redirects    int       `json:"redirects,omitempty"`
	RedirectMS   float64   `json:"redirect_ms,omitempty"`
	FinalURL     string    `json:"final_url,omitempty"`
	DNSMS        float64   `json:"dns_ms"` // first OS lookup of the host
	ConnectMS    float64   `json:"connect_ms"`
	TLSMS        float64   `json:"tls_ms"`
	TTFBMS       float64   `json:"ttfb_ms"`
	DownloadMS   float64   `json:"download_ms"`
	ElapsedMS    float64   `json:"elapsed_ms"` // measured wall clock of the representative run (redirects included)
	TotalMS      float64   `json:"total_ms"`   // dns_ms + elapsed_ms
	MinElapsedMS float64   `json:"min_elapsed_ms,omitempty"`
	MaxElapsedMS float64   `json:"max_elapsed_ms,omitempty"`
	RunTotalsMS  []float64 `json:"run_elapsed_ms,omitempty"`
	Bytes        int64     `json:"bytes,omitempty"`
	Truncated    bool      `json:"truncated,omitempty"` // stopped at the read limit (not a failure)
	RateKbps     float64   `json:"rate_kbps,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// Layer is one hop of the diagnostic path with its worst observed status.
type Layer struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Status string `json:"status"` // pass, warn, fail, unknown
	Note   string `json:"note"`
}
