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
	Redacted     bool             `json:"redacted"`
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
	Samples    int      `json:"samples"`
	TimeoutMS  int64    `json:"timeout_ms"`
	Providers  []string `json:"providers"`
	Extra      []string `json:"extra_resolvers"`
	Quick      bool     `json:"quick"`
	Traceroute bool     `json:"traceroute"`
	Encrypted  bool     `json:"encrypted"`
	IPv4       bool     `json:"ipv4"`
	IPv6       bool     `json:"ipv6"`
}

// Summary is the headline result.
type Summary struct {
	Verdict  string `json:"verdict"` // healthy, degraded, broken
	Headline string `json:"headline"`
	Pass     int    `json:"pass"`
	Info     int    `json:"info"`
	Warn     int    `json:"warn"`
	Fail     int    `json:"fail"`
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
	Label       string            `json:"label"`
	Provider    string            `json:"provider"`
	ProviderKey string            `json:"provider_key"`
	Role        string            `json:"role"` // system, gateway, public, custom
	Addr        string            `json:"addr"`
	Family      int               `json:"family"`
	Primary     bool              `json:"primary"`
	Interface   string            `json:"interface,omitempty"`
	LocalAddr   string            `json:"local_addr,omitempty"`
	OnLink      bool              `json:"on_link"`
	Reachable   bool              `json:"reachable"`
	Latency     Latency           `json:"latency"`
	ColdMS      float64           `json:"uncached_ms,omitempty"`
	DNSSEC      string            `json:"dnssec"`    // validating, not-validating, inconclusive, n/a
	Filtering   string            `json:"filtering"` // blocks-ads, no-ad-blocking, unknown
	NXDOMAIN    string            `json:"nxdomain"`  // correct, hijacked, unknown
	Software    string            `json:"software,omitempty"`
	Identity    map[string]string `json:"identity,omitempty"`
	Egress      Egress            `json:"egress"`
	Tests       []TestResult      `json:"tests"`
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
