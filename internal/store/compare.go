package store

import (
	"sort"

	"github.com/StormAvenger/SAdns/internal/model"
)

// MetricDelta is one compared number. Missing is set when either scan did
// not measure it, so the UI never shows a fake change.
type MetricDelta struct {
	Key     string  `json:"key"`
	Name    string  `json:"name"`
	Unit    string  `json:"unit"`
	A       float64 `json:"a"`
	B       float64 `json:"b"`
	Delta   float64 `json:"delta"`
	Missing bool    `json:"missing,omitempty"`
	// Better is "lower" for times and loss; the UI colours by direction.
	Better string `json:"better"`
}

// FindingChange is a finding present in only one of the scans, or whose
// severity changed.
type FindingChange struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Change string `json:"change"` // new, resolved, changed
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

// Comparison is the result of comparing scan A (older) with scan B (newer).
type Comparison struct {
	A        Entry           `json:"a"`
	B        Entry           `json:"b"`
	Metrics  []MetricDelta   `json:"metrics"`
	Layers   []LayerChange   `json:"layers"`
	Findings []FindingChange `json:"findings"`
	Notes    []string        `json:"notes,omitempty"`
}

// LayerChange compares the path-overview status of one layer.
type LayerChange struct {
	Key string `json:"key"`
	A   string `json:"a"`
	B   string `json:"b"`
}

// Compare builds a comparison. a and b are ordered oldest → newest by the caller.
func Compare(ea, eb Entry, ra, rb *model.Report) Comparison {
	c := Comparison{A: ea, B: eb}
	ma, mb := ea.Metrics, eb.Metrics
	add := func(key, name, unit string, okA, okB bool, va, vb float64) {
		d := MetricDelta{Key: key, Name: name, Unit: unit, A: va, B: vb, Better: "lower"}
		if !okA || !okB {
			d.Missing = true
		} else {
			d.Delta = vb - va
		}
		c.Metrics = append(c.Metrics, d)
	}
	add("dns_median_ms", "DNS median (system resolver)", "ms", ma.DNSOK, mb.DNSOK, ma.DNSMedianMS, mb.DNSMedianMS)
	add("dns_loss_pct", "DNS query loss", "%", ma.DNSOK, mb.DNSOK, ma.DNSLossPct, mb.DNSLossPct)
	add("dns_jitter_ms", "DNS jitter", "ms", ma.DNSOK, mb.DNSOK, ma.DNSJitterMS, mb.DNSJitterMS)
	add("gateway_rtt_ms", "Gateway round trip", "ms", ma.GatewayOK, mb.GatewayOK, ma.GatewayRTTMS, mb.GatewayRTTMS)
	add("gateway_loss_pct", "Gateway packet loss", "%", ma.GatewayOK, mb.GatewayOK, ma.GatewayLoss, mb.GatewayLoss)
	add("internet_rtt_ms", "Internet round trip", "ms", ma.InternetOK, mb.InternetOK, ma.InternetRTTMS, mb.InternetRTTMS)
	add("internet_loss_pct", "Internet packet loss", "%", ma.InternetOK, mb.InternetOK, ma.InternetLoss, mb.InternetLoss)
	add("web_avg_ms", "Website load (mean)", "ms", ma.WebOK > 0, mb.WebOK > 0, ma.WebAvgMS, mb.WebAvgMS)
	add("warn", "Warnings", "", true, true, float64(ea.Warn), float64(eb.Warn))
	add("fail", "Failures", "", true, true, float64(ea.Fail), float64(eb.Fail))

	for _, k := range []string{"device", "lan", "gateway", "internet", "dns", "web"} {
		la, lb := ea.Layers[k], eb.Layers[k]
		if la == "" {
			la = "unknown"
		}
		if lb == "" {
			lb = "unknown"
		}
		c.Layers = append(c.Layers, LayerChange{Key: k, A: la, B: lb})
	}

	if ra != nil && rb != nil {
		fa, fb := findingMap(ra), findingMap(rb)
		for id, f := range fb {
			if o, ok := fa[id]; !ok {
				c.Findings = append(c.Findings, FindingChange{ID: id, Title: f.Title, Change: "new", To: f.Severity})
			} else if o.Severity != f.Severity {
				c.Findings = append(c.Findings, FindingChange{ID: id, Title: f.Title, Change: "changed", From: o.Severity, To: f.Severity})
			}
		}
		for id, f := range fa {
			if _, ok := fb[id]; !ok {
				c.Findings = append(c.Findings, FindingChange{ID: id, Title: f.Title, Change: "resolved", From: f.Severity})
			}
		}
		sort.Slice(c.Findings, func(i, j int) bool {
			if c.Findings[i].Change != c.Findings[j].Change {
				return c.Findings[i].Change < c.Findings[j].Change
			}
			return c.Findings[i].ID < c.Findings[j].ID
		})
	}
	if ea.Mode != eb.Mode {
		c.Notes = append(c.Notes, "The scans used different depths (quick vs full); some differences reflect coverage, not the network.")
	}
	if ea.DataMode != eb.DataMode {
		c.Notes = append(c.Notes, "One scan used Low Data Mode; website timings are not directly comparable.")
	}
	if ea.Vantage != eb.Vantage {
		c.Notes = append(c.Notes, "The scans were taken from different vantage points (e.g. host vs container); path results are not directly comparable.")
	}
	if ea.Host != eb.Host && ea.Host != "" && eb.Host != "" {
		c.Notes = append(c.Notes, "The scans come from different devices.")
	}
	return c
}

// findingMap keys findings by ID, keeping the most severe duplicate
// (some IDs repeat per resolver).
func findingMap(r *model.Report) map[string]model.Finding {
	rank := map[string]int{model.Fail: 4, model.Warn: 3, model.Info: 2, model.Pass: 1, model.Skip: 0}
	m := map[string]model.Finding{}
	for _, f := range r.Findings {
		if o, ok := m[f.ID]; !ok || rank[f.Severity] > rank[o.Severity] {
			m[f.ID] = f
		}
	}
	return m
}
