package probe

import (
	"sync"

	"github.com/StormAvenger/SAdns/internal/model"
)

// DataPolicy is the single place where HTTP data-usage limits are defined.
// Standard mode favours measurement quality; Low Data Mode keeps every
// low-bandwidth diagnostic (DNS, ping, routing, TLS, IPv4/IPv6) and only
// reduces how much HTTP body data the website tests download.
type DataPolicy struct {
	LowData           bool
	WebSamples        int   // fresh loads per resource and address family
	BaselineBodyLimit int64 // max body bytes read per response, built-in sites
	CustomBodyLimit   int64 // max body bytes read per response, user-specified URLs
	ScanBodyBudget    int64 // max HTTP body bytes for the whole scan; 0 = no scan-level budget
}

const (
	kib = int64(1) << 10
	mib = int64(1) << 20
)

// NewDataPolicy returns the limits for the selected mode. Change budgets here.
func NewDataPolicy(lowData, quick bool) DataPolicy {
	if lowData {
		return DataPolicy{LowData: true, WebSamples: 1, BaselineBodyLimit: 512 * kib, CustomBodyLimit: 512 * kib, ScanBodyBudget: 10 * mib}
	}
	p := DataPolicy{WebSamples: 3, BaselineBodyLimit: 512 * kib, CustomBodyLimit: 20 * mib}
	if quick {
		p.WebSamples = 2
	}
	return p
}

// dataMeter counts HTTP body bytes for one scan and enforces the scan-level
// budget. Budgeted reads reserve bytes before reading, so concurrent
// downloads can never jointly exceed the budget.
type dataMeter struct {
	mu            sync.Mutex
	budget        int64 // 0 = unlimited
	used          int64 // body bytes actually read
	reserved      int64 // granted but not yet settled
	requests      int
	sampled       int // responses deliberately stopped at the per-response limit
	budgetLimited int // requests skipped or cut short by the scan budget
}

// reserve grants up to want bytes (possibly 0) of the remaining budget.
func (m *dataMeter) reserve(want int64) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.budget <= 0 {
		return want
	}
	avail := m.budget - m.used - m.reserved
	if avail <= 0 {
		return 0
	}
	if want > avail {
		want = avail
	}
	m.reserved += want
	return want
}

// settle returns a reservation and records the bytes that were really read.
func (m *dataMeter) settle(granted, used int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.budget > 0 {
		m.reserved -= granted
	}
	m.used += used
}

// exhausted reports whether no further budgeted download can start.
func (m *dataMeter) exhausted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.budget > 0 && m.used+m.reserved >= m.budget
}

func (m *dataMeter) request() { m.mu.Lock(); m.requests++; m.mu.Unlock() }

func (m *dataMeter) mark(outcome string) {
	m.mu.Lock()
	switch outcome {
	case model.OutcomeSampled:
		m.sampled++
	case model.OutcomeBudget:
		m.budgetLimited++
	}
	m.mu.Unlock()
}

// note records a small, fixed-size diagnostic request (captive-portal and
// public-IP checks, a few KiB each). These are essential low-bandwidth
// checks: they are counted, and charged to the budget, but never skipped.
func (m *dataMeter) note(n int64) {
	m.mu.Lock()
	m.requests++
	m.used += n
	m.mu.Unlock()
}

func (e *Engine) dataUsage() model.DataUsage {
	m, p := e.meter, e.pol
	m.mu.Lock()
	defer m.mu.Unlock()
	d := model.DataUsage{
		Mode: "standard", HTTPBodyBytes: m.used, HTTPRequests: m.requests, SampledResponses: m.sampled, BudgetLimited: m.budgetLimited,
		ScanBudgetBytes: p.ScanBodyBudget, BaselineLimitBytes: p.BaselineBodyLimit, CustomLimitBytes: p.CustomBodyLimit, WebSamples: p.WebSamples,
		Scope: "HTTP response-body bytes downloaded by the website, captive-portal and public-IP tests. Not total network usage: DNS (including DoH), TLS/HTTP protocol overhead, ping, traceroute and NTP traffic are not counted.",
	}
	if p.LowData {
		d.Mode = "low-data"
		d.ConfidenceAffected = true
		d.Note = "Low Data Mode: one website sample per address family and capped bodies, so website timing findings rest on single measurements and are reported with lower confidence."
	}
	return d
}
