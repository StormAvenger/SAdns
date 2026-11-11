package service

import (
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/probe"
)

// ScanRequest is the client-facing description of a scan, shared by the
// HTTP API and the mobile binding so both validate input the same way.
type ScanRequest struct {
	Quick     bool     `json:"quick"`
	Samples   int      `json:"samples"`
	TimeoutMS int      `json:"timeout_ms"`
	Providers []string `json:"providers"`
	// NoProviders must be set explicitly: an empty Providers list alone means
	// "default (all)", so clients send this when every provider is off.
	NoProviders bool     `json:"no_providers"`
	LowData     bool     `json:"low_data"`
	URLs        []string `json:"urls"`
	Extra       []string `json:"extra"`
	Traceroute  bool     `json:"traceroute"`
	Encrypted   bool     `json:"encrypted"`
	IPv4        bool     `json:"ipv4"`
	IPv6        bool     `json:"ipv6"`
}

// ConfigFrom validates and clamps a request onto a base configuration.
// Out-of-range values fall back to the base; lists are truncated to limits.
func ConfigFrom(base probe.Config, req ScanRequest) probe.Config {
	cfg := base
	cfg.Quick = req.Quick
	if req.Samples > 0 && req.Samples <= 50 {
		cfg.Samples = req.Samples
	}
	if cfg.Quick && req.Samples == 0 {
		cfg.Samples = 3
	}
	if req.TimeoutMS >= 200 && req.TimeoutMS <= 15000 {
		cfg.Timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	cfg.Providers = nil
	for i, p := range req.Providers {
		if i >= 32 {
			break
		}
		cfg.Providers = append(cfg.Providers, p)
	}
	cfg.NoProviders = req.NoProviders
	cfg.URLs = nil
	for i, u := range req.URLs {
		if i >= probe.MaxCustomURLs {
			break
		}
		if n, err := probe.NormalizeURL(u); err == nil {
			cfg.URLs = append(cfg.URLs, n)
		}
	}
	cfg.Extra = nil
	for i, x := range req.Extra {
		if i >= 16 {
			break // resource limit
		}
		if x = strings.TrimSpace(x); x != "" && len(x) <= 256 {
			cfg.Extra = append(cfg.Extra, x)
		}
	}
	cfg.Traceroute, cfg.Encrypted, cfg.IPv4, cfg.IPv6 = req.Traceroute, req.Encrypted, req.IPv4, req.IPv6
	if !cfg.IPv4 && !cfg.IPv6 {
		cfg.IPv4, cfg.IPv6 = true, true
	}
	cfg.LowData = req.LowData
	return cfg
}
