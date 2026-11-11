# Changelog

All notable changes to SAdns. Versions follow [Semantic Versioning](https://semver.org/); until 1.0 any release may change report formats.

## v0.1.0 — 2026-11-11

First public pre-release.

### Dashboard and UI
- Redesigned UI: graphite / ice-blue glass material, design tokens, light / dark / auto appearance, reduced-motion and reduced-transparency support, keyboard focus, responsive from phones to wide desktops.
- Dashboard with overall status, Run diagnostics, live progress, last and next scan, Auto Run status, top issues, path overview, resolver comparison, latency/loss and website timing charts.
- Distinct Healthy / Warning / Failed / Unknown / Not tested states (colour, glyph and word).
- Settings built from one row component with identical switches in a fixed right-hand column; Advanced section for providers, websites, extra resolvers, samples and timeout.

### History, trends, Auto Run
- Persistent history of completed, cancelled and failed scans: pin, delete, clear, import, compare two scans, download any scan for AI.
- Trend charts: DNS latency/jitter/loss, gateway and internet round trip and loss, website load, warnings/failures, IPv4/IPv6 health.
- Auto Run scheduler (default off; 60 min, Quick, Standard data, keep 100): pause, resume, run now, cancel; no overlapping scans; one catch-up scan after downtime; persists across restarts.
- File-based, versioned storage with atomic writes and crash recovery ([docs/STORAGE.md](docs/STORAGE.md)).

### Server mode and Docker
- `sadns serve`: password-protected dashboard for LAN/Docker (PBKDF2 hash, sessions, CSRF, Host allow-list, rate limiting). Desktop mode unchanged: loopback only.
- `/api/v1` JSON API and `sadns healthcheck`.
- Multi-stage, multi-arch Dockerfile (non-root, health check, graceful stop), Compose file, Unraid template, CI build and smoke test. No image is published.
- Container vantage detection: bridge results are labelled as the container's view, with coverage gaps; host networking is an explicit opt-in.
- `sadns run --save` stores CLI scans in history (Docker one-shot).

### Groundwork
- JSON Schema for reports (`docs/schema/report.schema.json`), generated from the code and tested.
- `mobile/sadnsmobile`: gomobile-compatible on-device engine binding; [docs/ANDROID.md](docs/ANDROID.md).
- Benchmarks and [docs/LANGUAGE-EVALUATION.md](docs/LANGUAGE-EVALUATION.md).

### Diagnostics
- OS resolver discovery for Windows (DNS Client, NRPT, DoH policy), macOS (`scutil --dns`, including split-DNS and interface-scoped resolvers) and Linux (resolv.conf, systemd-resolved per-link routing domains).
- Per-resolver suite: UDP/TCP, AAAA, latency, uncached lookups, EDNS0, truncation→TCP, large UDP, DNSSEC (positive/negative controls, CD=1 and EDE evidence), NXDOMAIN integrity, ad/tracker filtering, identity, egress network, 0x20, EDNS version, DNS Cookies (two-step), HTTPS/SVCB records, burst handling, caching (timed against network RTT), rebinding protection (with controls), DDR, DoH/Private-Relay canaries, local DoT/DoH ports.
- Public resolvers: Cloudflare, Google, Quad9, OpenDNS, AdGuard, Control D over IPv4/IPv6, plus DoT and DoH.
- Connectivity, dual-stack, public IP, clock (HTTPS only), CGNAT (overlay-aware), interception (bogon probes + graded indicators), failover estimates, route selection, traceroute.
- Network health: ping loss/jitter with ordered samples, path MTU, NTP (validated replies), captive portal / HTTP proxy, NAT64 (all RFC 6052 prefix lengths), local names, WPAD.
- Website loading: DNS / connect / TLS / first byte / download per site and family, with root-cause correlation.

- Website tests: 3 runs per resource and family, measured wall-clock totals, redirects followed and reported, completeness (2xx + full body) required, transfer rate, user-specified URLs (`--url`).

- Low Data Mode (`--low-data`, UI toggle, off by default): 1 website sample, 512 KiB per response, 10 MiB shared HTTP budget per scan; standard mode unchanged. Central `DataPolicy`.
- Download outcomes: complete-verified / complete / sampled / budget-limited / failed — hitting the sample limit is no longer reported as a full download. HTTP data usage reported in UI, Markdown and JSON.

### Analysis & reports
- Path overview (device → LAN → router → internet → DNS → websites) with an explicit "not tested" state; verdict *partial* when nothing failed but significant areas were untested.
- Findings carry evidence, a fix and a confidence (confirmed / suspected / inconclusive); coverage gaps list what could not be tested.
- Markdown report written for AI assistants; JSON for tooling; three privacy levels (full / technical / public-safe).

### UI & security
- Liquid Glass tinted-dark browser UI, cancellable scans.
- Loopback-only listener, one-time token exchanged for an HttpOnly SameSite=Strict cookie, CSRF header, hash-pinned Content-Security-Policy, bounded run time and event history.
- Shared DNS response validation (QR, ID, opcode, question, malformed data) for UDP, TCP, DoT and DoH.

### Build
- Zero third-party Go modules. CI on Linux, Windows and macOS with race detector, staticcheck and govulncheck. Release binaries with SHA-256 checksums and build-provenance attestations.
