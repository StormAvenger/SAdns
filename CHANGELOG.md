# Changelog

All notable changes to SAdns. Versions follow [Semantic Versioning](https://semver.org/); until 1.0 any release may change report formats.

## v0.1.0 — unreleased

First public pre-release.

### Diagnostics
- OS resolver discovery for Windows (DNS Client, NRPT, DoH policy), macOS (`scutil --dns`, including split-DNS and interface-scoped resolvers) and Linux (resolv.conf, systemd-resolved per-link routing domains).
- Per-resolver suite: UDP/TCP, AAAA, latency, uncached lookups, EDNS0, truncation→TCP, large UDP, DNSSEC (positive/negative controls, CD=1 and EDE evidence), NXDOMAIN integrity, ad/tracker filtering, identity, egress network, 0x20, EDNS version, DNS Cookies (two-step), HTTPS/SVCB records, burst handling, caching (timed against network RTT), rebinding protection (with controls), DDR, DoH/Private-Relay canaries, local DoT/DoH ports.
- Public resolvers: Cloudflare, Google, Quad9, OpenDNS, AdGuard, Control D over IPv4/IPv6, plus DoT and DoH.
- Connectivity, dual-stack, public IP, clock (HTTPS only), CGNAT (overlay-aware), interception (bogon probes + graded indicators), failover estimates, route selection, traceroute.
- Network health: ping loss/jitter with ordered samples, path MTU, NTP (validated replies), captive portal / HTTP proxy, NAT64 (all RFC 6052 prefix lengths), local names, WPAD.
- Website loading: DNS / connect / TLS / first byte / download per site and family, with root-cause correlation.

### Analysis & reports
- Findings carry evidence, a fix and a confidence (confirmed / suspected / inconclusive); coverage gaps list what could not be tested.
- Markdown report written for AI assistants; JSON for tooling; three privacy levels (full / technical / public-safe).

### UI & security
- Liquid Glass tinted-dark browser UI, cancellable scans.
- Loopback-only listener, one-time token exchanged for an HttpOnly SameSite=Strict cookie, CSRF header, hash-pinned Content-Security-Policy, bounded run time and event history.
- Shared DNS response validation (QR, ID, opcode, question, malformed data) for UDP, TCP, DoT and DoH.

### Build
- Zero third-party Go modules. CI on Linux, Windows and macOS with race detector, staticcheck and govulncheck. Release binaries with SHA-256 checksums and build-provenance attestations.
