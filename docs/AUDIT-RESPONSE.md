# Response to the November 2026 repository audit

Audit of commit `b7ef524`. Each item was checked against the code before changing anything. Status: **Fixed**, **Partly** (improved, follow-up remains), **Deferred** (roadmap), **Disputed** (with reasoning).

## Highest-priority code issues

| Audit item | Status | What changed |
|---|---|---|
| DNS response validation inconsistent | **Fixed** | One `dnsclient.Validate` for UDP/TCP/DoT/DoH: QR flag, ID, opcode, question name/type/class, answers without a question, malformed data (only truncated UDP may be cut short). DoH also checks the content type. UDP ignores mismatched packets (possible spoofs) instead of failing. Tests cover each case. |
| OS lookup pass/fail incomplete | **Fixed** | Lookups are judged against the expected families (`v4+v6`, `v4`, `v6`); `Resolved` and `Missing` are recorded separately. Missing AAAA is a warning, or info when the host has no global IPv6 (AI_ADDRCONFIG). |
| DNSSEC false positives | **Fixed** | Positive control (ietf.org) must resolve; validation is *confirmed* only by a DNSSEC Extended DNS Error or a CD=1 bypass, *suspected* with AD-on-control only; an unexplained SERVFAIL is retried and then *inconclusive*. A mock "dead upstream" proves it is no longer reported as validating. |
| Dedup loses provider metadata | **Fixed** | One measurement per endpoint, but a system resolver that is 1.1.1.1 keeps its Cloudflare identity (DoT/DoH, egress-ASN verification). Test added. |
| macOS scoped resolvers | **Fixed** | Parser moved to a platform-neutral file (tested on every CI OS); scoped-only servers become split resolvers `(scoped to <if>)`; link-local zones are kept. |
| Redaction not comprehensive | **Fixed** | Three levels — full / technical (default) / public-safe (LAN IPs → consistent `[lan-ip-N]`, internal domains, ISP resolver IP). Test asserts no identifier survives in Markdown or JSON. |
| Scan cancellation incomplete | **Fixed** | Per-scan context with a 10-minute ceiling, Cancel button / `POST /api/cancel`, context-aware sleeps, phase checkpoints, queued suites skipped; report marked `cancelled`. Test cancels a live scan. |
| ASN unchecked index | **Fixed** | `parseCymruOrigin` validates structure and digits; empty/malformed TXT → unknown. Test includes the empty-record case. |

## Diagnostic accuracy

| Audit item | Status | What changed |
|---|---|---|
| HTTPS-record success on empty NOERROR | **Fixed** | Pass requires records for a name known to publish them; empty answers are compared with public resolvers (*confirmed* stripping only if they return records). |
| Caching detection | **Fixed** | Three never-seen names resolved twice; repeat time compared with the network RTT → `local-cache` / `upstream-cache` / `no-cache` / `unknown`. TTL decay is no longer used. Mock tests include "no cache, forwarding to a caching upstream". |
| Interception overconfident | **Fixed** | Indicators graded strong/weak. *Confirmed* needs the bogon probe or strong indicators from ≥2 resolvers; an ASN mismatch alone is *suspected*, with the innocent explanations and a confirming test named. |
| CGNAT from any 100.64/10 | **Fixed** | Only the default-route interface counts; Tailscale/ZeroTier/WireGuard/WARP etc. are excluded and noted. |
| CGNAT from traceroute | **Fixed** | Now an *inconclusive* observation with the confirming check. |
| Rebinding control | **Fixed** | A public-IP control on the same wildcard service must resolve first; nip.io then sslip.io; otherwise inconclusive. |
| Ad-block too narrow | **Fixed** | Five names; mechanisms counted (NXDOMAIN, REFUSED, sinkhole, EDE, empty); `blocks-ads` / `partial` / `none`. |
| Cookies incomplete | **Fixed** | The server cookie is presented on a second query; support only claimed if accepted (BADCOOKIE detected). |
| Cold lookup noisy | **Fixed** | Three unique *existing* names; median and p90 reported; failures excluded. |
| Burst without baseline | **Fixed** | 5 → 20 → 20, serialised globally; loss at 5 vs repeatable loss at 20 are reported differently. |
| Failover modelled, not measured | **Partly** | Labelled "estimate from documented OS behaviour, not measured" everywhere. Measuring it requires changing the OS DNS configuration, which a read-only diagnostic should not do — on the roadmap as an opt-in mode. |
| Ping sparkline order | **Fixed** | Per-packet samples in send order (icmp_seq on Unix, line order on Windows); losses shown where they happened; no fake ordering when unknown. |
| Confidence states | **Fixed** | `confidence` on findings (confirmed / suspected / inconclusive), shown in UI and report; plus a *coverage gaps* list so untested areas read as "unknown", not "healthy". |

## OS and network compatibility

| Audit item | Status | Notes |
|---|---|---|
| macOS actual resolution (CGO_ENABLED=0) | **Disputed** | Since Go 1.20 the `net` package on macOS resolves through the system (libSystem) even without cgo, so macOS lookups do follow the native path. The concern is valid for **Linux/BSD**, where Go's own resolver ignores nsswitch modules — now stated in the README and in every Linux report's coverage section. |
| systemd-resolved per-link routing | **Fixed** | Links without `+DefaultRoute` and with `~domain` routing become split resolvers; search vs routing domains separated. |
| Windows NRPT / DoH / VPN routing | **Partly** | NRPT rules and DoH mappings are captured and shown; deeper effective-resolver analysis is on the roadmap. |
| IPv6 link-local zones | **Fixed** | `%zone` kept for link-local servers on macOS and Linux. |
| NAT64 /96 only | **Fixed** | RFC 6052 layouts for /32–/96 with the u-octet rule; tests for several lengths. |
| -4/-6 consistency | **Fixed** | Connectivity, public-IP, ping, MTU, NTP and web tests all honour the flags; disabled families are reported, not diagnosed. |
| VPN / overlays | **Fixed** | Broader overlay list (Tailscale, ZeroTier, WireGuard, WARP, NetBird, Nebula, AnyConnect, GlobalProtect, Fortinet…). |
| Minimal containers | **Fixed** | Missing tools appear as coverage gaps, never as a clean result. |
| Policy routing / multiple gateways | **Partly** | Every gateway is tested and route selection is reported per destination; policy-routing analysis is future work. |

## Security, privacy and reliability

| Audit item | Status | Notes |
|---|---|---|
| Redaction off by default | **Fixed** | Copy/download default to *Technical*; *Full* asks for confirmation. |
| Loopback not enforced | **Fixed** | `--listen` rejects non-loopback addresses. |
| NTP response integrity | **Fixed** | Mode, version, stratum, leap indicator, origin-timestamp echo and non-zero timestamps validated. |
| HTTP fallback trust | **Fixed** | Clock skew is only taken from a verified HTTPS response. |
| Resource limits | **Fixed** | Run ceiling, event-history cap, extra-resolver cap, response-size limits. |
| Token in URLs | **Fixed** | The browser has to be opened with a URL, so the first request carries the token; it is immediately exchanged for an HttpOnly SameSite=Strict cookie and removed with `history.replaceState`. API requests no longer accept it in the query string. |
| Inline CSP | **Fixed** | `script-src`/`style-src` pinned to SHA-256 hashes of the shipped blocks; no `unsafe-inline`; inline style attributes removed. A test fails if the hashes drift. |
| Model-level redaction | **Disputed (design)** | Redaction runs on the final Markdown/JSON on purpose: that is the only place raw command output (ipconfig, scutil, traceroutes) can be scrubbed. The audit's goal — no identifier in shared output — is enforced by a test instead. |

## Build, testing, documentation

| Audit item | Status | Notes |
|---|---|---|
| No published release | **Pending owner** | Publishing creates a public download page, so it is left to the repository owner: **Actions → Release → Run workflow**. |
| Manual-release instructions wrong | **Fixed (audit correct)** | The README described a `workflow_dispatch` trigger that had not actually been committed. It now exists. |
| macOS CI | **Fixed** | Matrix: Ubuntu, Windows, macOS. |
| Race detection | **Fixed** | `go test -race` in CI — it immediately found a real race in HTTP/2 trace hooks, now fixed. |
| Pinned actions, permissions | **Fixed** | Actions pinned to commit SHAs; minimal `permissions`. |
| Attestation / checksums | **Fixed** | Build-provenance attestation and SHA-256 sums on every release; code signing deferred. |
| Portable checksums | **Fixed** | `sha256sum` or `shasum -a 256`. |
| Partial-failure reporting | **Fixed** | Skip / inconclusive states plus coverage gaps. |
| Coverage, static analysis | **Fixed** | Per-package coverage, staticcheck and govulncheck in CI. |
| SECURITY / CONTRIBUTING / CHANGELOG / templates | **Fixed** | Added. |
| README roadmap stale | **Fixed** | Roadmap now lists only unbuilt work. |

## Features

Built now: **website loading diagnostics** (DNS / connect / TLS / first byte / download per site and family, with correlation — e.g. "DNS 5 ms, TLS 800 ms → don't change DNS").

Roadmap: read-only UniFi / Pi-hole / AdGuard Home integration, DHCP option 6 and RA/RDNSS inspection, measured failover, DoQ / DoH3, history and monitoring, Docker image for Unraid, guided symptom-based diagnostics, signed binaries.

## Not yet covered by tests

"Windows, macOS and Linux produce equivalent results for the same network" needs real hosts; CI now runs the unit and mock suites natively on all three, but not live-network comparisons. Tests against real Unbound / dnsmasq / AdGuard Home instances are also still to do.
