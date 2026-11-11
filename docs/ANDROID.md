# Android groundwork

No Android app exists yet. This document records the architecture prepared for one, and its limits.

## What is in place

- **Engine separated from UI.** Scanning (`internal/probe`), analysis (`internal/analyze`), reporting
  (`internal/report`), storage (`internal/store`) and orchestration (`internal/service`) have no
  dependency on the web UI. `internal/web` is one client of `internal/service`; the mobile binding is
  another.
- **Versioned report schema.** Reports carry `"schema": "sadns/report/v1"`. `docs/schema/report.schema.json`
  (JSON Schema 2020-12) is generated from the Go types by `tools/schemagen`, and a test fails if it is
  stale. Rule: fields may be added within v1; removing or retyping a field bumps the schema string.
- **A clean API for remote clients.** `/api/v1/*` (scans, progress events via SSE, cancel, history,
  compare, import, trends, schedule) with `api_version` in `/api/v1/info`. A phone app can drive a
  `sadns serve` instance on the LAN with the same password/session/CSRF flow as the browser.
- **An on-device binding.** `mobile/sadnsmobile` exposes a gomobile-compatible API that uses only
  strings, bools, errors and one callback interface: `NewScanner(dir)`, `Start(requestJSON, listener)`,
  `Cancel`, `Running`, `HistoryJSON`, `Report(id, format, privacy)`, `SetPinned`, `Delete`,
  `SetSystemDNS`. It shares request validation with the HTTP API (`service.ConfigFrom`), and is tested.
  So **quick tests can run locally on the phone**, without a server.

## Recommended app stack

Kotlin + Jetpack Compose for the UI. Build the engine with:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
gomobile bind -target=android -androidapi 24 -o sadns.aar ./mobile/sadnsmobile
```

The app supplies what Go cannot read on Android, using platform APIs, as **platform collectors** kept in
the app:

| Data | Android API |
|---|---|
| Active network's DNS servers | `ConnectivityManager.getLinkProperties(network).dnsServers` → `SetSystemDNS` |
| Private DNS (DoT) mode and host | `LinkProperties.isPrivateDnsActive`, `privateDnsServerName` |
| Wi-Fi SSID/RSSI/link speed/frequency | `WifiManager` / `NetworkCapabilities.transportInfo` (location permission for SSID) |
| Cellular vs Wi-Fi vs VPN | `NetworkCapabilities.hasTransport(...)` |
| Gateway / routes | `LinkProperties.routes` |

## Limitations on Android

- No `ping`/`traceroute` for apps on modern Android, and no raw sockets without root. Use TCP-connect
  timing (already used for connectivity) and report ICMP tests as not available.
- `/proc/net/route` and most of `/proc/net` are not readable by apps (Android 10+), so Go's interface
  and gateway discovery is incomplete. The platform collectors above replace it.
- Background work is constrained: scheduled scans must use `WorkManager` (minimum 15-minute periodic
  interval, deferred under Doze), not a Go timer.
- Private DNS (DoT) set system-wide changes what "the OS resolver path" means; the app should record it
  in the report's vantage.
- Battery and data: default to Quick + Low Data Mode on cellular.

## Go (gomobile) vs a Rust core

| | gomobile (Go engine as-is) | Rust shared library |
|---|---|---|
| Code reuse | All of the engine today | Rewrite of probe/analyze/report |
| Binary size | ~8–12 MB per ABI | ~2–4 MB per ABI |
| Interop | Generated Java/Kotlin bindings | UniFFI (Kotlin/Swift) |
| Risk | Low: same code that ships today | High: two engines diverge until the rewrite is complete |

Recommendation: start with gomobile. Revisit Rust only if APK size or a specific capability (e.g. a
QUIC/DoQ stack with tighter control) justifies it, and then for a new component behind the same
JSON contract, not a rewrite. See [LANGUAGE-EVALUATION.md](LANGUAGE-EVALUATION.md).
