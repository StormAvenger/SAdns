# Contributing to SAdns

Thanks for helping! The most valuable contributions are **reports where SAdns got a diagnosis wrong** — that is how the rules improve.

## Reporting a misdiagnosis

1. Run `sadns run --privacy public` (or use **Public-safe** in the UI) and attach the `.json` report.
2. Describe what is actually wrong (or right) with your network and which finding disagreed.
3. Include your router/resolver (UniFi, Pi-hole, OpenWrt, ISP box…) and OS.

## Development

```bash
make test        # unit + mock-resolver integration tests
go test -race ./...
make mock        # local mock resolvers for offline UI/report work
go run ./cmd/sadns ui
```

Ground rules:

- **No third-party Go modules.** Everything uses the standard library; this keeps the binary auditable.
- **Every new check needs a mock scenario and a test** for both the healthy and the broken case (`internal/mockdns`, `internal/probe/probe_test.go`).
- **Every new finding needs evidence, a fix, and an honest confidence.** If another cause is plausible, say so and use `suspected`. A wrong confident diagnosis is worse than none.
- Untrusted input (DNS, NTP, HTTP, command output) must be bounds-checked and must never panic.
- UI: build DOM with `h()`/text nodes only (never `innerHTML`), no inline `style=""` attributes or new `<script>`/`<style>` blocks (the CSP pins their hashes).
- Run `gofmt` and `go vet`; CI also runs staticcheck and govulncheck.
