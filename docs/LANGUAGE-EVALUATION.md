# Language evaluation: Go, Rust, C++

The owner prefers Rust/C++ where it makes a real difference. This document evaluates whether SAdns
should move, based on measurements rather than preference. **Conclusion: keep Go for the existing
engine; consider Rust only for specific new components where it is measurably better.**

## What SAdns spends its time on

A scan is **network-bound**: a quick scan takes 10–40 s, almost entirely waiting for DNS timeouts,
TCP/TLS handshakes, ping and HTTP. CPU work is tiny. Benchmarks (`go test -bench . ./internal/dnswire
./internal/report ./internal/store`, 2-vCPU Xeon, Go 1.24):

| Operation | Time | Per scan |
|---|---|---|
| Pack a DNS query (EDNS, DO, NSID) | 0.2 µs | a few hundred queries ≈ 0.1 ms |
| Parse a DNS message | 0.6 µs (71 MB/s) | ≈ 0.3 ms |
| Render the Markdown report | 0.36 ms | once |
| Render JSON | 0.53 ms | once |
| Public-level redaction of the report | 6.2 ms | once per export |
| Save to history (gzip + fsync + index) | 6.8 ms | once |
| Load a stored report | 0.08 ms | per view |

Resource use: release binary ≈ 8 MB (static, all platforms from one machine); `sadns serve` idle RSS
≈ 8 MiB; a quick scan peaks at ≈ 15 MiB RSS.

Even a 10× faster CPU path would save **under 10 ms of a 10–40 s scan**. There is no performance case
for a rewrite.

## Comparison

| Concern | Go (current) | Rust | C++ |
|---|---|---|---|
| Static cross-compile to Windows/macOS/Linux, x86+ARM | `GOOS/GOARCH`, no toolchains | Good with `cross`/zig; macOS needs SDK | Toolchain per target |
| Dependencies today | **Zero** (stdlib DNS, TLS, HTTP/2, crypto) | Needs crates for TLS (rustls), HTTP, async (tokio), DNS | Needs OpenSSL/BoringSSL, HTTP, etc. |
| Memory safety | GC, bounds-checked | Compile-time, no GC | Manual; highest risk for a network parser |
| Parsing untrusted network data | Safe; fuzz-tested codec | Safe; excellent | Requires great care |
| Binary size | ~8 MB | ~3–5 MB | ~2–5 MB |
| Mobile | gomobile (works today) | UniFFI, smaller libs | JNI by hand |
| Contributor familiarity / review | High | Medium | Medium |

## Where Rust could be justified later

- A **mobile-first engine** if APK size becomes a problem (see [ANDROID.md](ANDROID.md)).
- **DNS-over-QUIC / HTTP/3** probing, if Go's ecosystem lacks a suitable stdlib-only path and a mature
  Rust stack (quinn) gives better control. It would ship as a separate component behind the existing
  JSON contract.
- A **packet-capture / passive analysis** add-on, where zero-copy parsing at line rate matters.

## Proposal

1. No wholesale rewrite.
2. Keep the engine's contract language-neutral: the versioned JSON schema and `/api/v1`.
3. If a Rust component is added, it gets its own benchmarks against the Go equivalent before it
   replaces anything, and it must not break the single-binary download for desktop users.
