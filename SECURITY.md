# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository. I aim to acknowledge reports within a week.

Useful details: affected version (`sadns version`), OS, what an attacker can do, and steps to reproduce.

## Scope

SAdns runs locally and sends network probes. In scope:

- The desktop UI server (`sadns ui`): it must only be reachable from the local machine and only by the page it opened. Bypasses of the loopback restriction, the session token/cookie, the CSRF header check, the Host-header check or the Content-Security-Policy are in scope.
- Server mode (`sadns serve`, Docker): authentication bypass, session fixation/theft, CSRF, Host/Origin check bypass, password-hash weaknesses, brute-force limits, credentials or session tokens leaking into logs, reports or history, and serving without a password on a non-loopback address.
- Stored data: history, settings and the password hash must be private to the user (0700/0600) and survive crashes without corruption; imported reports must not be able to escape the data directory.
- Parsing of untrusted network data (DNS, NTP, HTTP, command output) leading to crashes, hangs or code execution.
- Redaction failures: identifiers that survive the `technical` or `public` privacy levels.
- Supply chain: the release workflow, build provenance and checksums.

Out of scope: the content of third-party DNS answers, and results that are wrong because the network itself lies (report those as normal bugs).

## Verifying downloads

Every release ships `SHA256SUMS.txt` and a GitHub build-provenance attestation:

```bash
gh attestation verify sadns-windows-amd64.exe --repo StormAvenger/SAdns
```

## Security model

| | Desktop (`sadns ui`) | Server (`sadns serve`) |
|---|---|---|
| Listener | Loopback only (enforced) | Any address; no-auth only on loopback |
| Authentication | One-time launch token → HttpOnly SameSite=Strict cookie | Password: PBKDF2-HMAC-SHA256, 600,000 iterations, random salt, only the hash stored (`secrets/auth.json`) or kept in memory (`SADNS_PASSWORD`). No default password: a random one is generated and printed once. |
| Sessions | Per-launch token | Random 256-bit IDs, in memory, 12 h idle / 7 d absolute, max 64 |
| CSRF | Token in `X-SAdns-CSRF` | Per-session token in `X-SAdns-CSRF`, plus Origin and `Sec-Fetch-Site` checks |
| DNS rebinding | Host must be loopback | Host must be an IP, `localhost`, the container hostname or in `SADNS_ALLOWED_HOSTS` |
| Brute force | n/a | 5 failures per client per 5 min → 5 min lockout; at most 2 concurrent hash checks |
| Input | JSON bodies ≤ 64 KiB, unknown fields rejected; imports ≤ 16 MiB and schema-checked; scan IDs pattern-checked before any file access | same |
| Headers | Hash-pinned CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, COOP/CORP, `no-store` | same; set `SADNS_SECURE_COOKIES` behind HTTPS |

The API is read-only with respect to the network: diagnostics only send probes, and SAdns never changes
system, router or DNS settings. `/healthz` is unauthenticated and returns only `{"status":"ok"}`.
For internet exposure, put SAdns behind an HTTPS reverse proxy with its own access control (see
[docs/DOCKER.md](docs/DOCKER.md)).
