# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository. I aim to acknowledge reports within a week.

Useful details: affected version (`sadns version`), OS, what an attacker can do, and steps to reproduce.

## Scope

SAdns runs locally and sends network probes. In scope:

- The browser UI server (`sadns ui`): it must only be reachable from the local machine and only by the page it opened. Bypasses of the loopback restriction, the session token/cookie, the CSRF header check, the Host-header check or the Content-Security-Policy are in scope.
- Parsing of untrusted network data (DNS, NTP, HTTP, command output) leading to crashes, hangs or code execution.
- Redaction failures: identifiers that survive the `technical` or `public` privacy levels.
- Supply chain: the release workflow, build provenance and checksums.

Out of scope: the content of third-party DNS answers, and results that are wrong because the network itself lies (report those as normal bugs).

## Verifying downloads

Every release ships `SHA256SUMS.txt` and a GitHub build-provenance attestation:

```bash
gh attestation verify sadns-windows-amd64.exe --repo StormAvenger/SAdns
```
