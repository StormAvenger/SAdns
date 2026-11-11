# Running SAdns in Docker

`sadns serve` is the long-running mode for Docker, Unraid and other always-on hosts. It gives you a
password-protected dashboard, scheduled scans (Auto Run), persistent history and trends. The image is
**not published yet**. You build it yourself; publishing an image needs the repository owner's approval.

## Build

```bash
git clone https://github.com/StormAvenger/SAdns && cd SAdns
docker build -t sadns:local .
# multi-arch (needs buildx; arm64 emulation only for the small runtime stage):
docker buildx build --platform linux/amd64,linux/arm64 -t sadns:local .
```

The image is multi-stage: the Go binary is cross-compiled on the build machine and copied into a small
Alpine runtime with `ping`, `tracepath`, `ip` and CA certificates. It runs as UID/GID **10001**, stores
everything in `/data`, exposes port **8053** and has a `HEALTHCHECK` (`sadns healthcheck`, which calls the
unauthenticated, information-free `/healthz`).

## Run (persistent service)

```bash
docker run -d --name sadns --restart unless-stopped \
  -p 8053:8053 -v sadns-data:/data \
  -e TZ=America/Los_Angeles \
  --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true --read-only --tmpfs /tmp \
  --memory 256m --cpus 1 \
  sadns:local
docker logs sadns      # the generated password is printed here, once
```

Open `http://<docker-host>:8053`. Or use the Compose file in the repository root: put a password in
`sadns_password.txt` and run `docker compose up -d`.

## One-shot (run, save, exit)

```bash
docker run --rm -v sadns-data:/data sadns:local run --save --out /data/reports
# or: docker compose --profile once run --rm sadns-once
```

This writes Markdown and JSON reports to `/data/reports` and adds the scan to the history the dashboard
shows. The exit code is 0 when the scan completed.

## What a container can and cannot measure

SAdns records its **vantage point** in every report (`vantage` in JSON, a row at the top of the Markdown)
and never presents a container's view as the host's.

| Mode | How to run | What the results describe |
|---|---|---|
| **Bridge** (default) | `-p 8053:8053` | The container: its virtual interface, the Docker bridge as "gateway", Docker's DNS settings. Internet, DNS-resolver and website tests are meaningful for the host's uplink through Docker's NAT. Layers are renamed *Container*, *Container network* and *Docker bridge*; a `VANTAGE-CONTAINER` finding and coverage gaps list what cannot be measured; the verdict is never plain "healthy". |
| **Host network** (opt-in) | `--network host -e SADNS_NETWORK_MODE=host` (Linux) | The Docker host's own interfaces, routes and gateway. The container still uses its own `resolv.conf` and libc, so "what host applications experience" can differ, and the report says so. Host networking means the container can reach every port the host can: choose it knowingly. |
| **Other devices** | Run SAdns on the device and use **History → Import report** | Each device's own view, browsable and comparable in one place. Imported scans are excluded from trend lines so vantage points don't mix. |

Not available from inside a bridge-networked container: the host's Wi-Fi/LAN link quality, the host's DNS
configuration, router-specific tests (router DNS, rebind protection, local encrypted DNS, double NAT on
the real LAN), and host interface addresses / IPv6. Detection uses `/.dockerenv`, `/run/.containerenv`,
`/proc/1/cgroup`, the visible interfaces and the default gateway; set `SADNS_NETWORK_MODE` (`bridge`,
`host`, `macvlan`) to be explicit. Privileged mode is never needed. `NET_RAW` is only for ping and
traceroute; drop it and those tests are reported as not run.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `SADNS_PASSWORD` / `SADNS_PASSWORD_FILE` | none | Dashboard password (12+ characters). If neither is set, a random password is generated, printed once in the log, and only its hash is stored. `--reset-password` generates a new one. |
| `SADNS_ALLOWED_HOSTS` | none | Extra host names you type in the browser (`tower.local,sadns.home.arpa`). IP addresses and `localhost` always work; `*` allows any name. |
| `SADNS_SECURE_COOKIES` | `false` | Mark the session cookie Secure; set behind an HTTPS reverse proxy. |
| `SADNS_LISTEN` | `:8053` | Listen address. |
| `SADNS_DATA_DIR` | `/data` | History, settings and the password hash. |
| `SADNS_NETWORK_MODE` | auto | `bridge`, `host`, `macvlan`: vantage hint. |
| `SADNS_SCHEDULE_ENABLED` | UI setting | `true` / `false`; applied at every start. |
| `SADNS_SCHEDULE_INTERVAL` | `60m` | `30m`, `6h`, `1d`; minimum 5 minutes. |
| `SADNS_SCHEDULE_MODE` | `quick` | `quick` or `full`. |
| `SADNS_SCHEDULE_LOW_DATA` | `false` | Low Data Mode for scheduled scans. |
| `SADNS_HISTORY_RETAIN` | `100` | Unpinned scans to keep. |
| `TZ` | UTC | Time zone for logs and schedule display. |

`SADNS_AUTH=none` (or `--no-auth`) disables the password, and is refused unless `SADNS_LISTEN` is a
loopback address.

## Reverse proxy (HTTPS)

SAdns serves plain HTTP. For access beyond your LAN, or to use a name with HTTPS, put it behind a TLS
reverse proxy and set `SADNS_SECURE_COOKIES=true` and `SADNS_ALLOWED_HOSTS=<the public name>`.
Caddy example:

```
sadns.example.net {
    reverse_proxy sadns:8053 {
        flush_interval -1      # live progress uses Server-Sent Events
    }
}
```

nginx: `proxy_pass http://sadns:8053; proxy_http_version 1.1; proxy_buffering off; proxy_set_header Host $host;`.
The proxy must pass the original `Host` header. Login rate limiting is per client IP. Behind a proxy all
clients share the proxy's address, so failed logins from one user can briefly lock out others; prefer
proxy-level authentication or an allow-list if the dashboard is reachable from the internet.

## Unraid

`deploy/unraid/sadns.xml` is a Docker template (example only, since no public image exists yet). Build
the image on the server (`docker build -t sadns:local .` in a clone), copy the template to
`/boot/config/plugins/dockerMan/templates-user/`, and add the container from it. Make the appdata folder
writable by UID 10001: `chown -R 10001:10001 /mnt/user/appdata/sadns`. Switch *Network Type* to `host` to
measure the Unraid server's own network.

## Restart policies, logs, limits

- `--restart unless-stopped` (Compose `restart: unless-stopped`) keeps Auto Run going across reboots.
  The schedule's next-run time is persisted; after downtime **one** catch-up scan runs ~30 s after start,
  never one per missed interval.
- `docker stop` sends SIGTERM: a running scan is cancelled, its partial results are saved, and the
  process exits 0 (well inside Docker's 10 s grace period).
- Logs go to stdout; use the `json-file` driver with `max-size`/`max-file`. Logs never contain the
  password (except the one-time generated one at first start) or session tokens.
- 256 MiB / 1 CPU is plenty: idle RSS is about 8 MiB and a quick scan peaks around 15 MiB.

## CI

`.github/workflows/ci.yml` builds the image for amd64 and arm64 (`--output type=cacheonly`, nothing
pushed) and runs `tools/docker/smoke.sh` against the amd64 image. It checks health, auth, CSRF, the Host
allow-list, non-root UID, a real scan with the container vantage reported, persistence across restart,
graceful stop, the generated-password flow, refusal of no-auth on all interfaces, one-shot mode and host
networking detection.
