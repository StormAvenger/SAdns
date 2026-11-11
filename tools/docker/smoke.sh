#!/usr/bin/env bash
# Container smoke test. Usage: tools/docker/smoke.sh <image>
# Builds nothing and pushes nothing; it only runs the given local image.
# MINIMAL=1 skips checks that need a shell in the image.
set -euo pipefail
IMG=${1:?image}
PW="smoke-test-password-$RANDOM"
PORT=18053
N=sadns-smoke-$$
VOL=sadns-smoke-vol-$$
pass=0
ok()   { echo "PASS $*"; pass=$((pass+1)); }
fail() { echo "FAIL $*"; docker logs "$N" 2>&1 | tail -40 || true; exit 1; }
cleanup() { docker rm -f "$N" "$N-gen" "$N-host" >/dev/null 2>&1 || true; docker volume rm -f "$VOL" "$VOL-gen" >/dev/null 2>&1 || true; rm -f /tmp/$N.cj; }
trap cleanup EXIT

docker volume create "$VOL" >/dev/null
docker run -d --name "$N" -p 127.0.0.1:$PORT:8053 -v "$VOL:/data" -e SADNS_PASSWORD="$PW" \
  --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true --read-only --tmpfs /tmp "$IMG" >/dev/null

for i in $(seq 1 60); do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$N")
  [ "$st" = healthy ] && break
  [ "$st" = none ] && { curl -fsS http://127.0.0.1:$PORT/healthz >/dev/null 2>&1 && break; }
  sleep 1
done
[ "$st" = healthy ] || [ "$st" = none ] || fail "container never became healthy ($st)"
ok "health check: $st"

[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/healthz)" = 200 ] && ok "/healthz 200 without login" || fail "/healthz"
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/api/v1/info)" = 401 ] && ok "API requires login" || fail "API open without login"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"password":"wrong-password-123"}' http://127.0.0.1:$PORT/api/v1/login)" = 401 ] && ok "wrong password rejected" || fail "wrong password"
curl -fsS -c /tmp/$N.cj -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:$PORT/api/v1/login >/dev/null && ok "login" || fail "login"
INFO=$(curl -fsS -b /tmp/$N.cj http://127.0.0.1:$PORT/api/v1/info)
CSRF=$(echo "$INFO" | python3 -c 'import sys,json;print(json.load(sys.stdin)["csrf"])')
MODE=$(echo "$INFO" | python3 -c 'import sys,json;v=json.load(sys.stdin)["vantage"];print(v["mode"] if v["in_container"] else "host")')
[ "$MODE" = container-bridge ] && ok "vantage detected as $MODE" || fail "vantage $MODE"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' http://127.0.0.1:$PORT/)" = 403 ] && ok "foreign Host rejected" || fail "host check"
[ "$(curl -s -o /dev/null -w '%{http_code}' -b /tmp/$N.cj -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:$PORT/api/v1/scans)" = 403 ] && ok "CSRF required" || fail "csrf"

UID_IN=$(docker inspect -f '{{.Config.User}}' "$N")
[ "${UID_IN%%:*}" = 10001 ] && ok "runs as non-root user $UID_IN" || fail "user $UID_IN"

curl -fsS -b /tmp/$N.cj -H "X-SAdns-CSRF: $CSRF" -H 'Content-Type: application/json' \
  -d '{"quick":true,"low_data":true,"ipv4":true,"ipv6":true,"providers":["cloudflare"],"encrypted":true}' http://127.0.0.1:$PORT/api/v1/scans >/dev/null && ok "scan started" || fail "start scan"
for i in $(seq 1 240); do
  n=$(curl -fsS -b /tmp/$N.cj http://127.0.0.1:$PORT/api/v1/history | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["entries"]))')
  [ "$n" -ge 1 ] && break; sleep 1
done
[ "$n" -ge 1 ] && ok "scan saved to history" || fail "scan did not finish"
MD=$(curl -fsS -b /tmp/$N.cj "http://127.0.0.1:$PORT/api/v1/report?format=md&privacy=public")
echo "$MD" | grep -q "VANTAGE-CONTAINER" && ok "report flags the container vantage" || fail "no vantage finding"
echo "$MD" | grep -q "$PW" && fail "password in report" || ok "no password in report"

docker restart -t 20 "$N" >/dev/null
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:$PORT/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -c /tmp/$N.cj -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:$PORT/api/v1/login >/dev/null
n=$(curl -fsS -b /tmp/$N.cj http://127.0.0.1:$PORT/api/v1/history | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["entries"]))')
[ "$n" -ge 1 ] && ok "history persists across restart" || fail "history lost on restart"

T0=$(date +%s); docker stop -t 20 "$N" >/dev/null; T1=$(date +%s)
CODE=$(docker inspect -f '{{.State.ExitCode}}' "$N")
[ "$CODE" = 0 ] && [ $((T1-T0)) -lt 15 ] && ok "graceful stop in $((T1-T0)) s (exit $CODE)" || fail "stop: exit $CODE after $((T1-T0)) s"

# Generated password: printed once, only a hash kept.
docker volume create "$VOL-gen" >/dev/null
docker run -d --name "$N-gen" -v "$VOL-gen:/data" "$IMG" >/dev/null; sleep 3
docker logs "$N-gen" 2>&1 | grep -q "shown only once" && ok "first start prints a generated password" || fail "no generated password"
docker restart "$N-gen" >/dev/null; sleep 3
[ "$(docker logs "$N-gen" 2>&1 | grep -c 'shown only once')" = 1 ] && ok "password not printed again after restart" || fail "password printed twice"

# No-auth is refused on all interfaces.
if docker run --rm "$IMG" serve --no-auth >/dev/null 2>&1; then fail "no-auth on 0.0.0.0 accepted"; else ok "no-auth refused on non-loopback"; fi

# One-shot mode writes a report and exits.
if [ "${MINIMAL:-0}" != 1 ]; then
  docker run --rm -v "$VOL:/data" "$IMG" run --quick --low-data --providers cloudflare --save --out /data/reports >/dev/null 2>&1 && ok "one-shot run exits 0" || fail "one-shot"
  docker run --rm -v "$VOL:/data" --entrypoint sh "$IMG" -c 'ls /data/reports/*.md >/dev/null && stat -c %a /data/history' | grep -q 700 && ok "one-shot report written; data dir 0700" || fail "one-shot output"
  docker run --rm --entrypoint sh "$IMG" -c 'command -v ping && command -v tracepath && command -v ip' >/dev/null && ok "diagnostic tools present" || fail "tools missing"
fi

# Host networking (informed opt-in) is detected as such.
if [ "$(uname)" = Linux ]; then
  docker run -d --name "$N-host" --network host -e SADNS_LISTEN=127.0.0.1:18054 -e SADNS_PASSWORD="$PW" "$IMG" >/dev/null
  for i in $(seq 1 20); do curl -fsS http://127.0.0.1:18054/healthz >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS -c /tmp/$N.cj -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:18054/api/v1/login >/dev/null
  HM=$(curl -fsS -b /tmp/$N.cj http://127.0.0.1:18054/api/v1/info | python3 -c 'import sys,json;print(json.load(sys.stdin)["vantage"]["mode"])')
  [ "$HM" = container-host-network ] && ok "host networking detected" || fail "host network mode: $HM"
fi
echo "All $pass container checks passed."
