# SAdns container image. Multi-stage, multi-arch (linux/amd64, linux/arm64):
#   docker buildx build --platform linux/amd64,linux/arm64 -t sadns .
# The Go build runs on the build machine's native platform and cross-compiles
# (no emulation needed); only the small runtime stage is per-architecture.
#
# Default command: `sadns serve` (dashboard, Auto Run, history) on :8053.
# One-shot:        docker run --rm -v sadns-data:/data sadns run --save --out /data/reports

ARG GO_IMAGE=golang:1-alpine
ARG RUNTIME_IMAGE=alpine:3

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG BUILT=unknown
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.built=${BUILT}" \
    -o /out/sadns ./cmd/sadns

FROM ${RUNTIME_IMAGE}
# Diagnostic tools SAdns calls: ping/tracepath (iputils), ip (iproute2),
# traceroute (busybox). ca-certificates for DoH/HTTPS tests, tzdata so TZ works.
RUN apk add --no-cache ca-certificates tzdata iputils iproute2 \
 && addgroup -S -g 10001 sadns \
 && adduser -S -D -H -u 10001 -G sadns -h /data sadns \
 && mkdir -p /data && chown sadns:sadns /data && chmod 0700 /data
COPY --from=build /out/sadns /usr/local/bin/sadns
ENV SADNS_DATA_DIR=/data \
    SADNS_LISTEN=:8053 \
    SADNS_IN_CONTAINER=1
VOLUME ["/data"]
EXPOSE 8053
USER 10001:10001
WORKDIR /data
# Liveness only: /healthz reveals nothing and needs no password.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["sadns", "healthcheck"]
# SIGTERM (docker stop) cancels a running scan, saves its partial results and exits.
STOPSIGNAL SIGTERM
ENTRYPOINT ["sadns"]
CMD ["serve"]

LABEL org.opencontainers.image.title="SAdns" \
      org.opencontainers.image.description="DNS & network diagnostics with a password-protected dashboard, scheduled scans and AI-ready reports" \
      org.opencontainers.image.source="https://github.com/StormAvenger/SAdns" \
      org.opencontainers.image.licenses="MIT"
