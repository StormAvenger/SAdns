VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.built=$(DATE)
PLATFORMS := windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/arm

.PHONY: build test vet dist clean mock

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o sadns ./cmd/sadns

test:
	go test ./...

vet:
	go vet ./...

# Start local mock resolvers for offline UI/report work.
mock:
	go run ./tools/mockdns

dist: clean
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/sadns-$$os-$$arch$$ext ./cmd/sadns || exit 1; \
	done
	cd dist && { command -v sha256sum >/dev/null && sha256sum sadns-* || shasum -a 256 sadns-*; } > SHA256SUMS.txt

clean:
	rm -rf dist sadns sadns.exe
