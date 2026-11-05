VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS  = -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)
BINARY   = epack-collector-bitdefender
EPACK_VERSION = $(shell go list -m -f '{{.Version}}' github.com/locktivity/epack)

.PHONY: build test lint clean build-all trace-map

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/epack-collector-bitdefender

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

# Rewrites docs/schema/trace-map.json from the collectortest suite and the
# source. It uses the epack version go.mod pins, as CI does.
trace-map:
	go run -tags components github.com/locktivity/epack/cmd/epack@$(EPACK_VERSION) sdk map

build-all:
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-amd64  ./cmd/epack-collector-bitdefender
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-arm64  ./cmd/epack-collector-bitdefender
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-amd64 ./cmd/epack-collector-bitdefender
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-arm64 ./cmd/epack-collector-bitdefender

clean:
	rm -f $(BINARY)
	rm -rf dist/
