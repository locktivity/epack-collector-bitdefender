VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS  = -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)
BINARY   = epack-collector-bitdefender

.PHONY: build test lint clean build-all

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/epack-collector-bitdefender

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

build-all:
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-amd64  ./cmd/epack-collector-bitdefender
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-arm64  ./cmd/epack-collector-bitdefender
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-amd64 ./cmd/epack-collector-bitdefender
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-arm64 ./cmd/epack-collector-bitdefender

clean:
	rm -f $(BINARY)
	rm -rf dist/
