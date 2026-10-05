# Garmr Makefile

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build build-server build-cli test test-load lint fmt-check clean docker help bench-e2e \
	test-storage doc-dev

all: build

## Build targets

build: build-server build-cli ## Build all binaries

build-server: ## Build the Garmr server
	@echo "Building garmr-server..."
	go build $(LDFLAGS) -o bin/garmr-server ./cmd/garmr-server

build-cli: ## Build the Garmr CLI
	@echo "Building garmr..."
	go build $(LDFLAGS) -o bin/garmr ./cmd/garmr

build-linux: ## Build for Linux (for containers)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/garmr-server-linux ./cmd/garmr-server
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/garmr-linux ./cmd/garmr

## CUE targets

cue-fmt: ## Format CUE files
	cue fmt ./...

cue-vet: ## Validate CUE files
	cue vet ./schemas/...

cue-export: ## Export CUE schemas to JSON
	cue export ./schemas/policy.cue --out json > schemas/policy.schema.json

## Test targets

# -short skips the load tests; they are slow under -race and belong in
# `make test-load`, not on the `release` path.
test: ## Run unit tests (skips load tests; see test-load)
	go test -short -v -race -cover ./...

test-load: ## Run the load tests (slow: sustained RPS under -race)
	go test -v -race -run 'TestLoadTest' ./internal/server/...

test-cover: ## Run tests with coverage report
	go test -short -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

check-coverage: ## Enforce coverage floor on CLI↔server integration surface
	./scripts/check-coverage.sh

test-storage: ## Run storage backend unit tests
	go test -v -race ./internal/storage/...

bench: ## Run benchmarks
	go test -bench=. -benchmem ./internal/engine/...

bench-e2e: ## Benchmark garmr-server vs OPA end to end over HTTP (~40 min; ARGS=-quick for a smoke run)
	./scripts/bench-e2e/run.sh $(ARGS)

## Lint and format

lint: fmt-check ## Run linters
	golangci-lint run ./...
	cue vet ./schemas/...

fmt-check: ## Verify Go and CUE formatting without rewriting files
	@out="$$($$(go env GOROOT)/bin/gofmt -l ./cmd ./internal)"; \
		if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	cue fmt --check ./schemas/... ./example-policies/...

fmt: ## Format code
	go fmt ./...
	cue fmt ./...

## Development

run: dev ## Alias of dev: run the server locally against the example policies

dev: build ## Run server in development mode (no config file)
	@mkdir -p /tmp/garmr-audit
	./bin/garmr-server --dev --policy-dir ./example-policies --audit-path /tmp/garmr-audit/audit.log --log-format console

run-server: build-server ## Run the server with example config (local policy and audit paths)
	./bin/garmr-server --config config.example.yaml --policy-dir ./example-policies --audit-path stdout

## Docs

doc-dev: ## Run the Astro documentation site locally (bun)
	cd docs && bun install && bun --bun run dev

## Docker

docker-build: ## Build container image (host platform)
	docker build -f Containerfile -t garmr:$(VERSION) .

docker-push: docker-build ## Push Docker image
	docker push garmr:$(VERSION)

# Multi-arch release image. Requires `docker buildx` with a qemu-enabled
# builder already configured (`docker buildx create --use --name garmr-builder`).
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64
DOCKER_REGISTRY  ?= ghcr.io/infrashift
DOCKER_IMAGE     ?= $(DOCKER_REGISTRY)/garmr

docker-buildx: ## Build multi-arch image without pushing (local tar only)
	docker buildx build \
		--file Containerfile \
		--platform $(DOCKER_PLATFORMS) \
		--tag $(DOCKER_IMAGE):$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--output type=oci,dest=dist/garmr-$(VERSION)-oci.tar \
		.

docker-release: ## Build and push multi-arch image to $(DOCKER_IMAGE)
	docker buildx build \
		--file Containerfile \
		--platform $(DOCKER_PLATFORMS) \
		--tag $(DOCKER_IMAGE):$(VERSION) \
		--tag $(DOCKER_IMAGE):latest \
		--build-arg VERSION=$(VERSION) \
		--push \
		.

## Install

install: build ## Install binaries to GOPATH/bin
	cp bin/garmr $(GOPATH)/bin/
	cp bin/garmr-server $(GOPATH)/bin/

install-cli: build-cli ## Install CLI only
	cp bin/garmr $(GOPATH)/bin/

## Clean

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f schemas/*.schema.json

## Release

release: clean test lint build-linux ## Prepare release artifacts
	mkdir -p dist
	tar -czf dist/garmr-$(VERSION)-linux-amd64.tar.gz \
		-C bin garmr-server-linux garmr-linux \
		-C .. config.example.yaml README.md
	sha256sum dist/*.tar.gz > dist/checksums.txt

## Help

help: ## Show this help
	@echo "Garmr Policy Agent - CUE-based Policy Evaluation"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'