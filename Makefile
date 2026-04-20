# Garmr Makefile

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build build-server build-cli test lint clean docker help \
	test-storage test-minio-start test-minio-stop test-s3-integration

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
	cue vet ./examples/...

cue-export: ## Export CUE schemas to JSON
	cue export ./schemas/policy.cue --out json > schemas/policy.schema.json

## Test targets

test: ## Run tests (excludes plugins)
	go test -v -race -cover $$(go list ./... | grep -v '/plugins/')

test-all: ## Run all tests including plugins
	go test -v -race -cover ./...

test-cover: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out $$(go list ./... | grep -v '/plugins/')
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration: build ## Run integration tests
	./scripts/integration-test.sh

test-storage: ## Run storage backend unit tests
	go test -v -race ./internal/storage/...

test-minio-start: ## Start MinIO for integration testing (podman)
	podman play kube test/integration/minio-pod.yaml
	@echo "Waiting for MinIO..."
	@for i in $$(seq 1 30); do curl -sf http://localhost:9000/minio/health/live > /dev/null 2>&1 && echo "MinIO is ready" && break; sleep 1; done

test-minio-stop: ## Stop MinIO pod
	podman play kube --down test/integration/minio-pod.yaml

test-s3-integration: test-minio-start build ## Run S3 integration tests
	go test -v -tags integration -timeout 120s ./test/integration/...
	$(MAKE) test-minio-stop

bench: ## Run benchmarks
	go test -bench=. -benchmem ./internal/engine/...

## Plugin targets

build-plugins: ## Build all plugins
	@echo "Building plugins..."
	@mkdir -p bin/plugins
	go build -buildmode=plugin -o bin/plugins/kafka.so ./internal/experimental/plugins/kafka
	go build -buildmode=plugin -o bin/plugins/otel.so ./internal/experimental/plugins/otel
	go build -buildmode=plugin -o bin/plugins/prometheus.so ./internal/experimental/plugins/prometheus

## Lint and format

lint: ## Run linters
	golangci-lint run ./...
	cue vet ./...

fmt: ## Format code
	go fmt ./...
	cue fmt ./...

## Development

run: build ## Run server with config.yaml
	@mkdir -p /tmp/garmr-audit
	./bin/garmr-server --config garmr-server.config.yaml

dev: build ## Run server in development mode (no config file)
	@mkdir -p /tmp/garmr-audit
	./bin/garmr-server --dev --policy-dir ./examples --audit-path /tmp/garmr-audit/audit.log --log-format console

run-server: build-server ## Run the server with example config
	./bin/garmr-server --config config.example.yaml

## Docker

docker-build: ## Build Docker image
	docker build -t garmr:$(VERSION) .

docker-push: docker-build ## Push Docker image
	docker push garmr:$(VERSION)

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