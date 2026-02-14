# Garmr Makefile

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build build-server build-cli test lint proto clean docker help

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

## Proto generation

proto: ## Generate protobuf code
	@echo "Generating protobuf code..."
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=. --grpc-gateway_opt=paths=source_relative \
		api/proto/policy.proto

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

bench: ## Run benchmarks
	go test -bench=. -benchmem ./internal/engine/...

## Plugin targets

build-plugins: ## Build all plugins (requires CGO)
	@echo "Building plugins..."
	@mkdir -p bin/plugins
	go build -buildmode=plugin -o bin/plugins/consul.so ./plugins/consul
	go build -buildmode=plugin -o bin/plugins/s3.so ./plugins/s3
	go build -buildmode=plugin -o bin/plugins/kafka.so ./plugins/kafka
	go build -buildmode=plugin -o bin/plugins/otel.so ./plugins/otel
	go build -buildmode=plugin -o bin/plugins/prometheus.so ./plugins/prometheus
	go build -buildmode=plugin -o bin/plugins/markdown.so ./plugins/markdown
	go build -buildmode=plugin -o bin/plugins/duckdb.so ./plugins/duckdb
	go build -buildmode=plugin -o bin/plugins/logging.so ./plugins/logging
	go build -buildmode=plugin -o bin/plugins/audit-file.so ./plugins/audit-file
	go build -buildmode=plugin -o bin/plugins/consul-authz.so ./plugins/consul-authz
	go build -buildmode=plugin -o bin/plugins/vault-authz.so ./plugins/vault-authz

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