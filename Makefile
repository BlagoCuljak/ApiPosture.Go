.PHONY: build test lint clean install run-sample

# Build variables
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X github.com/BlagoCuljak/ApiPosture.Go/pkg/version.Version=$(VERSION) -X github.com/BlagoCuljak/ApiPosture.Go/pkg/version.Commit=$(COMMIT) -X github.com/BlagoCuljak/ApiPosture.Go/pkg/version.BuildDate=$(BUILD_DATE)"

# Default target
all: build

# Build the binary
build:
	go build $(LDFLAGS) -o bin/apiposture ./cmd/apiposture

# Install globally
install:
	go install $(LDFLAGS) ./cmd/apiposture

# Run tests
test:
	go test -v -race ./...

# Run tests with coverage
test-cover:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
	golangci-lint run

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run against sample Gin app
run-sample-gin:
	go run ./cmd/apiposture scan ./samples/gin_app

# Run against sample Echo app
run-sample-echo:
	go run ./cmd/apiposture scan ./samples/echo_app

# Run with JSON output
run-json:
	go run ./cmd/apiposture scan ./samples/gin_app --output json

# Run with markdown output
run-markdown:
	go run ./cmd/apiposture scan ./samples/gin_app --output markdown

# Download dependencies
deps:
	go mod download
	go mod tidy

# Generate mocks (if using mockery)
mocks:
	mockery --all --dir=internal --output=internal/mocks

# Check for outdated dependencies
outdated:
	go list -u -m all

# Format code
fmt:
	gofmt -s -w .
	goimports -w .

# Verify module
verify:
	go mod verify

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  install       - Install globally"
	@echo "  test          - Run tests"
	@echo "  test-cover    - Run tests with coverage"
	@echo "  lint          - Run linter"
	@echo "  clean         - Clean build artifacts"
	@echo "  run-sample-gin   - Run against sample Gin app"
	@echo "  run-sample-echo  - Run against sample Echo app"
	@echo "  run-json      - Run with JSON output"
	@echo "  run-markdown  - Run with markdown output"
	@echo "  deps          - Download and tidy dependencies"
	@echo "  fmt           - Format code"
