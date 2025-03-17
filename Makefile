# Variables
BINARY_NAME = santa-rule-importer
MAIN_FILE = ./cmd/main.go

# Default target
.PHONY: all
all: deps build

.PHONY: deps
.ONESHELL: deps
deps:
	export GOPRIVATE="buf.build/gen/go,${GOPRIVATE}"
	buf registry login
	go mod download

# Build the binary
.PHONY: build
build:
	go build -o santa-rule-importer cmd/main.go

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)

# Run tests
.PHONY: test
test:
	go test -v ./...

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build           - Build the santa-rule-importer binary"
	@echo "  clean           - Remove build artifacts"
	@echo "  deps            - Build dependencies"
	@echo "  test            - Run tests"
	@echo "  fmt             - Format code"
	@echo "  help            - Show this help message"

.DEFAULT_GOAL := all
