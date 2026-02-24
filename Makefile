.PHONY: build build-static clean run test

BINARY=dev-sshd
VERSION?=1.0.0

# Build flags
LDFLAGS=-ldflags "-s -w"

# Default target
all: build

# Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) .

# Build static binary (CGO_ENABLED=0)
build-static:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) .

# Build for Linux AMD64 (static)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 host_key

# Run the server (for development)
run: build
	SSHD_USERNAME=test SSHD_PASSWORD=test ./$(BINARY)

# Run with no auth (for testing)
run-noauth: build
	./$(BINARY) --auth-mode=none

# Download dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Test (placeholder)
test:
	go test -v ./...
