# Test Strategy: gorev

This document defines the quality assurance and automation strategy for `gorev`.

## 1. Testing Pyramid

We follow a structured testing pyramid to ensure fast feedback and high confidence.

### Unit Tests
- **Scope**: Individual functions and packages (`internal/parser`, `internal/database`).
- **Goal**: 80%+ code coverage for business logic.
- **Execution**: `go test -v ./internal/...`

### Integration Tests
- **Scope**: Interaction between components and external services (Redis).
- **Goal**: Validate data flow and cache management.
- **Execution**: `go test -v -tags integration ./...` (requires Redis).

### End-to-End (E2E) Tests
- **Scope**: Full system behavior via Docker and `openssl`.
- **Goal**: Zero-regression for real-world client requests (OCSP/CRL).
- **Execution**: `bash scripts/test_e2e.sh`

### Performance & Stress Tests
- **Scope**: System behavior under heavy load (1M+ CRL entries).
- **Goal**: Ensure latency targets are met for signed response generation.
- **Execution**: `go test -v -tags integration -run TestLargeCRL ./...`

## 2. Quality Gates

### Static Analysis
- **Tool**: `golangci-lint`
- **Config**: `.golangci.yml`
- **Policy**: All PRs must pass linting without errors.

### Security Scanning
- **Tool**: `govulncheck`
- **Policy**: No known vulnerabilities in dependencies.

### Resilience (Fuzzing)
- **Scope**: `internal/parser` (PEM/DER decoding).
- **Goal**: Prevent panics on malformed or malicious inputs.
- **Execution**: `go test -fuzz FuzzLoadCRL ./internal/parser`

## 3. Automation Workflow

1. **Local Development**: Run unit tests and linting before pushing.
2. **CI**: Automated execution of unit, integration (with Redis sidecar), and linting.
3. **Release**: Full E2E and Stress test execution for every release candidate.
