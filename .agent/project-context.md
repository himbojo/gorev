# Project Context: gorev

## Overview
`gorev` is a custom Go-based webserver designed to act as both a **Certificate Revocation List (CRL) endpoint** and an **Online Certificate Status Protocol (OCSP) responder**.  
It utilizes **Redis** as a fast, in-memory backend database to store and query the revocation status of certificates.
It is deployed using **Docker** and **Docker Compose**, running the Go responder server and the Redis database in adjacent containers.

## Architecture & Implementation
- **Language**: Go
- **Dependencies**: 
  - `github.com/redis/go-redis/v9` for Redis connectivity.
  - `github.com/fsnotify/fsnotify` for directory watching.
  - `golang.org/x/crypto/ocsp` for OCSP request parsing and response generation.
- **Components**:
  - `main.go`: Application entrypoint. Initializes the Redis client (with optional password auth), server, and background file watcher. Parses files from `DATA_DIR` at startup and registers configurable multi-endpoint HTTP routes for OCSP, CRL, CA, and Chain services. Uses a `multiDirHandler` with symlink-resolved path validation to prevent traversal attacks. CRLs are signature-verified against their issuing CA before loading. Graceful shutdown on SIGTERM/SIGINT via `http.Server.Shutdown`.
  - `internal/database`: Connects to Redis with optional password authentication. Manages sets of revoked certificate serials per CA (`ca:{caName}:revoked`), and actively serves an OCSP response cache. Uses `redis.Set` with TTL (not the deprecated `SetEx`). Cache invalidation uses an atomic Lua script.
  - `internal/parser`: Decodes and parses PEM CA certificates, CRLs (PEM or DER), and PEM responder certificates and keys.
  - `internal/server`: Thread-safe HTTP handlers for OCSP. Strictly matches the issuer from the OCSP request — returns OCSP Unauthorized (RFC 6960) when no matching CA is found (no silent fallbacks). POST body is limited to 64KB via `io.LimitReader`.
  - `internal/watcher`: Background routine using `fsnotify` that watches `DATA_DIR` for file changes with a 2-second debounce to coalesce rapid events into a single reload.
  - `stress_test.go`: Integration test (build tag `integration`) that generates a 1M-entry CRL in-memory, tests the full pipeline, and reports latency metrics. Requires Redis.

## Deployment Details
- **Docker Compose (`docker-compose.yml`)**:
  - `redis`: Uses the `redis:7-alpine` image, persists data to a volume `redis_data`. Port bound to `127.0.0.1` only. Supports optional password authentication via `REDIS_PASSWORD` env var.
  - `responder`: Builds from the local `Dockerfile`, runs as non-root user `gorev` (UID 1001). Mounts the `DATA_DIR` containing `.pem` and `.crl` files as read-only. Runtime base image pinned to `alpine:3.21`.
- **Environment Variables**:
  - `REDIS_ADDR`: DNS/IP and port for the Redis instance (default: `localhost:6379`).
  - `REDIS_PASSWORD`: Optional Redis authentication password (default: empty / no auth).
  - `DATA_DIR`: Directory where certificates and CRLs reside (default: `.`).
  - `ENDPOINTS_OCSP`: Comma-separated OCSP handler paths (default: `/ocsp`).
  - `ENDPOINTS_CRL`: Comma-separated CRL file server paths (default: `/crls`).
  - `ENDPOINTS_CA`: Comma-separated CA certificate file server paths (default: `/cas`).
  - `ENDPOINTS_CHAIN`: Comma-separated CA chain file server paths (default: disabled).
  - Multiple service types can share the same path (e.g., `/`). When overlapping, the server searches each source directory in order and serves the first file match found.

## Known Artifacts/Test Data
The project expects files strictly separated in the data directory.
`data/` is used for the production-like local environment:
- `data/cas/ca.pem`: A CA public certificate.
- `data/crls/Lab-Root-CA.crl`: A sample CRL populated with revoked serials.
- `data/responders/ocsp-1-cert.pem` / `data/responders/ocsp-1-key.pem`: The OCSP responder cert and key in PEM format.

Additionally, test certificates meant for external verification should not be placed in the loader directories. We typically put them in `clients/`:
- `clients/revoked-cert.pem`: A sample revoked certificate.
- `clients/valid-cert.pem`: A sample valid certificate.

`test-data/` is generated natively during the e2e testing lifecycle and mounts to the container dynamically under `docker-compose.test.yml`. Test data topologies currently include 2-tier and 3-tier certificate chains scaffolding multiple responder endpoints.

## Automated Testing
Comprehensive unit tests cover all internal components:
- `internal/parser`: decoding CAs, CRLs, and keys.
- `internal/database`: Redis sets and cache management.
- `internal/watcher`: fsnotify events and debounce.
- `internal/server`: OCSP handling and issuer matching.

Run all tests:
```bash
go test -v ./...
```

An automated end-to-end testing suite is included in the `scripts/` directory:
- `generate_pki.sh`: Scaffolds multi-tier Certificate Authorities, issues valid/revoked end entities, and generates CRL and OCSP responder credentials in the `test-data/` folder.
- `test_e2e.sh`: Wraps the PKI generation, spins up the docker environment natively evaluating the `test-data/` artifacts via a test compose, and executes client assertions using openssl to test positive/negative status code paths.

A stress/integration test is available via Go's testing framework:
```bash
docker compose up -d redis
go test -v -tags integration -run TestLargeCRL -timeout 10m ./...
docker compose down
```
### Resilience & Quality
- **Test Strategy**: Defined in [.agent/test-strategy.md](test-strategy.md), outlining the testing pyramid and quality gates.
- **Static Analysis**: Managed via [.golangci.yml](../.golangci.yml) with `golangci-lint`.
- **Fuzzing**: Native Go fuzzing implemented in `internal/parser/parser_fuzz_test.go` to ensure parser resilience against malformed DER/PEM data.

This generates a 1M-entry CRL in-memory, tests the full parse → Redis → OCSP pipeline, and reports latency metrics. It is guarded by the `integration` build tag.

## Status
- Core logic for Redis integration, file watching, and OCSP response generation is production-ready.
- Strict security controls (path validation, CRL signature verification) are enforced.
- Performance scaling verified with 1M-entry CRL stress testi ng.
- AI Agent roles updated to prioritize cryptographic integrity and system concurrency.

## Delivery Status
- **Current Version**: `v1.0.0-beta` 
- **Build Status**: Passing (Unit, E2E, Integration).
- **Documentation**: Technical retrospective completed for v1.0.0-beta. Roadmap refined.

## Roadmap
- [x] **v1.0.0 (MVP)**: Multi-CA support, Redis caching, async file watching, E2E test suite.
- [ ] **v1.1.0**: Performance optimizations and detailed caching metrics.

## Agent Roles
Specialized AI agent roles (Developer, Tester, DevOps, Security) are defined in [roles.md](roles.md). Agents should assume these roles as appropriate to apply specific domain expertise.

## Development Guidelines
- All Go code must follow [Effective Go](https://go.dev/doc/effective_go) principles, including proper formatting, idiomatic naming, and simplified control structures.
- **MANDATORY TESTING RULE:** After *every* code change, you MUST run the full verification suite before considering the work complete:
  1. `go build -o /dev/null ./...` — ensure the project compiles
  2. `go vet ./...` — run the Go static analyser
  3. `bash scripts/test_e2e.sh` — run the end-to-end test suite (requires Docker)
  4. `go test -v -tags integration -run TestLargeCRL -timeout 10m ./...` — run the stress/integration test (requires Redis)
- **MANDATORY SECURITY RULE:** When coding or performing security reviews, the following resources MUST be referenced at minimum:
  - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
  - [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
  - [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
  - [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/projects/ssdf)
  - [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
  - [OWASP Secure Coding Practices Checklist](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
  - [MITRE CWE/SANS Top 25](https://www.sans.org/top25-software-errors/)
