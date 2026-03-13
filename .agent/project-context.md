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
  - `main.go`: Application entrypoint. Initializes the Redis client, server, and background file watcher. Parses files from `DATA_DIR` at startup and registers configurable multi-endpoint HTTP routes for OCSP, CRL, CA, and Chain services. Uses a `multiDirHandler` to merge overlapping file-serving paths so multiple service types can share the same URL prefix. All startup logging uses `log.Printf` for consistent timestamped output.
  - `internal/database`: Connects to Redis. Manages sets of revoked certificate serials per CA (`ca:{caName}:revoked`), and actively serves an occlusion cache for signed OCSP responses natively. Uses `redis.Set` with TTL (not the deprecated `SetEx`).
  - `internal/parser`: Decodes and parses PEM CA certificates, CRLs (PEM or DER), and PEM responder certificates and keys.
  - `internal/server`: Thread-safe HTTP handlers for OCSP. Identifies the issuer from the OCSP request, evaluates it against the database occlusion cache to rapidly return pre-signed hits, or generates dynamic responses signed by the responder key natively, while inserting them into the cache. POST body is limited to 64KB via `io.LimitReader` for safety.
  - `internal/watcher`: Background routine using `fsnotify` that watches `DATA_DIR` for file additions/deletions/modifications and triggers a full reload of certificates and CRLs while instantly wiping the OCSP occlusion cache safely.
  - `stress_test.go`: Integration test (build tag `integration`) that generates a 1M-entry CRL in-memory, tests the full pipeline, and reports latency metrics. Requires Redis.

## Deployment Details
- **Docker Compose (`docker-compose.yml`)**:
  - `redis`: Uses the `redis:7-alpine` image, persists data to a volume `redis_data`.
  - `responder`: Builds from the local `Dockerfile`. Mounts the `DATA_DIR` containing `.pem`, `.crl`, and `.pfx` files as read-only.
- **Environment Variables**:
  - `REDIS_ADDR`: DNS/IP and port for the Redis instance (default: `localhost:6379`).
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
An automated end-to-end testing suite is included in the `scripts/` directory:
- `generate_pki.sh`: Scaffolds multi-tier Certificate Authorities, issues valid/revoked end entities, and generates CRL and OCSP responder credentials in the `test-data/` folder.
- `test_e2e.sh`: Wraps the PKI generation, spins up the docker environment natively evaluating the `test-data/` artifacts via a test compose, and executes client assertions using openssl to test positive/negative status code paths.

A stress/integration test is available via Go's testing framework:
```bash
docker compose up -d redis
go test -v -tags integration -run TestLargeCRL -timeout 10m ./...
docker compose down
```
This generates a 1M-entry CRL in-memory, tests the full parse → Redis → OCSP pipeline, and reports latency metrics. It is guarded by the `integration` build tag.

## Status
- The codebase logic for Redis integration, file watching, HTTP routing, and OCSP response generation is fully implemented.
- The project successfully compiles and is ready for integration testing and Docker Compose deployment.
- A robust, repeatable Multi-CA E2E testing framework has been scripted and verified. No known bugs exist.
- A `.dockerignore` file excludes the compiled binary, test data, and git history from Docker build context.

## Development Guidelines
- All Go code must follow [Effective Go](https://go.dev/doc/effective_go) principles, including proper formatting, idiomatic naming, and simplified control structures.
- **MANDATORY AGENT RULE:** After *every* iteration of feature development or code modification, you MUST explicitly update the `.gitignore`, `.agent/project-context.md`, and `README.md` to perfectly reflect the current state of the application. Do not leave documentation out of sync.
