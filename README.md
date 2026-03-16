# gorev

`gorev` is a custom Go-based webserver designed to act as both a **Certificate Revocation List (CRL) endpoint** and an **Online Certificate Status Protocol (OCSP) responder**. It uses **Redis** as a fast, in-memory backend database to store and query the revocation status of certificates.

[![Build Status](https://img.shields.io/badge/status-ready-success.svg)](https://github.com/himbojo/gorev)
[![Go Version](https://img.shields.io/badge/go-1.26.1+-blue.svg)](go.mod)

## Architecture
- **Language**: Go
- **Database**: Redis
- **Components**:
  - `main.go`: Application entrypoint. Initializes configuration and application state.
  - `app.go`: Encapsulates core application logic, certificate reload orchestrations, and HTTP route binding.
  - `config.go`: Centralized parsing of environment variables.
- **Default Endpoints**:
  - `GET /crls/<filename>`: Serves static CRLs.
  - `GET /cas/<filename>`: Serves CA certificates.
  - `GET /ocsp/<base64req>`: Responds to HTTP GET OCSP requests.
  - `POST /ocsp`: Responds to HTTP POST OCSP requests.

All endpoints are fully configurable via environment variables (see below).

The application uses an asynchronous file watcher (`fsnotify`) with a 2-second debounce to scan the `DATA_DIR` directory for updates in three explicit subdirectories (`cas/`, `crls/`, `responders/`) in real-time, and updates the in-memory CAs/responders and Redis.
It supports multiple CAs and multiple Responder certificates intuitively pairing `.pem` responder certificates to their private keys via public key matching. CRLs are **signature-verified** against their issuing CA before revocations are loaded. PFX files are not supported to prevent static password hardcoding.

Pre-signed OCSP responses are automatically **cached in Redis** upon generation. Successive identical requests map directly to the cache, bypassing expensive cryptographic operations entirely. The cache is atomically flushed before any PKI reload. The server supports **graceful shutdown** on SIGTERM/SIGINT.

## Endpoint Configuration
Each service type can be served on **multiple URL paths** using comma-separated environment variables:

| Variable | Default | Serves |
|---|---|---|
| `ENDPOINTS_OCSP` | `/ocsp` | OCSP handler (POST + GET) |
| `ENDPOINTS_CRL` | `/crls` | Files from `DATA_DIR/crls/` |
| `ENDPOINTS_CA` | `/cas` | Files from `DATA_DIR/cas/` |
| `ENDPOINTS_CHAIN` | *(disabled)* | Files from `DATA_DIR/cas/` on separate paths |
| `REDIS_PASSWORD` | *(empty)* | Optional Redis authentication password |

**Example:** To serve CRLs on both `/` and `/CRL`, and OCSP on `/ocsp` and `/responder`:
```yaml
environment:
  - ENDPOINTS_CRL=/,/CRL
  - ENDPOINTS_OCSP=/ocsp,/responder
  - ENDPOINTS_CA=/cas,/CA
  - ENDPOINTS_CHAIN=/chain,/chains
```

Multiple service types can share the same path (e.g., `/`). When paths overlap, the server searches each source directory in order and serves the first file match found.

## Data Directory
The `gorev` server dynamically loads the Public Key Infrastructure (PKI) based on the contents of the `DATA_DIR` (which defaults to `.` locally, but `/data` in the provided Docker images).
For the responder to function properly, the following subdirectory structure is required (e.g. within `/data` for Docker):
- `cas/`: Place Certificate Authority certificates here (e.g., `/data/cas/`). Ensure that missing CAs are placed here otherwise signature validation will fail for CRLs. Supported formats: `.pem`, `.crt`, `.cer`, `.der`.
- `crls/`: Place Certificate Revocation Lists here (e.g., `/data/crls/`). Supported formats: `.crl`.
- `responders/`: Place dedicated OCSP responder certificates and their matching private keys here (e.g., `/data/responders/`). Supported formats: `.pem`, `.crt`, `.cer`, `.der` for certs and `.pem`, `.key`, `.der` for keys.

## Getting Started

### Local Build and Testing
Requires Go 1.26.1+.

1. Run `go mod tidy` to download dependencies.
2. Run `go build -o gorev ./...` to build the binary.
3. You can execute `./gorev` directly, but it requires a running instance of Redis.

### Docker Deployment
The quickest way to deploy the responder and its required Redis instance is via Docker Compose.
Certificates should be placed in the `data/` directory (`data/cas/`, `data/crls/`, `data/responders/`), which is mounted automatically using `docker-compose.yml` for production usage.

If you are running the automated E2E tests, `docker-compose.test.yml` will mount the generated `test-data/` directory instead to isolate test artifacts.

```bash
docker compose up -d --build
```

### Usage
Once the responder is running (e.g. on localhost:8080), you can test the endpoints using openSSL:

**CRL Fetching**
```bash
curl -s http://localhost:8080/crls/Lab-Root-CA.crl | openssl crl -inform DER -text -noout
```

**OCSP Request**
```bash
openssl ocsp -CAfile data/cas/ca.pem -issuer data/cas/ca.pem -cert data/clients/valid-cert.pem -url http://localhost:8080/ocsp -VAfile data/responders/ocsp-1-cert.pem
```

### Corporate Proxy Cabundle
If deploying or using `gorev` behind a corporate proxy, you may need to update your client or system cabundle to trust the internal infrastructure. 
Use a **chain file** containing all the individual CAs concatenated together. This aggregate file contains all the necessary root and intermediate CAs required to be added to the trust store, which can be configured within your proxy or provided to your client tools (like via the `-CAfile` argument in `openssl`).

For Alpine-based Docker images (like the default `Dockerfile` provided), you can install a custom cabundle by copying it into `/usr/local/share/ca-certificates/` and running `update-ca-certificates`:

```dockerfile
# Example snippet for appending to a Dockerfile
USER root
COPY corporate-chain.crt /usr/local/share/ca-certificates/corporate-chain.crt
RUN update-ca-certificates
USER gorev
```

## Automated Testing

### Unit Tests
Comprehensive unit tests have been added for all internal components (`parser`, `database`, `server`, `watcher`).
- `internal/parser`: Validates PEM/DER decoding for certificates, CRLs, and private keys.
- `internal/database`: Verifies Redis interactions (revocation sets and OCSP response cache). Requires Redis.
- `internal/watcher`: Tests file system monitoring and the 2-second debounce logic.
- `internal/server`: Validates OCSP request processing (POST/GET), responder matching, and response generation.

Run unit tests:
```bash
go test -v ./internal/...
```

### E2E Tests
An automated end-to-end testing suite is included in the `scripts/` directory:
- `generate_pki.sh`: Completely scaffolds out multi-tier Certificate Authorities, issue valid/revoked end entities, and generates CRL and OCSP responder credentials in a new `test-data/` folder.
- `test_e2e.sh`: Wraps the PKI generation, spins up the docker environment natively evaluating the `test-data/` artifacts, and executes client assertions using openssl to test positive/negative status code paths.

### Stress / Integration Test
A Go integration test (`stress_test.go`) validates the full pipeline under load with a **1,000,000-entry CRL**. It generates all PKI in-memory (no openssl required), parses the CRL, bulk-loads into Redis, and queries OCSP — reporting latency metrics for each stage.

Requires a running Redis instance on `localhost:6379` (or set `REDIS_ADDR`).

```bash
# Start Redis
docker compose up -d redis

# Run the stress test
go test -v -tags integration -run TestLargeCRL -timeout 10m ./...

# Stop Redis when done
docker compose down
```

The test is guarded by the `integration` build tag so it does not run during normal `go test ./...`.

## Security

`gorev` is built with a security-first mindset:
- **Threat Modeling**: See our initial [Threat Model](.agent/threat-model.md) for details on trust boundaries and mitigations.
- **Supply Chain**: Periodic scanning with `govulncheck`. Dependencies (`x/crypto`, `x/net`) are pinned to recent, hardened versions.
- **Minimal Surface**: Runs as non-root in a minimal Alpine-based container. The build context is optimized via `.dockerignore` to exclude non-essential files.
- **Resource Protection**: Docker deployment includes strict CPU and Memory limits (2GB RAM, 2 CPU) to prevent resource exhaustion attacks.
- **Robustness**: Path resolution in `multiDirHandler` uses mandatory `filepath.EvalSymlinks` and hardened `filepath.Abs` error handling to prevent traversal attacks.

## Agentic Development
For detailed project context and agent instructions, see [.agent/project-context.md](.agent/project-context.md). 
Review the [Technical Retrospective (v1.0.0-beta)](.agent/retrospectives/v1.0.0-beta.md) for architectural insights. 
Follow [Effective Go](https://go.dev/doc/effective_go) for all code modifications.
