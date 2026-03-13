# gorev

`gorev` is a custom Go-based webserver designed to act as both a **Certificate Revocation List (CRL) endpoint** and an **Online Certificate Status Protocol (OCSP) responder**. It uses **Redis** as a fast, in-memory backend database to store and query the revocation status of certificates.

## Architecture
- **Language**: Go
- **Database**: Redis
- **Default Endpoints**:
  - `GET /crls/<filename>`: Serves static CRLs.
  - `GET /cas/<filename>`: Serves CA certificates.
  - `GET /ocsp/<base64req>`: Responds to HTTP GET OCSP requests.
  - `POST /ocsp`: Responds to HTTP POST OCSP requests.

All endpoints are fully configurable via environment variables (see below).

The application uses an asynchronous file watcher (`fsnotify`) to scan the `DATA_DIR` directory for updates in three explicit subdirectories (`cas/`, `crls/`, `responders/`) in real-time, and updates the in-memory CAs/responders and Redis immediately. 
It supports multiple CAs and multiple Responder certificates intuitively pairing `.pem` responder certificates to their private keys via public key matching. PFX files are not supported to prevent static password hardcoding.

Pre-signed OCSP responses are automatically **cached in Redis** upon generation. Successive identical requests map directly to the cache, bypassing expensive cryptographic operations entirely. The cache is safely flushed upon any detection of PKI topology changes via the file watcher.

## Endpoint Configuration
Each service type can be served on **multiple URL paths** using comma-separated environment variables:

| Variable | Default | Serves |
|---|---|---|
| `ENDPOINTS_OCSP` | `/ocsp` | OCSP handler (POST + GET) |
| `ENDPOINTS_CRL` | `/crls` | Files from `DATA_DIR/crls/` |
| `ENDPOINTS_CA` | `/cas` | Files from `DATA_DIR/cas/` |
| `ENDPOINTS_CHAIN` | *(disabled)* | Files from `DATA_DIR/cas/` on separate paths |

**Example:** To serve CRLs on both `/` and `/CRL`, and OCSP on `/ocsp` and `/responder`:
```yaml
environment:
  - ENDPOINTS_CRL=/,/CRL
  - ENDPOINTS_OCSP=/ocsp,/responder
```

Multiple service types can share the same path (e.g., `/`). When paths overlap, the server searches each source directory in order and serves the first file match found.

## Getting Started

### Local Build and Testing
Requires Go 1.22+.

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

## Automated Testing

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

## Agentic Development
For detailed project context and agent instructions, see `.agent/project-context.md`. Follow [Effective Go](https://go.dev/doc/effective_go) for all code modifications.
