# rev-responder

`rev-responder` is a custom Go-based webserver designed to act as both a **Certificate Revocation List (CRL) endpoint** and an **Online Certificate Status Protocol (OCSP) responder**. It uses **Redis** as a fast, in-memory backend database to store and query the revocation status of certificates.

## Architecture
- **Language**: Go
- **Database**: Redis
- **Endpoints**:
  - `GET /CRL/<filename>`: Serves static CRLs.
  - `GET /ocsp/<base64req>`: Responds to HTTP GET OCSP requests.
  - `POST /ocsp`: Responds to HTTP POST OCSP requests.

The application uses an asynchronous file watcher (`fsnotify`) to scan the `DATA_DIR` directory for updates in three explicit subdirectories (`cas/`, `crls/`, `responders/`) in real-time, and updates the in-memory CAs/responders and Redis immediately. 
It supports multiple CAs and multiple Responder certificates intuitively pairing `.pem` responder certificates to their private keys via public key matching. PFX files are not supported to prevent static password hardcoding.

## Getting Started

### Local Build and Testing
Requires Go 1.22+.

1. Run `go mod tidy` to download dependencies.
2. Run `go build -o rev-responder ./...` to build the binary.
3. You can execute `./rev-responder` directly, but it requires a running instance of Redis.

### Docker Deployment
The quickest way to deploy the responder and its required Redis instance is via Docker Compose.
Certificates should be placed in the `data/` directory (`data/cas/`, `data/crls/`, `data/responders/`), which is mounted automatically using `docker-compose.yml` for production usage.

If you are running the automated E2E tests, `docker-compose.test.yml` will mount the generated `test-data/` directory instead to isolate test artifacts.

```bash
docker-compose up -d --build
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
An automated end-to-end testing suite is included in the `scripts/` directory:
- `generate_pki.sh`: Completely scaffolds out multi-tier Certificate Authorities, issue valid/revoked end entities, and generates CRL and OCSP responder credentials in a new `test-data/` folder.
- `test_e2e.sh`: Wraps the PKI generation, spins up the docker environment natively evaluating the `test-data/` artifacts, and executes client assertions using openssl to test positive/negative status code paths.

## Agentic Development
For detailed project context and agent instructions, see `.agent/project-context.md`. Follow [Effective Go](https://go.dev/doc/effective_go) for all code modifications.
