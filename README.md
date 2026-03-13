# rev-responder

`rev-responder` is a custom Go-based webserver designed to act as both a **Certificate Revocation List (CRL) endpoint** and an **Online Certificate Status Protocol (OCSP) responder**. It uses **Redis** as a fast, in-memory backend database to store and query the revocation status of certificates.

## Architecture
- **Language**: Go
- **Database**: Redis
- **Endpoints**:
  - `GET /CRL/<filename>`: Serves static CRLs.
  - `GET /ocsp/<base64req>`: Responds to HTTP GET OCSP requests.
  - `POST /ocsp`: Responds to HTTP POST OCSP requests.

The application uses an asynchronous file watcher (`fsnotify`) to scan the `DATA_DIR` directory for updates to `.pem`, `.crl`, and `.pfx` files in real-time, and updates the in-memory CAs/responders and Redis immediately. 
It supports multiple CAs and multiple Responder certificates intuitively pairing `.pem` certificates to their private keys if they match.

## Getting Started

### Local Build and Testing
Requires Go 1.22+.

1. Run `go mod tidy` to download dependencies.
2. Run `go build -o rev-responder ./...` to build the binary.
3. You can execute `./rev-responder` directly, but it requires a running instance of Redis.

### Docker Deployment
The quickest way to deploy the responder and its required Redis instance is via Docker Compose.
Sample certificates are provided in the `examples/` directory and are mounted automatically using `docker-compose.yml` for basic production/example usage.

If you are running the automated E2E tests, `docker-compose.test.yml` will mount the generated `test-data/` directory instead to isolate test artifacts.

```bash
docker-compose up -d --build
```

### Usage
Once the responder is running (e.g. on localhost:8080), you can test the endpoints using openSSL:

**CRL Fetching**
```bash
curl -s http://localhost:8080/CRL/Lab-Root-CA.crl | openssl crl -inform DER -text -noout
```

**OCSP Request**
```bash
openssl ocsp -CAfile examples/ca.pem -issuer examples/ca.pem -cert examples/valid-cert.pem -url http://localhost:8080/ocsp -VAfile examples/ocsp-1-cert.pem
```

## Agentic Development
For detailed project context and agent instructions, see `.agent/project-context.md`. Follow [Effective Go](https://go.dev/doc/effective_go) for all code modifications.
