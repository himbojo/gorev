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
  - `software.sslmate.com/src/go-pkcs12` for `.pfx` responder certificate parsing.
- **Components**:
  - `main.go`: Application entrypoint. Initializes the Redis client, server, and background file watcher. Parses files from `DATA_DIR` at startup and handles HTTP routing for `/ocsp` and `/CRL`.
  - `internal/database`: Connects to Redis. Manages sets of revoked certificate serial numbers per CA (`ca:{caName}:revoked`).
  - `internal/parser`: Decodes and parses PEM CA certificates, CRLs (PEM or DER), PEM responder certificates and keys, and PFX responder certificates.
  - `internal/server`: Thread-safe HTTP handlers for OCSP. Identifies the issuer from the OCSP request, queries Redis for revocation status, and dynamically generates an OCSP response signed by the responder key.
  - `internal/watcher`: Background routine using `fsnotify` that watches `DATA_DIR` for file additions/deletions/modifications and triggers a full reload of certificates and CRLs.

## Deployment Details
- **Docker Compose (`docker-compose.yml`)**:
  - `redis`: Uses the `redis:7-alpine` image, persists data to a volume `redis_data`.
  - `responder`: Builds from the local `Dockerfile`. Mounts the `DATA_DIR` containing `.pem`, `.crl`, and `.pfx` files as read-only.
- **Environment Variables**:
  - `REDIS_ADDR`: DNS/IP and port for the Redis instance (default: `localhost:6379`).
  - `DATA_DIR`: Directory where certificates and CRLs reside (default: `.`).

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
- `test_e2e.sh`: Wraps the PKI generation, spins up the docker environment nativesly evaluating the `test-data/` artifacts via a test compose, and executes client assertions using openssl to test positive/negative status code paths.

## Status
- The codebase logic for Redis integration, file watching, HTTP routing, and OCSP response generation is fully implemented.
- The project successfully compiles and is ready for integration testing and Docker Compose deployment.
- A robust, repeatable Multi-CA E2E testing framework has been scripted and verified. No known bugs exist.

## Development Guidelines
- All Go code must follow [Effective Go](https://go.dev/doc/effective_go) principles, including proper formatting, idiomatic naming, and simplified control structures.
- **MANDATORY AGENT RULE:** After *every* iteration of feature development or code modification, you MUST explicitly update the `.gitignore`, `.agent/project-context.md`, and `README.md` to perfectly reflect the current state of the application. Do not leave documentation out of sync.
