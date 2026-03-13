# Product Requirements Document: gorev

## 1. Problem Statement
Managing Certificate Revocation Lists (CRLs) and responding to Online Certificate Status Protocol (OCSP) requests often requires heavy, complex infrastructure. Existing solutions can be difficult to configure, slow to update, and resource-intensive. `gorev` addresses the need for a **lightweight, high-performance, and "configuration-first" responder** that integrates seamlessly with modern containerized environments.

## 2. Product Goals
- **Performance**: Sub-millisecond OCSP response times for cached entries.
- **Simplicity**: Zero-config operation by default, with powerful overrides via environment variables.
- **Reliability**: Real-time updates to revocation status without service interruption using background file watching.
- **Scalability**: Capable of handling millions of revoked certificates via an optimized Redis backend.

## 3. Targeted Personas
- **Platform Engineers**: Deploying and managing PKI components in Kubernetes or Docker.
- **Security Architects**: Designing secure revocation checking for internal or external services.
- **Developers**: Needing a local, easy-to-run responder for testing TLS-enabled applications.

## 4. Functional Requirements
### 4.1 OCSP Responder
- **FR1**: Support HTTP POST requests for OCSP (RFC 6960).
- **FR2**: Support HTTP GET requests (base64 encoded) for OCSP.
- **FR3**: Automatically match issuers from requests to loaded CA certificates.
- **FR4**: Return `unauthorized` status when the issuer is unknown.

### 4.2 CRL Serving
- **FR5**: Serve static CRL files (`.crl`) from a configurable directory.
- **FR6**: Support multiple CRL endpoints and merged path handling.

### 4.3 Data Management
- **FR7**: Automatically reload data when files are added or modified in `DATA_DIR`.
- **FR8**: Verify CRL signatures against their issuing CA before loading revocations.
- **FR9**: Use Redis as an authoritative cache for revocation status and pre-signed OCSP responses.

## 5. Non-Functional Requirements
- **NFR1 - Performance**: Load 1M CRL entries into Redis in under 60 seconds (hardware dependent).
- **NFR2 - Concurrency**: Thread-safe handling of concurrent OCSP requests and background reloads.
- **NFR3 - Security**: Run as a non-root user; use multi-stage builds; strictly validate file paths to prevent traversal.

## 6. Future Roadmap (Internal Focus)
- Performance optimizations and enhanced caching metrics.
- Support for larger CRL sets (>10M) with optimized Redis structures.
