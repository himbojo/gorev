# PKI Strategy: gorev

## Overview
`gorev` serves as a critical infrastructure component providing revocation status via OCSP and CRL. The PKI strategy ensures high availability, cryptographic integrity, and strict adherence to industry standards (RFC 5280, RFC 6960).

## Trust Model
- **Trust Anchors**: Root CAs loaded from the configured `DATA_DIR/cas`.
- **Delegated Responders**: Support for OCSP responders with the `OCSPSigning` extended key usage, issued by the same CA as the certificates they are providing status for.
- **Identity Matching**: OCSP requests are matched against issuers based on Subject Public Key Info (SPKI) hashes (SHA-1/SHA-256) as per RFC 6960.

## Cryptographic Standards
### Supported Algorithms
- **Hashes**: SHA-1 (legacy support), SHA-256 (recommended).
- **Public Keys**: RSA (2048+), ECDSA (P-256, P-384), Ed25519.
- **Revocation Lists**: X.509 v2 CRLs (PEM or DER).

### Signature Verification
- **CRL Integrity**: Mandatory signature verification against the issuing CA before ingestion into Redis.
- **OCSP Responses**: Signed by a delegated responder or the CA itself.

## Data Lifecycle Management
### Revocation Ingestion
1. **Discovery**: `fsnotify` detects new or updated `.crl` files in `DATA_DIR/crls`.
2. **Validation**: Parser verifies the CRL signature and validity period.
3. **Synchronization**: Revoked serial numbers are loaded into Redis Sets (`ca:{caName}:revoked`).
4. **Cache Invalidation**: Atomic flush of the OCSP response cache upon any PKI reload to prevent stale "Good" responses for newly revoked certificates.

### OCSP Response Caching
- Generated OCSP responses are cached in Redis with a TTL derived from the `NextUpdate` field.
- Prevents redundant cryptographic signing operations for high-frequency requests.

## Roadmap & Future Enhancements
- **HSM Integration**: Support for hardware-backed signing of OCSP responses.
- **Deterministic Latency**: Further optimization of Redis Lua scripts for massive CRL sets.
- **AIA Support**: Serving Authority Information Access (AIA) pointers.
- **Metrics**: Detailed Prometheus metrics for OCSP request types, issuer matching success, and cryptographic performance.
