# PKI Compliance Checklist

This checklist ensures `gorev` remains compliant with standard PKI requirements.

## RFC 5280 (X.509/CRL)
- [x] Supports PEM and DER encoded CRLs.
- [x] Validates CRL signature against issuing CA.
- [ ] (Future) Support for indirect CRLs.
- [x] Handles large CRLs (verified via 1M-entry stress test).

## RFC 6960 (OCSP)
- [x] Supports OCSP via HTTP POST.
- [x] Supports OCSP via HTTP GET (Base64 encoded).
- [x] Strict Issuer Matching: Returns `Unauthorized` if no matching CA is found.
- [x] SPKI Hash Matching: Correctly resolves `IssuerNameHash` and `IssuerKeyHash`.
- [x] Delegated Responders: Validates `OCSPSigning` EKU and signature chain.
- [x] Cache Management: Derive TTL from `NextUpdate`.

## CA/Browser Forum Baseline Requirements
- [x] Response Timing: `thisUpdate` and `nextUpdate` fields correctly populated.
- [x] Graceful Handling: Returns appropriate error codes (e.g., `MalformedRequest`, `InternalError`).

## Cryptographic Best Practices
- [x] Private Key Security: Keys loaded into memory, never logged or exposed via API.
- [x] Algorithm Agnostic: Supports RSA, ECDSA, and Ed25519.
- [x] SHA-256 Favoritism: Prefers modern hashing for internal operations.

## Operational Integrity
- [x] Cold Start: Full scan of `DATA_DIR` on initiation.
- [x] Hot Reload: `fsnotify` based updates with debounce logic.
- [x] Atomic Updates: Redis cache in-sync with loaded PKI state.
