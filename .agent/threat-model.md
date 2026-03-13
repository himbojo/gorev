# Threat Model: gorev

## Trust Boundaries

1.  **Client -> Responder**: The internet/intranet boundary where OCSP and CRL requests originate.
2.  **Responder -> Redis**: The internal boundary where the responder queries the revocation database.
3.  **Responder -> Local Filesystem**: The boundary where the responder reads CA certificates, CRLs, and responder keys.

## Threat Actors

-   **External Attacker**: Malicious client attempting to gain sensitive information or cause a denial of service.
-   **Internal Compromise**: A compromised service or user on the same host attempting to escalate privileges or steal keys.

## Threats & Mitigations

| Threat | Description | Mitigation | Status |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | Attacker tries to read sensitive files (e.g., responder keys) via `/cas/` or `/crls/` endpoints. | `multiDirHandler` uses `filepath.Clean` and `filepath.EvalSymlinks` to enforce strict directory boundaries. | **Verified** |
| **Denial of Service (DoS)** | Attacker sends massive OCSP requests or large POST bodies to exhaust memory/CPU. | `io.LimitReader` restricts POST bodies to 64KB. Redis caching offloads expensive signing. | **Mitigated** |
| **OCSP Spoofing** | Attacker tries to forge OCSP responses for other CAs. | Responder strictly matches issuer SPKI hashes and returns `Unauthorized` for unknown issuers. | **Mitigated** |
| **Signature Bypass** | Attacker provides a malicious CRL without a valid signature. | `main.go` performs mandatory CRL signature verification against the issuing CA before ingestion. | **Enforced** |
| **Sensitive Asset Leak** | CA private keys or responder keys are leaked if the filesystem is compromised. | Keys should be protected with OS-level permissions. (Future: HSM support). | **Ongoing** |

## Attack Surface

-   **HTTP Endpoints**: `/ocsp`, `/cas`, `/crls`.
-   **Configuration**: Environment variables.
-   **Data Directory**: Local files monitored by `fsnotify`.

## Security Roadmap

1.  [ ] **HSM Integration**: Move responder keys to an HSM/KMS.
2.  [ ] **mTLS for Redis**: Secure the connection between the responder and Redis.
3.  [ ] **Rate Limiting**: Implement per-IP rate limiting for OCSP requests.
