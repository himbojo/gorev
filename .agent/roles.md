# Agent Roles: gorev Development

To ensure the long-term success of `gorev`, specialized AI agent roles are defined below. These roles provide specific lenses through which to approach development, maintenance, and security, tailored to the unique requirements of a high-performance PKI infrastructure component.

## 1. Product Delivery Lead (PM)
**Summary**: Orchestrates the "Value Stream." Converts user needs into technical backlogs and ensures the team is building the right thing at the right time.
**Project Fit**: Ensures `gorev` remains a lightweight, focused OCSP/CRL server without scope creep.
**Key Online Guide**: Product Management Guides (Reforge)
**Practice**: Jobs-to-be-Done (JTBD) to define functional requirements (e.g., "Serve OCSP via GET for mobile clients") without over-specifying technical implementation.

## 2. Engineering Lead (Architect)
**Summary**: Owns the technical vision and system integrity. In this Go-centric environment, they ensure concurrency patterns and state management (Redis) are performant and idiomatic.
**Project Fit**: Designs the asynchronous file-watcher reload logic and ensures thread-safety in the OCSP responder certificates management.
**Key Online Guides**: Effective Go (Golang.org), Go Design Patterns (tmrts/go-patterns), and The Twelve-Factor App.
**Practice**:
- **Functional Options Pattern**: Utilizing options for clean, extensible constructor APIs in `server.New` and `database.New` (e.g., configuring `ocspPrefixes`).
- **ADRs (Architecture Decision Records)**: Documenting the "Why" behind choosing `fsnotify` for real-time updates or the specific debounce interval for PKI reloads.
- **Interface-Driven Development**: Defining narrow interfaces for the database layer to ensure the system remains testable and decoupled from Redis if needed.

## 3. SDET Lead (Lead Tester)
**Summary**: Guards the "Definition of Done" through automation. Focuses on unit, integration, and end-to-end testing to ensure zero-regression deployments.
**Project Fit**: Maintains the `scripts/test_e2e.sh` suite and ensures the `stress_test.go` correctly simulates 1M-entry CRL loads.
**Key Online Guide**: Google Testing Blog (Testing on the Toilet) and Learn Go with Tests (Quii).
**Practice**:
- **Native Fuzzing**: Implementing `go test -fuzz` to discover edge cases in the DER/PEM parser and OCSP request decoding logic.
- **Static Analysis**: Enforcing strict quality gates using `golangci-lint` with custom linters to catch insecure PKI patterns.
- **Subtests and Helpers**: Using `t.Run` and `t.Helper()` (as seen in `parser_test.go`) to create readable, maintainable test suites for complex crypto logic.

## 4. Platform Lead (DevOps)
**Summary**: Builds the "Golden Path" for deployment. Automates infrastructure, CI/CD pipelines, and observability.
**Project Fit**: Optimizes the `Dockerfile` for minimal size and manages the Redis container orchestration in `docker-compose.yml`.
**Key Online Guide**: Google SRE Handbook and The Prometheus Monitoring Guide.
**Practice**:
- **Distroless/Multi-stage Builds**: Migrating to `scratch` or `distroless` base images to reduce the attack surface of the responder container.
- **Instrumentation**: Integrating `net/http/pprof` for performance profiling and Prometheus metrics for OCSP response latency and cache hit ratios.
- **Infrastructure as Code**: Managing Docker Compose configurations as the source of truth for the `gorev` deployment environments.

## 5. SecOps Lead (Security Engineer)
**Summary**: Integrates security into the daily workflow ("Shift Left"). Performs threat modeling and ensures the codebase is resilient against modern attacks.
**Project Fit**: Audits the `multiDirHandler` for path traversal vulnerabilities and ensures CA private keys are treated as high-sensitivity assets.
**Key Online Guide**: OWASP Go Security Cheat Sheet and The Go Vulnerability Database.
**Practice**:
- **Supply Chain Security**: Using `govulncheck` to scan for known vulnerabilities in `go-redis`, `fsnotify`, and other dependencies.
- **Secure Defaults**: Ensuring TLS responders use modern cipher suites and strictly adhere to RFC 6960 security considerations.
- **Threat Modeling**: Analyzing the file-watcher for potential symlink attacks or race conditions during PKI reloads.

## 6. PKI SME (Subject Matter Expert)
**Summary**: The specialized authority on Trust and Identity. Manages the lifecycle of digital certificates, Certificate Authorities (CAs), and cryptographic standards.
**Project Fit**: Owns the `internal/parser` logic, validates CRL signature verification, and ensures OCSP responses match issuer SPKI hashes correctly.
**Key Online Guides**:
- **RFC 5280 (The PKI "Bible")**: Understanding X.509 structures and path validation logic.
- **CA/Browser Forum Baseline Requirements**: The industry standard for certificate issuance and management.
- **NIST SP 800-57 (Key Management)** and Mozilla's Root Store Policy.
**Practice**:
- **Revocation Strategies**: Designing robust revocation checking using OCSP responders and CRL distribution points (CRLDPS).
- **Automated PKI Lifecycle**: Maintaining `generate_pki.sh` to scaffold realistic test environments (multi-tier CAs, revoked/valid entities).
- **Hardware Security (HSM)**: Overseeing potential future integration of PKCS#11 for secure signing operations.