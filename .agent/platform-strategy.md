# Platform Strategy: gorev

This document outlines the platform vision and infrastructure standards for `gorev`, ensuring a consistent, secure, and observable "Golden Path" for deployment.

## 1. Vision
`gorev` is designed as a cloud-native PKI infrastructure component. The goal is to provide a "zero-touch" deployment experience that is resilient by default and easy to monitor.

## 2. Deployment Strategy

### Containerization
- **Base Image**: Multi-stage Docker builds using `golang:1.22-alpine` for building and `alpine:3.21` for runtime.
- **Goal**: Transition runtime to `distroless` or `scratch` to minimize attack surface.
- **User**: Runs as non-root user `gorev` (UID 1001).

### Orchestration
- **Docker Compose**: The primary method for local and small-scale deployments.
- **Redis**: Deployed as a sidecar/adjacent container. Persists data via Docker volumes.
- **Port Mapping**: Redis bound strictly to `127.0.0.1` unless cross-host communication is required and secured.

## 3. Infrastructure Standards

### Hardening
- **ReadOnly Filesystem**: The `DATA_DIR` is mounted as read-only (`:ro`) to prevent the application from modifying its own PKI artifacts at runtime.
- **Secrets Management**: Sensitive values like `REDIS_PASSWORD` are managed via environment variables.

### Resilience
- **Restart Policy**: `unless-stopped` is used for both Redis and the responder to ensure high availability.
- **Health Checks**: (Planned) Implement Docker health checks for both services.

## 4. Observability Roadmap

### Metrics (Future)
- **Integration**: Prometheus exporter for:
    - OCSP request latency.
    - Cache hit/miss ratios.
    - PKI reload events.
    - Responder certificates expiration dates.

### Logging
- **Format**: Structured JSON logging (future improvement over current `log` package).
- **Target**: Standard output (stdout) for container log aggregation.

### Profiling
- **Support**: `net/http/pprof` enabled via build flags for performance troubleshooting in production-like environments.
