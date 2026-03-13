# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta] - 2026-03-13

### Added
- Core OCSP responder logic with GET and POST support.
- Static CRL and CA certificate serving.
- Redis backend for revocation statuses and OCSP response caching.
- Asynchronous file watching with debounce for DATA_DIR.
- Multi-tier CA support and signature verification for CRLs.
- Continuous Integration scaffolding: E2E tests, stress tests, and multi-stage Docker build.
