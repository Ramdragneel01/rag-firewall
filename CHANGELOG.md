# Changelog

All notable changes to `rag-firewall` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-04-30

### Added

- Initial public release.
- FastAPI proxy with `POST /v1/proxy/{path}` forwarding to a configurable upstream LLM API.
- Defense layer 1 — input scanner: weighted heuristics across instruction-override, persona-hijack, system-prompt-leak, data-exfiltration, command-injection, and obfuscation classes; base64 deobfuscation; pluggable classifier hook.
- Defense layer 2 — tool allowlist: blocks disallowed tool / function names across OpenAI, Anthropic, and legacy `functions` shapes.
- Defense layer 3 — output scanner: regex redaction for OpenAI keys, AWS access keys, AWS secret keys (hard-fail), GitHub PATs, private keys (hard-fail), SSNs, credit-card-shaped numbers, emails, and system-prompt echoes.
- Operator endpoints: `/health`, `/ready`, `/stats`, `/metrics` (Prometheus).
- In-process `MetricsStore` with thread-safe counters and a 500-event audit ring buffer.
- Generic public error messages (no block-reason oracle).
- Hop-by-hop header stripping; client `Authorization` replaced by firewall-managed upstream key.
- Dockerfile (non-root, healthcheck) and `docker-compose.yml`.
- GitHub Actions CI: ruff lint, pytest with coverage, container smoke test, GHCR publish on tag.
- 26 unit and integration tests covering all three layers and the proxy happy / sad paths.
- Documentation: `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `docs/RUNBOOK.md`.

[Unreleased]: https://github.com/Ramdragneel01/rag-firewall/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ramdragneel01/rag-firewall/releases/tag/v0.1.0
