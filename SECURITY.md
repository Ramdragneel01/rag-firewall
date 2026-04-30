# Security Policy — rag-firewall

## Status

`rag-firewall` is a defensive security tool for LLM applications. This document is the explicit threat model and disclosure policy for the project itself.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: **ramprakashdhulipudi@gmail.com**

Include:
- Description and impact
- Reproduction steps or proof-of-concept
- Affected version / commit SHA
- Your contact info for follow-up

We will acknowledge within 72 hours and aim to provide a remediation plan within 7 days for high-severity issues.

## Threat Model (v0.1)

### In Scope

| Class | Surface | Defense |
|---|---|---|
| Prompt injection (instruction override, persona hijack, system-prompt leak) | Input layer | Heuristic + base64 deobfuscation; classifier hook |
| Tool / function abuse (calling disallowed tools) | Tool layer | Name-based allowlist on OpenAI / Anthropic / legacy shapes |
| Output exfiltration of secrets (OpenAI keys, AWS keys, GitHub PATs, private keys) | Output layer | Regex redaction + hard-fail on private keys |
| PII leakage (email, SSN, credit-card-shaped numbers) | Output layer | Regex redaction |
| Block-reason oracle attacks | API surface | Public errors are intentionally generic |
| Credential forwarding from clients to upstream | Proxy | Client `Authorization` header is stripped; firewall owns the upstream key |

### Out of Scope (v0.1)

- **Streaming responses** — output scanner runs on full body. Tracked for v0.2.
- **Per-tenant policies** — global config only. Multi-tenant lands via `agent-cost-governor`.
- **Tool argument validation** — only tool *names* are checked. Schema-level checks via OPA are roadmap.
- **Network-level DDoS** — use a CDN / WAF in front of the firewall.
- **Supply-chain attacks on upstream models** — outside the firewall's control.

## Hardening Checklist

If you deploy `rag-firewall`:

- [ ] Run as non-root (the provided Dockerfile already does this).
- [ ] Set `RAGFW_TOOL_ALLOWLIST` for any tool-using workload.
- [ ] Place behind TLS termination (Cloud Run, ALB, nginx).
- [ ] Send `/metrics` to a private Prometheus; do not expose publicly.
- [ ] Rotate `RAGFW_UPSTREAM_API_KEY` via your secret manager, not env var dumps.
- [ ] Treat the audit log as security-sensitive — it contains attempted attack payloads.

## Dependency Security

- `pip-audit` runs in CI on every PR (planned for v0.2).
- Renovate bot enabled for automatic dependency updates.
- All runtime deps pinned in `requirements.txt`.

## Disclosure Timeline

- T+0: Report received
- T+72h: Acknowledgement
- T+7d: Remediation plan or status update
- T+30d: Public advisory (coordinated with reporter)

## Hall of Fame

Researchers who responsibly disclose are listed here with their permission.
