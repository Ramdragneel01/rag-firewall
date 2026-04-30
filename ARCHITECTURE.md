# Architecture — rag-firewall

## Goal

Provide a self-hostable, low-latency, drop-in defense layer between any client and any LLM API. The firewall must:

- be deployable as a single container,
- run without GPUs or large model dependencies (heuristic-first),
- expose a clean extension point for a real classifier (Llama Guard, Prompt Guard),
- never silently change request semantics for benign traffic.

## Component View

```
                ┌──────────────────────────────────────────────┐
                │                rag-firewall                  │
                │  ┌────────────┐   ┌────────────┐  ┌────────┐ │
 client ──HTTP─▶│  │  Layer 1   │──▶│  Layer 2   │──▶ Layer 3 │─▶ upstream LLM API
                │  │ Injection  │   │ Tool ACL   │  │ Output  │ │
                │  └────────────┘   └────────────┘  └────────┘ │
                │           │              │            │      │
                │           └────────┬─────┴────────────┘      │
                │                    ▼                          │
                │              MetricsStore                     │
                │      (counters, ring buffer, /metrics)        │
                └──────────────────────────────────────────────┘
```

## Module Map

| Module                                  | Responsibility                                      |
| --------------------------------------- | --------------------------------------------------- |
| `rag_firewall.app`                      | FastAPI app, proxy route, header normalization      |
| `rag_firewall.config`                   | Pydantic Settings, env-driven config                |
| `rag_firewall.pipeline`                 | Composes the three layers; pure-function decisions  |
| `rag_firewall.detectors.injection`      | Heuristic scoring + base64 deobfuscation            |
| `rag_firewall.detectors.tools`          | OpenAI/Anthropic/legacy tool-name allowlist         |
| `rag_firewall.detectors.output`         | Regex-based PII/secret redaction with hard-fail set |
| `rag_firewall.metrics`                  | Thread-safe counters, audit ring, Prometheus export |

## Request Flow

1. Client `POST /v1/proxy/<upstream-path>` with a JSON chat-completion body.
2. Body is parsed; non-JSON or non-object bodies are rejected with `400`.
3. **Layer 2** (tools) runs first because tool-misuse is cheap to detect and a hard "no".
4. **Layer 1** (injection) extracts non-system message text and scores it. Score ≥ threshold ⇒ block (`400 prompt_injection_detected`).
5. Authorization is rewritten with the firewall-managed upstream key. Hop-by-hop headers are stripped.
6. Upstream is called via `httpx.AsyncClient`. Connection / network errors ⇒ `502 upstream_error`.
7. **Layer 3** (output) scans the response body. Hard-fail categories (`private_key`, `aws_secret_key`) ⇒ `502 unsafe_response`. Soft categories ⇒ in-place redaction. Findings are recorded.
8. Response is returned to the client with the original status and content-type.

Every decision emits an `AuditEvent` to the in-process `MetricsStore`.

## Key Design Decisions

### 1. Heuristics first, classifier optional

A weighted regex set with base64 deobfuscation gives a useful out-of-the-box signal with **no** external model. The classifier hook (`score_classifier`) is an explicit extension point so the runtime image stays under ~150MB.

### 2. Pure-function pipeline

`pipeline.inspect_request` and `pipeline.inspect_response_text` are pure functions taking `(payload, settings)`. This makes the defense logic unit-testable without HTTP, which is where most bugs in proxy-style projects hide.

### 3. Don't echo the block reason

Public error messages are intentionally generic (`"Request rejected by firewall policy."`). The audit log records the matched class. Telling an attacker *why* they were blocked turns the firewall into a free oracle.

### 4. Hard-fail on private keys, redact everything else

Some leaks (private keys, AWS secrets) cannot be safely redacted because partial leakage is still a leak. These categories block the entire response. Lower-severity categories (emails, SSNs, OpenAI keys in echoes) are redacted in place to preserve UX.

### 5. Strip client `Authorization`

Clients never get to forward arbitrary credentials to the upstream. The firewall owns the upstream credential.

## Trade-offs Recorded for Future Iteration

- **No streaming yet.** The output scanner runs on the full body; streaming requires a token-buffered variant. Tracked for v0.2.
- **No per-tenant policy.** v0.1 is global config. Per-tenant config will land via `agent-cost-governor` integration.
- **In-process metrics.** Counters live in memory; restart loses history. Acceptable for v0.1; OTLP export is the long-term path.

## Operational Targets (v0.1)

- p95 added latency: ≤ 50ms (heuristic only)
- Image size: ≤ 200MB
- Memory: ≤ 256MB at idle
- Test coverage: ≥ 85% on `src/rag_firewall/`

## Extension Points

- `detectors.injection.score_classifier` — drop in a real classifier
- `detectors.output._RULES` — extend the regex catalog (consider Presidio for production)
- `metrics.MetricsStore` — swap for an OTLP-backed store
