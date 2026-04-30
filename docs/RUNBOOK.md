# Runbook — rag-firewall

Operational reference for engineers running `rag-firewall` in production.

## Service Summary

- **Purpose:** Defense-in-depth proxy between clients and an upstream LLM API.
- **Stateless:** Yes (counters reset on restart). Horizontally scalable.
- **Default port:** `8080`
- **Liveness:** `GET /health` → `{"status":"ok"}`
- **Readiness:** `GET /ready` → `{"status":"ready"}`
- **Telemetry:** `/stats` (JSON), `/metrics` (Prometheus)

## Standard Configuration

| Variable | Default | When to change |
|---|---|---|
| `RAGFW_UPSTREAM_BASE_URL` | `https://api.openai.com` | Switching providers (Anthropic, Vertex, Bedrock proxy) |
| `RAGFW_UPSTREAM_API_KEY` | empty | **Required** in production |
| `RAGFW_INJECTION_THRESHOLD` | `0.6` | Raise to reduce false positives; lower for stricter posture |
| `RAGFW_TOOL_ALLOWLIST` | empty | **Set** for any tool-using workload |
| `RAGFW_LOG_LEVEL` | `INFO` | `DEBUG` for incident investigation only |

## Deploy

### Cloud Run / ECS / AKS

```bash
docker pull ghcr.io/ramdragneel01/rag-firewall:latest
# Inject upstream key via your secret manager.
# Front with TLS termination. Restrict /metrics to private network.
```

### Compose (lab / staging)

```bash
docker compose up -d
docker compose logs -f rag-firewall
```

## Common Operations

### Roll a new version

1. Tag a release: `git tag v0.x.y && git push origin v0.x.y`.
2. CI publishes `ghcr.io/ramdragneel01/rag-firewall:v0.x.y` and `:latest`.
3. Update your deployment manifest to the new tag.
4. Watch `/metrics`: `ragfw_decisions_total{decision="block"}` should remain stable for benign traffic.

### Rotate the upstream key

1. Update `RAGFW_UPSTREAM_API_KEY` in the secret manager.
2. Trigger a rolling restart.
3. Confirm `/health` returns `200` and a sample request succeeds.
4. Revoke the old key upstream.

### Tune false positives

Symptom: `ragfw_decisions_total{layer="input",decision="block"}` rising without attack telemetry.

1. Pull recent audit events: `curl https://<host>/stats | jq '.recent[-20:]'`.
2. Identify the dominant class (e.g., `instruction_override`).
3. Raise `RAGFW_INJECTION_THRESHOLD` (e.g., `0.6` → `0.75`) and redeploy.
4. If a specific pattern is the culprit, file an issue with a sanitized payload sample.

## Alerts (suggested)

| Alert | Condition | Severity |
|---|---|---|
| Firewall down | `up{job="rag-firewall"} == 0` for 2m | P1 |
| Upstream errors high | `rate(ragfw_decisions_total{layer="output",decision="block"}[5m]) > rate_baseline * 5` | P2 |
| Block rate spike | `rate(ragfw_decisions_total{decision="block"}[5m]) > rate_baseline * 10` | P2 |
| Latency p95 > 250ms | application-level histogram | P3 |

## Incident Playbooks

### "Firewall is blocking legitimate traffic"

1. Capture: `curl /stats | jq '.recent[-50:]'`.
2. Correlate with the originating client's request — check the matched class.
3. Short-term mitigation: raise `RAGFW_INJECTION_THRESHOLD` for the affected deployment.
4. Long-term: open a PR adding a negative test case and refining the heuristic.

**Never** disable the firewall (`RAGFW_ENABLE_INPUT_SCANNER=false`) as a "fix" without an incident ticket and a time-boxed rollback.

### "Suspected secret leaked in a model response"

1. Confirm: search recent audit events for `output` layer findings — `private_key`, `aws_secret_key`, `openai_api_key`.
2. If `decision == "redact"`: the firewall caught it. Investigate why the model emitted it and rotate the secret upstream regardless.
3. If `decision == "block"`: the upstream produced a hard-fail leak. Same rotation flow + retro on the prompt that elicited it.
4. Open a SECURITY.md disclosure if the leak originated from an attacker prompt.

### "Upstream is down"

1. `/v1/proxy/...` returns `502 upstream_error`.
2. Confirm upstream status (provider status page).
3. The firewall does not retry; clients should use exponential backoff.
4. If extended outage: route traffic to a fallback `RAGFW_UPSTREAM_BASE_URL` via a config flip.

## Capacity Planning

- Memory: ~120 MB at idle, ~256 MB under sustained load (heuristic-only).
- CPU: a single worker handles ~500 RPS for short prompts on a 2-vCPU box.
- Latency budget added by firewall: p50 ~15 ms, p95 ~35 ms (heuristic only).

## Backup / Restore

`rag-firewall` is stateless. There is nothing to back up. Configuration lives in your secret manager and IaC.

## Contacts

- Maintainer: Ram Prakash Dhulipudi — ramprakashdhulipudi@gmail.com
- Security: see [SECURITY.md](../SECURITY.md)
