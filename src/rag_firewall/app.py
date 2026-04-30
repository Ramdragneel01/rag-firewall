"""FastAPI application: HTTP entry point for rag-firewall."""
from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from . import __version__
from .config import Settings, get_settings
from .metrics import AuditEvent, metrics
from .pipeline import inspect_request, inspect_response_text

# Hop-by-hop headers that must not be forwarded.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Tests pass a custom ``Settings`` instance."""
    settings = settings or get_settings()

    app = FastAPI(
        title="rag-firewall",
        version=__version__,
        description="Defense-in-depth proxy for LLM APIs.",
    )
    app.state.settings = settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/stats")
    def stats() -> dict[str, Any]:
        return metrics.snapshot()

    @app.get("/metrics")
    def prom_metrics() -> Response:
        return PlainTextResponse(metrics.prometheus(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/proxy/{path:path}")
    async def proxy(path: str, request: Request) -> Response:
        return await _handle_proxy(path, request, app.state.settings)

    return app


async def _handle_proxy(path: str, request: Request, settings: Settings) -> Response:
    raw = await request.body()
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "invalid_json", "message": "Request body must be valid JSON."}},
        )

    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "invalid_payload", "message": "Request body must be a JSON object."}},
        )

    # Layer 1 + 2 — input + tools
    decision = inspect_request(payload, settings)
    if not decision.allowed:
        metrics.record(
            AuditEvent(
                ts=_now(),
                layer="input" if decision.error_code == "prompt_injection_detected" else "tools",
                decision="block",
                classes=decision.audit_classes,
                score=decision.score,
            )
        )
        return JSONResponse(
            status_code=decision.status_code,
            content={
                "error": {
                    "code": decision.error_code,
                    "message": decision.public_message,
                }
            },
        )

    metrics.record(AuditEvent(ts=_now(), layer="input", decision="allow"))

    # Forward to upstream
    upstream_url = f"{settings.upstream_base_url.rstrip('/')}/{path}"
    forward_headers = _build_forward_headers(request.headers, settings)

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            upstream = await client.post(upstream_url, content=raw, headers=forward_headers)
    except httpx.HTTPError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": {"code": "upstream_error", "message": str(exc)}},
        )

    # Layer 3 — output scan
    response_text = upstream.text
    output_result = inspect_response_text(response_text, settings)
    if output_result.blocked:
        metrics.record(
            AuditEvent(
                ts=_now(),
                layer="output",
                decision="block",
                classes=output_result.findings,
            )
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "code": "unsafe_response",
                    "message": "Response withheld by firewall policy.",
                }
            },
        )

    if output_result.findings:
        metrics.record(
            AuditEvent(
                ts=_now(),
                layer="output",
                decision="redact",
                classes=output_result.findings,
            )
        )
    else:
        metrics.record(AuditEvent(ts=_now(), layer="output", decision="allow"))

    return Response(
        content=output_result.sanitized.encode("utf-8"),
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/json"),
    )


def _build_forward_headers(incoming, settings: Settings) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in incoming.items():
        if key.lower() in _HOP_BY_HOP:
            continue
        if key.lower() == "authorization":
            # Replace client auth with our managed upstream key.
            continue
        out[key] = value
    if settings.upstream_api_key:
        out["authorization"] = f"Bearer {settings.upstream_api_key}"
    out["content-type"] = out.get("content-type", "application/json")
    return out


def _now() -> float:
    import time
    return time.time()


# Default app for ``uvicorn rag_firewall.app:app``
app = create_app()
