"""Console entry point: ``python -m rag_firewall``."""
from __future__ import annotations

import uvicorn

from .config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "rag_firewall.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
