"""In-memory metrics and audit log for the firewall.

Keeps the runtime dependency surface tiny while still exposing useful telemetry
on ``/metrics`` (Prometheus) and ``/stats`` (JSON).
"""
from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from typing import Deque, Dict, List


@dataclass
class AuditEvent:
    ts: float
    layer: str           # "input" | "tools" | "output"
    decision: str        # "allow" | "block" | "redact"
    classes: List[str] = field(default_factory=list)
    score: float = 0.0


class MetricsStore:
    """Thread-safe in-process counters + bounded audit ring buffer."""

    def __init__(self, audit_capacity: int = 500) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()
        self._blocks_by_class: Counter[str] = Counter()
        self._audit: Deque[AuditEvent] = deque(maxlen=audit_capacity)
        self._started_at = time.time()

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._counts[f"{event.layer}.{event.decision}"] += 1
            for cls in event.classes:
                self._blocks_by_class[cls] += 1
            self._audit.append(event)

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self._started_at, 2),
                "counts": dict(self._counts),
                "blocks_by_class": dict(self._blocks_by_class),
                "recent": [asdict(e) for e in list(self._audit)[-50:]],
            }

    def prometheus(self) -> str:
        with self._lock:
            lines: List[str] = [
                "# HELP ragfw_decisions_total Firewall decisions by layer and outcome.",
                "# TYPE ragfw_decisions_total counter",
            ]
            for key, value in self._counts.items():
                layer, decision = key.split(".", 1)
                lines.append(
                    f'ragfw_decisions_total{{layer="{layer}",decision="{decision}"}} {value}'
                )
            lines.append("# HELP ragfw_blocks_by_class_total Blocks by attack class.")
            lines.append("# TYPE ragfw_blocks_by_class_total counter")
            for cls, value in self._blocks_by_class.items():
                lines.append(f'ragfw_blocks_by_class_total{{class="{cls}"}} {value}')
            return "\n".join(lines) + "\n"


metrics = MetricsStore()
