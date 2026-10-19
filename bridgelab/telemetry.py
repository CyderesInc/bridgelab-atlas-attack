"""Structured telemetry for attack chain events."""

import time
import uuid


class ChainLogger:
    """Records structured events as the attack chain progresses."""

    def __init__(self):
        self.chain_id = str(uuid.uuid4())[:8]
        self._events: list[dict] = []
        self._current_stage = ""

    def stage(self, stage_id: str, description: str):
        self._current_stage = stage_id
        print(f"\n{'=' * 64}")
        print(f"  [{stage_id.upper()}] {description}")
        print(f"{'=' * 64}")

    def event(self, stage: str, technique_id: str, description: str, details: dict | None = None):
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "chain_id": self.chain_id,
            "stage": stage,
            "technique_id": technique_id,
            "description": description,
            "details": details or {},
        }
        self._events.append(event)
        if technique_id.startswith("AML"):
            framework = "ATLAS"
        elif technique_id.startswith("T"):
            framework = "ATT&CK"
        else:
            framework = "BRIDGE"
        print(f"  [{framework}] {technique_id}: {description}")
        if details:
            for k, v in details.items():
                print(f"           {k}: {v}")

    def get_events(self) -> list[dict]:
        return list(self._events)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "event_count": len(self._events),
            "stages": sorted({e["stage"] for e in self._events}),
            "events": self._events,
        }
