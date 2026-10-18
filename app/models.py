"""
Core data shapes. Dataclasses only — no external dependency pulls in the
model layer, so parsing and rules stay usable as a library with nothing
else installed (same zero-dependency stance as Woodpecker).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    SUDO = "sudo"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class LogEvent:
    timestamp: datetime
    event_type: EventType
    user: str
    source_ip: str | None = None
    raw_line: str = ""
    # sudo-only fields
    target_user: str | None = None
    command: str | None = None


@dataclass
class Finding:
    rule: str
    severity: Severity
    user: str
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "user": self.user,
            "reasons": self.reasons,
            "evidence": self.evidence,
        }
