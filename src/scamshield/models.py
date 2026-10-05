"""Plain data containers shared by the engine, CLI and API."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

LIKELY_SCAM = "likely_scam"
SUSPICIOUS = "suspicious"
LOW_RISK = "low_risk"


@dataclass
class Finding:
    """One red flag (or reassuring sign, if weight < 0) found in a message."""

    rule_id: str
    category: str
    weight: int
    title: str
    explanation: str
    evidence: str = ""
    start: int = -1  # character offsets into the analysed text, -1 = none
    end: int = -1
    lang: str = "any"


@dataclass
class Report:
    score: int
    verdict: str
    headline: str
    findings: List[Finding] = field(default_factory=list)
    advice: List[str] = field(default_factory=list)
    script: str = "latin"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
