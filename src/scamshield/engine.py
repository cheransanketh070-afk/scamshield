"""The ScamShield engine: rules + link checks -> a score, a verdict and advice."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern, Union

from .models import LIKELY_SCAM, LOW_RISK, SUSPICIOUS, Finding, Report
from .urls import find_urls

BUILTIN_PACK = Path(__file__).with_name("data") / "patterns.json"
MAX_CHARS = 10_000          # longer text is truncated: scam messages are short
THRESHOLD_SCAM = 55
THRESHOLD_SUSPICIOUS = 25
COMBO_BONUS = 15

# A "pressure" signal plus an "ask" signal is the classic scam recipe.
PRESSURE = {"urgency", "threat", "prize", "impersonation", "secrecy", "family",
            "tech_support"}
ASKS = {"credentials", "payment", "risky_url"}

_SCRIPTS = [
    ("sinhala", "\u0d80", "\u0dff"), ("tamil", "\u0b80", "\u0bff"),
    ("devanagari", "\u0900", "\u097f"), ("arabic", "\u0600", "\u06ff"),
    ("cyrillic", "\u0400", "\u04ff"), ("cjk", "\u4e00", "\u9fff"),
]

HEADLINES = {
    LIKELY_SCAM: "Very likely a scam",
    SUSPICIOUS: "Looks suspicious",
    LOW_RISK: "No obvious red flags",
}
VERDICT_ADVICE = {
    LIKELY_SCAM: ["Don't reply, click anything or pay. Block the sender and report the message."],
    SUSPICIOUS: ["Don't act on this yet. Check it through the official app, website or phone number."],
    LOW_RISK: ["No tool can prove a message is safe. If money or personal details are involved, double-check."],
}


@dataclass
class Rule:
    id: str
    category: str
    lang: str
    weight: int
    title: str
    explain: str
    regexes: List[Pattern[str]]
    examples: List[str]


def detect_script(text: str) -> str:
    counts: Dict[str, int] = {}
    for ch in text:
        for name, lo, hi in _SCRIPTS:
            if lo <= ch <= hi:
                counts[name] = counts.get(name, 0) + 1
                break
    return max(counts, key=counts.get) if counts else "latin"


class Engine:
    """Load the built-in rules plus any community packs and analyse text."""

    def __init__(self, extra_packs: Optional[Iterable[Union[str, Path]]] = None):
        self.categories: Dict[str, Dict[str, str]] = {}
        self.rules: List[Rule] = []
        self.load_pack(BUILTIN_PACK)
        for pack in extra_packs or []:
            self.load_pack(pack)

    # -- loading ---------------------------------------------------------
    def load_pack(self, path: Union[str, Path]) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.categories.update(data.get("categories", {}))
        for raw in data.get("rules", []):
            self.rules.append(self._compile(raw))

    @staticmethod
    def _compile(raw: dict) -> Rule:
        for key in ("id", "category", "weight", "patterns"):
            if key not in raw:
                raise ValueError(f"rule {raw.get('id', '?')}: missing '{key}'")
        try:
            regexes = [re.compile(p, re.I | re.S) for p in raw["patterns"]]
        except re.error as exc:
            raise ValueError(f"rule {raw['id']}: bad regex ({exc})") from exc
        return Rule(id=raw["id"], category=raw["category"], lang=raw.get("lang", "any"),
                    weight=int(raw["weight"]), title=raw.get("title", raw["id"]),
                    explain=raw.get("explain", ""), regexes=regexes,
                    examples=raw.get("examples", []))

    # -- analysis --------------------------------------------------------
    def analyze(self, text: str) -> Report:
        text = (text or "")[:MAX_CHARS]
        findings: List[Finding] = []

        for rule in self.rules:
            for rx in rule.regexes:
                m = rx.search(text)
                if m:
                    findings.append(Finding(
                        rule_id=rule.id, category=rule.category, weight=rule.weight,
                        title=rule.title, explanation=rule.explain,
                        evidence=m.group(0)[:80], start=m.start(), end=m.end(),
                        lang=rule.lang))
                    break

        findings.extend(find_urls(text))

        cats = {f.category for f in findings if f.weight > 0}
        if any(f.category == "url" and f.weight >= 12 for f in findings):
            cats.add("risky_url")
        if cats & PRESSURE and cats & ASKS:
            findings.append(Finding(
                rule_id="combo.pressure_plus_ask", category="combo", weight=COMBO_BONUS,
                title="Pressure combined with a request",
                explanation="Rushing or scaring you while also asking for money, codes "
                            "or a click is the classic scam pattern."))

        score = max(0, min(100, sum(f.weight for f in findings)))
        verdict = (LIKELY_SCAM if score >= THRESHOLD_SCAM
                   else SUSPICIOUS if score >= THRESHOLD_SUSPICIOUS else LOW_RISK)
        findings.sort(key=lambda f: -f.weight)
        return Report(score=score, verdict=verdict, headline=HEADLINES[verdict],
                      findings=findings, advice=self._advice(verdict, findings),
                      script=detect_script(text))

    def _advice(self, verdict: str, findings: List[Finding]) -> List[str]:
        tips = list(VERDICT_ADVICE[verdict])
        for f in findings:
            if f.weight <= 0:
                continue
            tip = self.categories.get(f.category, {}).get("tip", "")
            if tip and tip not in tips:
                tips.append(tip)
        return tips[:5]
