"""ScamShield: a private, offline scam-message checker."""
from .engine import Engine
from .models import LIKELY_SCAM, LOW_RISK, SUSPICIOUS, Finding, Report

__version__ = "0.1.0"
__all__ = ["Engine", "Finding", "Report", "LIKELY_SCAM", "SUSPICIOUS", "LOW_RISK",
           "analyze", "__version__"]

_default = None


def analyze(text: str) -> Report:
    """Analyse a message with the built-in rules."""
    global _default
    if _default is None:
        _default = Engine()
    return _default.analyze(text)
