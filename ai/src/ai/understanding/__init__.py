from __future__ import annotations

from .email_analyzer import (
    Signal,
    UnderstandingResult,
    analyze_email,
    extract_forensic_signals,
)

__all__ = [
    "Signal",
    "UnderstandingResult",
    "analyze_email",
    "extract_forensic_signals",
]
