"""Adversarial performance-envelope audits with a certified dispatch policy."""

from .certificate import build_certificate, verify_certificate
from .dispatch import candidate_guards, evaluate_dispatch, fit_guard, guard_overhead_s
from .measure import measure, percentile
from .search import (
    Observation,
    OutputMismatch,
    SearchResult,
    evaluate_pair,
    minimize_witness,
    search_worst_case,
)

__all__ = [
    "Observation",
    "OutputMismatch",
    "SearchResult",
    "build_certificate",
    "candidate_guards",
    "evaluate_dispatch",
    "evaluate_pair",
    "fit_guard",
    "guard_overhead_s",
    "measure",
    "minimize_witness",
    "percentile",
    "search_worst_case",
    "verify_certificate",
]

__version__ = "0.1.0"
