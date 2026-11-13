"""Separate-process peak-RSS probe for the dispatched path (G5)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from envelope_guard.case_study import _guard_no_ff_len64, dispatch, optimized, realistic_corpus, baseline

docs = [realistic_corpus(target_bytes=2 * 1024 * 1024, seed=20261114 + i) for i in range(4)]
for doc in docs:
    for _ in range(3):
        dispatch(baseline, optimized, _guard_no_ff_len64, doc)
