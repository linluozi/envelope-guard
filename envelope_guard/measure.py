"""Low-noise wall-clock measurement used by the envelope audit.

The timer is always ``time.perf_counter``.  Each sample runs the callable
enough times that the sample lasts at least ``min_sample_time`` seconds, then
divides by the number of calls.  That keeps sub-microsecond functions from
being measured through a single timer tick.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Callable, Sequence

Timer = Callable[[], float]


@dataclass(frozen=True)
class Summary:
    median_s: float
    p25_s: float
    p75_s: float
    mean_s: float
    rsd: float
    samples: tuple[float, ...]
    calls_per_sample: int

    def to_dict(self) -> dict:
        return {
            "median_s": self.median_s,
            "p25_s": self.p25_s,
            "p75_s": self.p75_s,
            "mean_s": self.mean_s,
            "rsd": self.rsd,
            "samples_s": list(self.samples),
            "calls_per_sample": self.calls_per_sample,
        }


def percentile(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile; ``q`` in [0, 1]."""
    if not sorted_values:
        raise ValueError("empty sample")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (len(sorted_values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return float(sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac)


def _sample(
    fn: Callable[[bytes], object],
    arg: bytes,
    min_sample_time: float,
    max_calls: int,
) -> tuple[float, int]:
    fn(arg)  # local warm-up, outside the timed region
    calls = 1
    while True:
        start = time.perf_counter()
        for _ in range(calls):
            fn(arg)
        elapsed = time.perf_counter() - start
        if elapsed >= min_sample_time or calls >= max_calls:
            return elapsed / calls, calls
        calls = min(calls * 2, max_calls)


def measure(
    fn: Callable[[bytes], object],
    arg: bytes,
    *,
    warmup: int = 3,
    repeats: int = 7,
    min_sample_time: float = 0.001,
    max_calls: int = 1 << 16,
) -> Summary:
    if warmup < 0 or repeats < 2:
        raise ValueError("warmup >= 0 and repeats >= 2 are required")
    for _ in range(warmup):
        fn(arg)
    samples: list[float] = []
    calls_per_sample = 0
    for _ in range(repeats):
        per_call, calls_per_sample = _sample(fn, arg, min_sample_time, max_calls)
        samples.append(per_call)
    ordered = sorted(samples)
    mean = statistics.fmean(samples)
    stdev = statistics.stdev(samples) if len(samples) > 1 else 0.0
    return Summary(
        median_s=statistics.median(samples),
        p25_s=percentile(ordered, 0.25),
        p75_s=percentile(ordered, 0.75),
        mean_s=mean,
        rsd=(stdev / mean) if mean else 0.0,
        samples=tuple(samples),
        calls_per_sample=calls_per_sample,
    )
