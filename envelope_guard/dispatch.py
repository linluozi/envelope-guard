"""Cheap input guards and the dispatch policy fitted from measured data."""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from .measure import measure
from .search import Observation

GuardFn = Callable[[bytes], bool]


@dataclass(frozen=True)
class Guard:
    name: str
    description: str
    fn: GuardFn


@dataclass(frozen=True)
class DispatchStats:
    guard: str
    inputs: int
    routed_to_optimized: int
    route_fraction: float
    median_speedup: float
    median_routed_speedup: float
    p25_speedup: float
    worst_speedup: float
    median_base_s: float
    median_dispatched_s: float

    def to_dict(self) -> dict:
        return {
            "guard": self.guard,
            "inputs": self.inputs,
            "routed_to_optimized": self.routed_to_optimized,
            "route_fraction": self.route_fraction,
            "median_speedup": self.median_speedup,
            "median_routed_speedup": self.median_routed_speedup,
            "p25_speedup": self.p25_speedup,
            "worst_speedup": self.worst_speedup,
            "median_base_s": self.median_base_s,
            "median_dispatched_s": self.median_dispatched_s,
        }


def candidate_guards() -> tuple[Guard, ...]:
    """A fixed, interpretable guard family; no model is fitted offline."""
    return (
        Guard("always_base", "always use the baseline path", lambda b: False),
        Guard("always_opt", "always use the optimized path", lambda b: True),
        Guard("no_ff", "optimized only when 0xff is absent", lambda b: b.count(255) == 0),
        Guard("no_nul", "optimized only when 0x00 is absent", lambda b: b.count(0) == 0),
        Guard("ascii_only", "optimized only for pure ASCII", lambda b: b.isascii()),
        Guard(
            "ff_ratio_le_1_8",
            "optimized when 0xff density is at most 1/8",
            lambda b: b.count(255) * 8 <= len(b),
        ),
        Guard(
            "no_ff_len_ge_8",
            "optimized when 0xff is absent and length >= 8",
            lambda b: len(b) >= 8 and b.count(255) == 0,
        ),
        Guard(
            "no_ff_len_ge_64",
            "optimized when 0xff is absent and length >= 64",
            lambda b: len(b) >= 64 and b.count(255) == 0,
        ),
        Guard(
            "no_ff_len_ge_256",
            "optimized when 0xff is absent and length >= 256",
            lambda b: len(b) >= 256 and b.count(255) == 0,
        ),
        Guard("len_le_64", "optimized for inputs <= 64 bytes", lambda b: len(b) <= 64),
        Guard("len_le_256", "optimized for inputs <= 256 bytes", lambda b: len(b) <= 256),
        Guard("len_le_1024", "optimized for inputs <= 1024 bytes", lambda b: len(b) <= 1024),
        Guard("len_le_4096", "optimized for inputs <= 4096 bytes", lambda b: len(b) <= 4096),
    )


def evaluate_dispatch(guard: Guard, observations: Iterable[Observation]) -> DispatchStats:
    rows = list(observations)
    if not rows:
        raise ValueError("no observations")
    dispatched: list[float] = []
    speedups: list[float] = []
    routed_speedups: list[float] = []
    routed = 0
    for observation in rows:
        if guard.fn(observation.data):
            routed += 1
            chosen = observation.opt_s
            routed_speedups.append(observation.speedup)
        else:
            chosen = observation.base_s
        dispatched.append(chosen)
        speedups.append(observation.base_s / chosen)
    ordered = sorted(speedups)
    return DispatchStats(
        guard=guard.name,
        inputs=len(rows),
        routed_to_optimized=routed,
        route_fraction=routed / len(rows),
        median_speedup=statistics.median(speedups),
        median_routed_speedup=(
            statistics.median(routed_speedups) if routed_speedups else 1.0
        ),
        p25_speedup=ordered[(len(ordered) - 1) // 4],
        worst_speedup=min(speedups),
        median_base_s=statistics.median(o.base_s for o in rows),
        median_dispatched_s=statistics.median(dispatched),
    )


def fit_guard(
    observations: Sequence[Observation],
    *,
    min_route: float = 0.10,
    min_worst_speedup: float = 1.0,
    min_median_speedup: float = 1.05,
) -> tuple[Guard, list[DispatchStats]]:
    """Pick the guard with the best (worst, median) speedup among eligible ones.

    A guard is eligible only if it routes at least ``min_route`` of the measured
    inputs to the optimized path, the measured worst case does not regress, and
    the median speedup *on the inputs it routes to the optimized path* clears
    ``min_median_speedup``.  The calibration corpus is adversarial and therefore
    not representative, so the routed median -- not the corpus-wide median -- is
    the benefit signal.  If nothing qualifies the policy is ``always_base``,
    i.e. the audit refuses the optimization.
    """
    guards = candidate_guards()
    stats = [evaluate_dispatch(guard, observations) for guard in guards]
    by_name = {guard.name: guard for guard in guards}
    eligible = [
        item
        for item in stats
        if item.route_fraction >= min_route
        and item.worst_speedup >= min_worst_speedup
        and item.median_routed_speedup >= min_median_speedup
    ]
    if not eligible:
        return by_name["always_base"], stats
    best = max(
        eligible,
        key=lambda item: (
            item.worst_speedup,
            item.median_routed_speedup,
            item.route_fraction,
        ),
    )
    return by_name[best.guard], stats


def guard_overhead_s(guard: Guard, data: bytes) -> float:
    """Median cost of one guard decision (feature extraction + compare)."""
    return measure(
        lambda b: guard.fn(b),
        data,
        warmup=2,
        repeats=7,
        min_sample_time=0.001,
    ).median_s
