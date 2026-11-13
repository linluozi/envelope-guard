"""A realistic case study: auditing a fast path that is genuinely faster on
realistic inputs but has a hidden worst-case regression.

The subject is deliberately planted (it is a *case study*, not a claim about
any third-party library): a C-level ``bytes.translate`` fast path that is
~several times faster than a plain loop on realistic text, except for a rare
two-byte pattern (``0xff 0xff``) that triggers a slow branch.  The envelope
audit must find that pattern, minimize it, and contain it with a guard so the
worst case never bends below the baseline.
"""

from __future__ import annotations

import random

from .measure import measure

XOR_TABLE = bytes(index ^ 0x5A for index in range(256))
SLOW_MARKER = b"\xff\xff"

# Realistic-ish engineering corpus: ASCII log lines with the occasional
# binary escape, comment block, or the rare slow marker.
_LOG_LINES = [
    b"2026-11-14T00:00:00Z INFO  worker-12 processed 4096 records",
    b"2026-11-14T00:00:00Z WARN  partition offset 0 retained 90.2% of bytes",
    b"         at java.base/jdk.internal.util.ArraysSupport.vectorizedMismatch",
    b"panic: runtime error: index out of range [42] with length 41",
    b"#[0/15] allocating 2048 MiB for output tensor on device cuda:0",
    b"deploy branch=main sha=9f8612c7 preview=false region=us-west-2",
    b"cfg path=/etc/app/app.toml enabled=true replicas=3 autoscaler=on",
    b"INFO  gc: young=128MB old=512MB used_ratio=0.41 pause_ms=3.2",
    b"      buffer=[..55..]  cp_norm=0.99942 grad_norm=1.207e+01",
    b"security: denied token expiry=+1d scope=read:status ip=10.8.0.9",
    b'trace_id=0x9f2c1a user="alice" action="edit" status=200 dur=12ms',
    b"------------------ iteration 2000 / 2000 ------------------",
    b"WARN  connection pool exhausted; backing off 750ms (retries=12)",
    b"ERROR database 'orders' unavailable: connection refused (111)",
    b"note: the following backing up of the index will NOT be atomic",
    b"out: 'key' value 1234.5678 dtype=float64 shape=(2, 3, 4)",
]


def realistic_corpus(*, target_bytes: int, seed: int, marker_rate: float = 0.0) -> bytes:
    """A single document of roughly ``target_bytes`` mixing log lines.

    Most bytes are the clean ASCII log corpus; a small fraction of lines carry
    the slow marker so the corpus is not pathological-free.
    """
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < target_bytes:
        line = b"\n" + (_LOG_LINES[rng.randrange(len(_LOG_LINES))] + b"\n")
        if rng.random() < marker_rate and len(out) + 32 < target_bytes:
            out.extend(SLOW_MARKER)
            out.extend(line[: len(line) // 2])
            continue
        out.extend(line[: max(1, min(len(line), target_bytes - len(out)))])
    return bytes(out[:target_bytes])


def baseline(data: bytes) -> bytes:
    """Reference path: a plain Python loop (intentionally slow)."""
    return bytes(byte ^ 0x5A for byte in data)


def optimized(data: bytes) -> bytes:
    """Fast path: C-level translate; slow branch only on 0xff 0xff."""
    if SLOW_MARKER in data:
        for _ in range(40):
            data.translate(XOR_TABLE)
    return data.translate(XOR_TABLE)


def _guard_no_ff_len64(data: bytes) -> bool:
    return len(data) >= 64 and data.count(255) == 0


def dispatch(baseline_fn, optimized_fn, guard_fn, data: bytes) -> bytes:
    """Run the audited dispatch policy."""
    if guard_fn(data):
        return optimized_fn(data)
    return baseline_fn(data)


def bench_dispatch_components(
    *,
    sizes: tuple[tuple[str, int], ...],
    per_size: int = 6,
    seed: int = 20261114,
):
    """Time baseline, unconditional-optimized and guarded dispatch per size.

    Returns a list of dicts with per-size medians.
    """
    rows = []
    for label, size in sizes:
        docs = [realistic_corpus(target_bytes=size, seed=seed + i) for i in range(per_size)]
        base_s, opt_s, guarded_s = [], [], []
        for data in docs:
            base_s.append(measure(baseline, data, warmup=2, repeats=5).median_s)
            opt_s.append(measure(optimized, data, warmup=2, repeats=5).median_s)
            guarded_s.append(
                measure(
                    lambda b: dispatch(baseline, optimized, _guard_no_ff_len64, b),
                    data,
                    warmup=2,
                    repeats=5,
                ).median_s
            )
        base_median = _median(base_s)
        opt_median = _median(opt_s)
        guarded_median = _median(guarded_s)
        worst_naive = _min_ratio(base_s, opt_s)
        worst_guarded = _min_ratio(base_s, guarded_s)
        rows.append(
            {
                "size": label,
                "bytes": size,
                "docs": per_size,
                "baseline_median_s": base_median,
                "opt_median_s": opt_median,
                "guarded_median_s": guarded_median,
                "naive_median_speedup": base_median / opt_median,
                "guarded_median_speedup": base_median / guarded_median,
                "naive_worst_speedup": worst_naive,
                "guarded_worst_speedup": worst_guarded,
                "per_doc": [
                    {"base_s": b, "opt_s": o, "guarded_s": g}
                    for b, o, g in zip(base_s, opt_s, guarded_s)
                ],
            }
        )
    return rows


def _median(values):
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def _min_ratio(base, other):
    return min(b / o for b, o in zip(base, other))