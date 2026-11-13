"""Audit your own (baseline, optimized) pair with envelope_guard.

Run: python3 examples/audit_pair.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from envelope_guard import evaluate_dispatch, fit_guard, minimize_witness, search_worst_case


TABLE = bytes(index ^ 0x33 for index in range(256))


def baseline(data: bytes) -> bytes:
    return bytes(byte ^ 0x33 for byte in data)


def optimized(data: bytes) -> bytes:
    # A planted regression: the fast branch is slow when 0x00 0x00 is present.
    if b"\x00\x00" in data:
        for _ in range(25):
            data.translate(TABLE)
    return data.translate(TABLE)


result = search_worst_case(
    baseline,
    optimized,
    [b"hello", b"clean realistic text " * 8, b"\x00"],
    budget=250,
    seed=7,
)
witness, one_minimal, checks = minimize_witness(
    baseline, optimized, result.worst.data, threshold=0.4
)
guard, _ = fit_guard(result.observations)
stats = evaluate_dispatch(guard, result.observations)
print(f"worst={result.worst.speedup:.4f}x witness={witness.hex()} 1-minimal={one_minimal} checks={checks}")
print(f"guard={guard.name} worst-after-dispatch={stats.worst_speedup:.4f}x route={stats.route_fraction:.2%}")
