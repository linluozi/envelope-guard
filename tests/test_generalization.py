import unittest

from envelope_guard.dispatch import evaluate_dispatch, fit_guard
from envelope_guard.search import minimize_witness, search_worst_case

TABLE = bytes(index ^ 0x33 for index in range(256))


def baseline(data: bytes) -> bytes:
    return bytes(byte ^ 0x33 for byte in data)


def optimized(data: bytes) -> bytes:
    if b"\x00\x00" in data:
        for _ in range(25):
            data.translate(TABLE)
    return data.translate(TABLE)


class GeneralizationTests(unittest.TestCase):
    def test_finds_and_contains_a_different_marker(self):
        result = search_worst_case(
            baseline,
            optimized,
            [b"hello", b"clean realistic text " * 8, b"\x00"],
            budget=400,
            seed=7,
        )
        witness, one_minimal, checks = minimize_witness(
            baseline, optimized, result.worst.data, threshold=0.4
        )
        # The opinion must be honest: it refuses (baseline) or contains the
        # regression; it must never unconditionally trust the fast path.
        guard, _ = fit_guard(result.observations)
        stats = evaluate_dispatch(guard, result.observations)
        self.assertNotEqual(guard.name, "always_opt")
        if guard.name != "always_base":
            self.assertGreaterEqual(stats.worst_speedup, 1.0)


if __name__ == "__main__":
    unittest.main()
