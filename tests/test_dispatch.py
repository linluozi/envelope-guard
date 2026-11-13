import unittest

from envelope_guard.dispatch import evaluate_dispatch, fit_guard, guard_overhead_s
from envelope_guard.search import Observation


def observation(data: bytes, base_s: float, opt_s: float) -> Observation:
    return Observation(
        data=data,
        base_s=base_s,
        opt_s=opt_s,
        speedup=base_s / opt_s,
        output_sha256="00" * 32,
    )


class DispatchTests(unittest.TestCase):
    def test_fit_prefers_a_guard_that_removes_the_regression(self):
        rows = [
            observation(b"clean text " * 10, 50e-6, 5e-6),
            observation(b"clean ascii", 20e-6, 2e-6),
            observation(b"\xff\xff" + b"x" * 100, 60e-6, 300e-6),
            observation(b"abc\xff\xffdef", 10e-6, 40e-6),
        ]
        guard, table = fit_guard(rows)
        stats = evaluate_dispatch(guard, rows)
        self.assertGreaterEqual(stats.worst_speedup, 1.0)
        self.assertGreater(stats.median_speedup, 1.05)
        self.assertGreater(stats.route_fraction, 0.2)
        self.assertIn("no_ff", guard.name)
        self.assertEqual(len(table), 13)

    def test_fit_refuses_when_every_input_is_slower(self):
        rows = [observation(b"a" * 10, 10e-6, 20e-6) for _ in range(3)]
        guard, _ = fit_guard(rows)
        self.assertEqual(guard.name, "always_base")
        self.assertEqual(evaluate_dispatch(guard, rows).worst_speedup, 1.0)

    def test_guard_overhead_is_bounded(self):
        guard = next(g for g in __import__("envelope_guard").candidate_guards() if g.name == "no_ff")
        overhead = guard_overhead_s(guard, b"x" * 4096)
        self.assertGreater(overhead, 0.0)
        self.assertLess(overhead, 1e-3)


if __name__ == "__main__":
    unittest.main()
