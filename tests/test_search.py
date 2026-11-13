import hashlib
import unittest

from envelope_guard.demo import baseline, optimized
from envelope_guard.search import (
    OutputMismatch,
    evaluate_pair,
    minimize_witness,
    search_worst_case,
)

SEEDS = [b"hello world", b"abc" * 50, b"0123456789" * 20, b"\xff"]


class SearchTests(unittest.TestCase):
    def test_finds_planted_regression_and_minimizes_it(self):
        result = search_worst_case(
            baseline, optimized, SEEDS, budget=160, seed=20261114
        )
        self.assertEqual(result.evaluations, result.unique_inputs)
        self.assertLess(result.worst.speedup, 0.8)

        witness, one_minimal, checks = minimize_witness(
            baseline, optimized, result.worst.data, threshold=0.6
        )
        self.assertTrue(one_minimal)
        self.assertGreater(checks, 0)
        self.assertIn(b"\xff\xff", witness)
        self.assertLessEqual(len(witness), 4)

        # Every remaining single-byte deletion must lose the regression.
        for index in range(len(witness)):
            candidate = witness[:index] + witness[index + 1 :]
            observation = evaluate_pair(
                baseline, optimized, candidate, repeats=5, min_sample_time=0.001
            )
            self.assertGreaterEqual(observation.speedup, 0.6)

    def test_deduplicates_candidates(self):
        result = search_worst_case(
            baseline, optimized, SEEDS, budget=40, seed=7
        )
        hashes = [hashlib.sha256(observation.data).hexdigest() for observation in result.observations]
        self.assertEqual(len(hashes), len(set(hashes)))
        self.assertEqual(result.evaluations, result.unique_inputs)

    def test_output_mismatch_is_never_timed_as_a_speedup(self):
        def broken(data):
            return data + b"!"

        with self.assertRaises(OutputMismatch):
            evaluate_pair(baseline, broken, b"payload")


if __name__ == "__main__":
    unittest.main()
