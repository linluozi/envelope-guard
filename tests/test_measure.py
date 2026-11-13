import unittest

from envelope_guard.measure import measure, percentile


class MeasureTests(unittest.TestCase):
    def test_percentile_endpoints(self):
        values = [1.0, 2.0, 3.0, 4.0]
        self.assertEqual(percentile(values, 0.0), 1.0)
        self.assertEqual(percentile(values, 1.0), 4.0)
        self.assertAlmostEqual(percentile(values, 0.5), 2.5)

    def test_summary_shape(self):
        summary = measure(bytes.upper, b"abcdef" * 1000, warmup=2, repeats=5)
        self.assertEqual(len(summary.samples), 5)
        self.assertGreater(summary.median_s, 0.0)
        self.assertLessEqual(summary.p25_s, summary.median_s)
        self.assertLessEqual(summary.median_s, summary.p75_s)
        self.assertGreaterEqual(summary.calls_per_sample, 1)
        self.assertGreaterEqual(summary.rsd, 0.0)
        self.assertLess(summary.rsd, 1.0)

    def test_repeats_must_be_at_least_two(self):
        with self.assertRaises(ValueError):
            measure(bytes.upper, b"x", repeats=1)


if __name__ == "__main__":
    unittest.main()
