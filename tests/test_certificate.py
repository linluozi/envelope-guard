import unittest

from envelope_guard.certificate import SCHEMA, dumps, verify_certificate
from envelope_guard.demo import baseline, optimized, run_demo


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificate = run_demo(budget=200, seed=20261114)

    def test_self_check_passes(self):
        ok, errors = verify_certificate(self.certificate, baseline, optimized)
        self.assertTrue(ok, errors)

    def test_witness_is_one_minimal_and_two_bytes(self):
        witness = self.certificate["witness"]
        self.assertTrue(witness["one_minimal"])
        self.assertEqual(witness["hex"], "ffff")
        self.assertEqual(witness["length"], 2)

    def test_tampered_speedup_is_rejected(self):
        import copy

        tampered = copy.deepcopy(self.certificate)
        tampered["witness"]["speedup"] = 99.0
        ok, errors = verify_certificate(tampered, baseline, optimized)
        self.assertFalse(ok)
        self.assertTrue(any("not reproducible" in error for error in errors))

    def test_tampered_dispatch_median_is_rejected(self):
        import copy
        import json

        tampered = copy.deepcopy(self.certificate)
        tampered["dispatch"]["verification"]["median_speedup"] = 123.0
        ok, errors = verify_certificate(tampered, baseline, optimized)
        self.assertFalse(ok)
        self.assertTrue(any("median" in error for error in errors))

    def test_schema_and_serialization_roundtrip(self):
        import json

        self.assertEqual(self.certificate["schema"], SCHEMA)
        loaded = json.loads(dumps(self.certificate))
        self.assertEqual(loaded["witness"]["hex"], "ffff")
        self.assertTrue(loaded["self_check"]["verified"])


if __name__ == "__main__":
    unittest.main()
