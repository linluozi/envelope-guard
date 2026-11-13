import hashlib
import random
import unittest

from envelope_guard.demo import baseline, optimized

BOUNDARY_CASES = [
    b"",
    b"\x00",
    b"\xff",
    b"\xff\xff",
    b"\xff\xff\xff",
    bytes(range(256)),
    b"A" * 65536,
    b"\xff\xff" + b"middle" + b"\xff\xff",
    b"\x00" * 4096,
    ("emoji \U0001f600 mixed \u4e2d\u6587").encode("utf-8"),
]


class DifferentialTests(unittest.TestCase):
    def test_boundary_cases_are_byte_identical(self):
        for data in BOUNDARY_CASES:
            self.assertEqual(baseline(data), optimized(data))

    def test_every_byte_value(self):
        for value in range(256):
            data = bytes([value])
            self.assertEqual(baseline(data), optimized(data))

    def test_1200_unique_random_inputs(self):
        rng = random.Random(20261114)
        seen: dict[str, bytes] = {}
        for data in BOUNDARY_CASES:
            seen[hashlib.sha256(data).hexdigest()] = data
        while len(seen) < 1200:
            length = rng.choice([0, 1, 2, 3, 8, 17, 64, 255, 1024, 4096])
            if rng.random() < 0.35:
                marker = b"\xff\xff"
                head = bytes(rng.randrange(256) for _ in range(length // 2))
                tail = bytes(rng.randrange(256) for _ in range(length - length // 2))
                data = head + marker + tail
            else:
                data = bytes(rng.randrange(256) for _ in range(length))
            seen[hashlib.sha256(data).hexdigest()] = data
        self.assertEqual(len(seen), 1200)
        for data in seen.values():
            self.assertEqual(
                hashlib.sha256(baseline(data)).digest(),
                hashlib.sha256(optimized(data)).digest(),
            )


if __name__ == "__main__":
    unittest.main()
