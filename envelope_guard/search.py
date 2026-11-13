"""Adversarial search for inputs where an "optimized" path loses.

The search is a deterministic, seeded hill-climb over bytes.  Every candidate
is executed through both implementations and their outputs are compared
byte-for-byte before the candidate is timed, so a divergence can never be
mistaken for a speedup.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from .measure import measure

Impl = Callable[[bytes], bytes]

# Bytes that commonly trigger parser branches, plus 0x00/0xff boundaries.
BOUNDARY = b"\x00\xff\n\r\t <>&%\"'/"
MAX_SEARCH_BYTES = 64 * 1024


class OutputMismatch(AssertionError):
    """Raised when the two implementations disagree on a candidate."""


@dataclass(frozen=True)
class Observation:
    data: bytes
    base_s: float
    opt_s: float
    speedup: float
    output_sha256: str

    def to_dict(self, *, include_data: bool = False) -> dict:
        out = {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "length": len(self.data),
            "base_s": self.base_s,
            "opt_s": self.opt_s,
            "speedup": self.speedup,
            "output_sha256": self.output_sha256,
        }
        if include_data:
            out["hex"] = self.data.hex()
        return out


@dataclass(frozen=True)
class SearchResult:
    observations: tuple[Observation, ...]
    worst: Observation
    evaluations: int
    unique_inputs: int
    seed: int
    budget: int

    def to_dict(self, *, include_data: bool = False) -> dict:
        return {
            "budget": self.budget,
            "evaluations": self.evaluations,
            "unique_inputs": self.unique_inputs,
            "seed": self.seed,
            "worst": self.worst.to_dict(include_data=include_data),
            "observations": [
                o.to_dict(include_data=include_data) for o in self.observations
            ],
        }


def evaluate_pair(
    base: Impl,
    opt: Impl,
    data: bytes,
    *,
    repeats: int = 3,
    min_sample_time: float = 0.0005,
    warmup: int = 1,
) -> Observation:
    base_out = base(data)
    opt_out = opt(data)
    if base_out != opt_out:
        raise OutputMismatch(
            f"outputs differ on {len(data)}-byte input "
            f"sha256={hashlib.sha256(data).hexdigest()}"
        )
    base_summary = measure(
        base,
        data,
        warmup=warmup,
        repeats=repeats,
        min_sample_time=min_sample_time,
    )
    opt_summary = measure(
        opt,
        data,
        warmup=warmup,
        repeats=repeats,
        min_sample_time=min_sample_time,
    )
    return Observation(
        data=data,
        base_s=base_summary.median_s,
        opt_s=opt_summary.median_s,
        speedup=base_summary.median_s / opt_summary.median_s,
        output_sha256=hashlib.sha256(base_out).hexdigest(),
    )


def mutate(data: bytes, rng: random.Random, *, max_len: int = MAX_SEARCH_BYTES) -> bytes:
    """One structural mutation; deterministic for a given rng state."""
    buf = bytearray(data)
    op = rng.randrange(9)
    if op == 0 and buf:
        buf[rng.randrange(len(buf))] = rng.choice(BOUNDARY)
    elif op == 1 and buf:
        index = rng.randrange(len(buf))
        buf[index] ^= 1 << rng.randrange(8)
    elif op == 2 and len(buf) < max_len:
        buf.insert(rng.randrange(len(buf) + 1), rng.choice(BOUNDARY))
    elif op == 3 and len(buf) > 1:
        start = rng.randrange(len(buf))
        end = min(len(buf), start + rng.randint(1, max(1, len(buf) // 4)))
        del buf[start:end]
    elif op == 4 and buf and len(buf) < max_len:
        start = rng.randrange(len(buf))
        end = min(len(buf), start + rng.randint(1, 64))
        chunk = bytes(buf[start:end])
        at = rng.randrange(len(buf) + 1)
        buf[at:at] = chunk[: max_len - len(buf)]
    elif op == 5 and len(buf) < max_len:
        count = min(rng.randint(1, 64), max_len - len(buf))
        buf.extend(bytes(rng.choice(BOUNDARY) for _ in range(count)))
    elif op == 6 and buf and len(buf) < max_len:
        # Grow a run: append copies of a byte already present in the input.
        byte = buf[rng.randrange(len(buf))]
        count = min(rng.randint(2, 256), max_len - len(buf))
        buf.extend(bytes([byte]) * count)
    elif op == 7 and buf:
        start = rng.randrange(len(buf))
        end = min(len(buf), start + rng.randint(1, 64))
        buf[start:end] = bytes([rng.choice(BOUNDARY)]) * (end - start)
    elif op == 8 and len(buf) < max_len:
        byte = rng.choice(BOUNDARY)
        buf.extend(bytes([byte]) * min(rng.randint(1, 64), max_len - len(buf)))
    return bytes(buf[:max_len])


def search_worst_case(
    base: Impl,
    opt: Impl,
    seeds: Iterable[bytes],
    *,
    budget: int = 400,
    seed: int = 20261114,
    repeats: int = 3,
    min_sample_time: float = 0.0005,
) -> SearchResult:
    """Search for the lowest base/opt speedup over a deduplicated input set.

    ``budget`` counts *evaluated unique candidates*, not loop iterations.
    Duplicate candidates are skipped by sha256 and are not counted.
    """
    if budget < 1:
        raise ValueError("budget must be positive")
    rng = random.Random(seed)
    corpus: list[bytes] = []
    seen: set[str] = set()
    observations: list[Observation] = []

    def add(data: bytes) -> bool:
        if len(data) > MAX_SEARCH_BYTES:
            return False
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            return False
        seen.add(digest)
        corpus.append(data)
        return True

    for item in seeds:
        add(bytes(item))
    add(b"")

    for data in corpus:
        observation = evaluate_pair(
            base,
            opt,
            data,
            repeats=repeats,
            min_sample_time=min_sample_time,
        )
        observations.append(observation)

    evaluations = len(corpus)
    while evaluations < budget:
        if rng.random() < 0.65 or len(observations) < 5:
            parent = corpus[rng.randrange(len(corpus))]
        else:
            ranked = sorted(observations, key=lambda o: o.speedup)
            parent = ranked[rng.randrange(min(5, len(ranked)))].data
        candidate = mutate(parent, rng)
        digest = hashlib.sha256(candidate).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        corpus.append(candidate)
        observation = evaluate_pair(
            base,
            opt,
            candidate,
            repeats=repeats,
            min_sample_time=min_sample_time,
        )
        observations.append(observation)
        evaluations += 1

    # Re-time the five worst candidates with more repeats before declaring one
    # the witness; a single noisy sample must not become a certificate.
    ranked = sorted(observations, key=lambda o: o.speedup)[:5]
    for observation in ranked:
        refined = evaluate_pair(
            base,
            opt,
            observation.data,
            repeats=7,
            min_sample_time=0.002,
            warmup=2,
        )
        observations[observations.index(observation)] = refined
    worst = min(observations, key=lambda o: o.speedup)
    return SearchResult(
        observations=tuple(observations),
        worst=worst,
        evaluations=evaluations,
        unique_inputs=len(seen),
        seed=seed,
        budget=budget,
    )


def minimize_witness(
    base: Impl,
    opt: Impl,
    data: bytes,
    *,
    threshold: float = 0.9,
    repeats: int = 5,
    min_sample_time: float = 0.001,
    max_one_minimal_bytes: int = 512,
) -> tuple[bytes, bool, int]:
    """Delete chunks while ``speedup < threshold`` holds, then bytes.

    Returns ``(witness, one_minimal, checks)``.  ``one_minimal`` is only claimed
    after every remaining single-byte deletion has been measured and rejected.
    """

    def is_bad(candidate: bytes) -> bool:
        observation = evaluate_pair(
            base,
            opt,
            candidate,
            repeats=repeats,
            min_sample_time=min_sample_time,
        )
        return observation.speedup < threshold

    if not is_bad(data):
        return data, False, 0
    checks = 0
    current = data
    chunks = 2
    while len(current) > 1:
        chunk_size = max(1, len(current) // chunks)
        removed = False
        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size :]
            checks += 1
            if is_bad(candidate):
                current = candidate
                chunks = max(2, chunks - 1)
                removed = True
                break
        if not removed:
            if chunks >= len(current):
                break
            chunks = min(len(current), chunks * 2)

    one_minimal = False
    if len(current) <= max_one_minimal_bytes:
        changed = True
        while changed:
            changed = False
            for index in range(len(current)):
                candidate = current[:index] + current[index + 1 :]
                checks += 1
                if is_bad(candidate):
                    current = candidate
                    changed = True
                    break
        one_minimal = True
    return current, one_minimal, checks
