"""A planted subject used to validate the audit pipeline end to end.

The subject is *deliberately faulty*: ``optimized`` takes a slow branch whenever
the two-byte sequence ``0xff 0xff`` is present.  The audit must (a) find it,
(b) minimize it to a 1-minimal witness, and (c) build a guard that removes the
regression.  This is a pipeline test, not a performance claim about any library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys

from .certificate import build_certificate, dumps, verify_certificate
from .dispatch import evaluate_dispatch, fit_guard
from .search import (
    MAX_SEARCH_BYTES,
    evaluate_pair,
    minimize_witness,
    mutate,
    search_worst_case,
)

SUBJECT = "planted-xor-ff-ff-regression"
XOR_TABLE = bytes(index ^ 0x5A for index in range(256))
SLOW_MARKER = b"\xff\xff"


def baseline(data: bytes) -> bytes:
    """Reference path: a plain Python loop (intentionally unoptimized)."""
    return bytes(byte ^ 0x5A for byte in data)


def optimized(data: bytes) -> bytes:
    """Fast path: C-level translate, with a planted slow branch on 0xff 0xff."""
    if SLOW_MARKER in data:
        for _ in range(40):
            data.translate(XOR_TABLE)
    return data.translate(XOR_TABLE)


def build_verification_set(seed: int, count: int = 48) -> list[bytes]:
    """Inputs generated with a different RNG stream than the search."""
    rng = random.Random(seed)
    seeds = [b"hello world", b"abc" * 50, b"0123456789" * 20, b""]
    seen: set[str] = set()
    out: list[bytes] = [b"", SLOW_MARKER, b"clean ascii input"]
    for item in out:
        seen.add(hashlib.sha256(item).hexdigest())
    while len(out) < count:
        parent = seeds[rng.randrange(len(seeds))]
        candidate = parent
        for _ in range(rng.randint(1, 3)):
            candidate = mutate(candidate, rng, max_len=4096)
        digest = hashlib.sha256(candidate).hexdigest()
        if digest in seen or len(candidate) > MAX_SEARCH_BYTES:
            continue
        seen.add(digest)
        out.append(candidate)
    return out


def run_demo(*, budget: int = 400, seed: int = 20261114, threshold: float = 0.6) -> dict:
    # Generic boundary seeds; none of them contains the two-byte slow marker.
    seeds = [
        b"hello world",
        b"abc" * 50,
        b"0123456789" * 20,
        b"\x00",
        b"\xff",
        b"\n",
        b"\r",
        b"\x00\xff\n\r",
    ]
    search = search_worst_case(
        baseline,
        optimized,
        seeds,
        budget=budget,
        seed=seed,
        repeats=3,
        min_sample_time=0.0005,
    )
    witness, one_minimal, checks = minimize_witness(
        baseline,
        optimized,
        search.worst.data,
        threshold=threshold,
        repeats=5,
        min_sample_time=0.001,
    )
    verification_set = build_verification_set(seed + 1)
    verification = [
        evaluate_pair(
            baseline, optimized, item, repeats=5, min_sample_time=0.001
        )
        for item in verification_set
    ]
    guard, guard_table = fit_guard(search.observations)
    calibration = evaluate_dispatch(guard, search.observations)
    certificate = build_certificate(
        subject=SUBJECT,
        base=baseline,
        opt=optimized,
        worst=search.worst,
        witness=witness,
        one_minimal=one_minimal,
        minimization_checks=checks,
        search_meta={
            "budget": search.budget,
            "evaluations": search.evaluations,
            "unique_inputs": search.unique_inputs,
            "seed": search.seed,
            "worst_before_minimization": search.worst.to_dict(include_data=True),
            "candidate_guards": [row.to_dict() for row in guard_table],
        },
        guard=guard,
        calibration=calibration,
        verification=verification,
        threshold=threshold,
    )
    ok, errors = verify_certificate(certificate, baseline, optimized)
    certificate["self_check"] = {"verified": ok, "errors": errors}
    if not ok:
        raise SystemExit("certificate self-check failed: " + "; ".join(errors))
    return certificate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="envelope_guard")
    parser.add_argument("--budget", type=int, default=400)
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--out", default="certificate.json")
    args = parser.parse_args(argv)

    certificate = run_demo(
        budget=args.budget, seed=args.seed, threshold=args.threshold
    )
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(dumps(certificate))
    witness = certificate["witness"]
    dispatch = certificate["dispatch"]
    search = certificate["search"]
    print(f"subject: {certificate['subject']}")
    print(
        f"search: {search['evaluations']} evaluations, "
        f"{search['unique_inputs']} unique inputs, "
        f"worst {search['worst_before_minimization']['speedup']:.4f}x"
    )
    print(
        f"witness: {witness['hex'] or '<empty>'} ({witness['length']} bytes), "
        f"{witness['speedup']:.4f}x, 1-minimal={witness['one_minimal']}, "
        f"checks={witness['minimization_checks']}"
    )
    print(
        f"dispatch: {dispatch['guard']} routes "
        f"{dispatch['calibration']['route_fraction']:.1%} to optimized; "
        f"calibration worst {dispatch['calibration']['worst_speedup']:.4f}x"
    )
    print(
        f"verification: {dispatch['verification']['inputs']} inputs, "
        f"median {dispatch['verification']['median_speedup']:.4f}x, "
        f"worst {dispatch['verification']['worst_speedup']:.4f}x"
    )
    print(
        f"guard overhead: {dispatch['overhead_ns']:.1f} ns "
        f"({dispatch['overhead_ratio']:.4%} of median baseline)"
    )
    print(f"certificate: {args.out}")
    print(f"self-check: {'PASS' if certificate['self_check']['verified'] else 'FAIL'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
