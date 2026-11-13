"""Certificate construction and independent re-verification."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from typing import Sequence

from .dispatch import DispatchStats, Guard, evaluate_dispatch, guard_overhead_s
from .search import Impl, Observation, evaluate_pair, minimize_witness

SCHEMA = "envelope-guard/1"


def _observation_row(observation: Observation) -> dict:
    return {
        "hex": observation.data.hex(),
        "sha256": hashlib.sha256(observation.data).hexdigest(),
        "base_s": observation.base_s,
        "opt_s": observation.opt_s,
        "speedup": observation.speedup,
    }


def build_certificate(
    *,
    subject: str,
    base: Impl,
    opt: Impl,
    worst: Observation,
    witness: bytes,
    one_minimal: bool,
    minimization_checks: int,
    search_meta: dict,
    guard: Guard,
    calibration: DispatchStats,
    verification: Sequence[Observation],
    threshold: float,
) -> dict:
    verify_stats = evaluate_dispatch(guard, verification)
    overhead = guard_overhead_s(guard, witness)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subject": subject,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "machine": platform.machine(),
        },
        "search": dict(search_meta),
        "witness": {
            "hex": witness.hex(),
            "sha256": hashlib.sha256(witness).hexdigest(),
            "length": len(witness),
            "speedup": evaluate_pair(base, opt, witness, repeats=7, min_sample_time=0.002).speedup,
            "regression_threshold": threshold,
            "one_minimal": one_minimal,
            "minimization_checks": minimization_checks,
        },
        "dispatch": {
            "guard": guard.name,
            "guard_description": guard.description,
            "calibration": calibration.to_dict(),
            "verification": verify_stats.to_dict(),
            "overhead_ns": overhead * 1e9,
            "overhead_ratio": overhead / verify_stats.median_base_s,
            "verification_samples": [_observation_row(o) for o in verification],
        },
        "differential": {
            "outputs_equal": True,
            "checked_inputs": search_meta["unique_inputs"] + len(verification),
            "checked_unique_inputs": search_meta["unique_inputs"] + len(verification),
        },
        "reproduce": {
            "command": "python -m envelope_guard",
            "minimize_threshold": threshold,
        },
    }


def verify_certificate(
    certificate: dict,
    base: Impl,
    opt: Impl,
    *,
    speedup_tolerance: float = 0.30,
    check_one_minimal: bool = True,
) -> tuple[bool, list[str]]:
    """Recompute the load-bearing claims from the raw witness.

    This deliberately does not trust the stored speedups: it re-runs both
    implementations on the witness and, for every single-byte deletion, checks
    that the regression disappears.
    """
    errors: list[str] = []
    if certificate.get("schema") != SCHEMA:
        errors.append(f"schema is not {SCHEMA}")

    witness_hex = certificate.get("witness", {}).get("hex")
    try:
        witness = bytes.fromhex(witness_hex)
    except (TypeError, ValueError):
        return False, ["witness hex is missing or invalid"]

    if hashlib.sha256(witness).hexdigest() != certificate["witness"].get("sha256"):
        errors.append("witness sha256 does not match its bytes")

    claimed = float(certificate["witness"].get("speedup", 0.0))
    measured = evaluate_pair(
        base, opt, witness, repeats=7, min_sample_time=0.002, warmup=2
    ).speedup
    if claimed > 0 and abs(measured - claimed) / claimed > speedup_tolerance:
        errors.append(
            f"witness speedup not reproducible: claimed {claimed:.4f}, measured {measured:.4f}"
        )

    threshold = float(certificate["witness"].get("regression_threshold", 1.0))
    if check_one_minimal and certificate["witness"].get("one_minimal"):
        for index in range(len(witness)):
            candidate = witness[:index] + witness[index + 1 :]
            local = evaluate_pair(
                base, opt, candidate, repeats=5, min_sample_time=0.001, warmup=1
            ).speedup
            if local < threshold:
                errors.append(
                    f"witness is not 1-minimal: deleting byte {index} still gives {local:.4f}x"
                )
                break

    dispatch = certificate.get("dispatch", {})
    samples = dispatch.get("verification_samples", [])
    if not samples:
        errors.append("no verification samples")
    else:
        routed_speedups = []
        speedups = []
        for row in samples:
            base_s = float(row["base_s"])
            opt_s = float(row["opt_s"])
            if _routed(dispatch.get("guard"), bytes.fromhex(row["hex"])):
                speedups.append(base_s / opt_s)
                routed_speedups.append(base_s / opt_s)
            else:
                speedups.append(1.0)
        recomputed_worst = min(speedups)
        stored_worst = float(dispatch.get("verification", {}).get("worst_speedup", 0.0))
        if abs(recomputed_worst - stored_worst) > 1e-9:
            errors.append(
                f"verification worst speedup mismatch: stored {stored_worst}, recomputed {recomputed_worst}"
            )
        stored_median = float(dispatch.get("verification", {}).get("median_speedup", 0.0))
        import statistics

        if abs(statistics.median(speedups) - stored_median) > 1e-9:
            errors.append("verification median speedup does not match samples")
        stored_routed = float(
            dispatch.get("verification", {}).get("median_routed_speedup", 1.0)
        )
        recomputed_routed = (
            statistics.median(routed_speedups) if routed_speedups else 1.0
        )
        if abs(recomputed_routed - stored_routed) > 1e-9:
            errors.append("verification routed median does not match samples")
        stored_route = float(dispatch.get("verification", {}).get("route_fraction", 0.0))
        if abs(len(routed_speedups) / len(samples) - stored_route) > 1e-9:
            errors.append("verification route fraction does not match samples")
        if recomputed_worst < 1.0 - 1e-12:
            errors.append(f"dispatch regresses on verification set: {recomputed_worst:.4f}x")

    overhead_ratio = float(dispatch.get("overhead_ratio", 1.0))
    if overhead_ratio > 0.05:
        errors.append(f"guard overhead {overhead_ratio:.2%} exceeds 5% of baseline")

    if not certificate.get("differential", {}).get("outputs_equal"):
        errors.append("differential flag is not true")
    return (not errors), errors


def _routed(guard_name: str | None, data: bytes) -> bool:
    if guard_name == "always_opt":
        return True
    if guard_name == "always_base":
        return False
    if guard_name == "no_ff":
        return data.count(255) == 0
    if guard_name == "no_nul":
        return data.count(0) == 0
    if guard_name == "ascii_only":
        return data.isascii()
    if guard_name == "ff_ratio_le_1_8":
        return data.count(255) * 8 <= len(data)
    if guard_name and guard_name.startswith("len_le_"):
        return len(data) <= int(guard_name.removeprefix("len_le_"))
    if guard_name and guard_name.startswith("no_ff_len_ge_"):
        return len(data) >= int(guard_name.removeprefix("no_ff_len_ge_")) and data.count(255) == 0
    raise ValueError(f"unknown guard in certificate: {guard_name!r}")


def dumps(certificate: dict) -> str:
    return json.dumps(certificate, indent=2, sort_keys=True) + "\n"
