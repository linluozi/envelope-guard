"""Builds benchmark/baseline.json and benchmark/optimized.json for the README.

Baseline = reference path always (the call site has no fast path).
Optimized = audited dispatch policy (guard + fast path + fallback).

Runs on a realistic multi-document corpus, dropping raw samples and the full
certificate alongside CSScription.log.
"""

from __future__ import annotations

import json
import platform
import resource
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from envelope_guard.case_study import (
    baseline,
    dispatch,
    _guard_no_ff_len64,
    optimized,
    realistic_corpus,
)
from envelope_guard.measure import measure

SIZES = [
    ("small", 64 * 1024),
    ("medium", 512 * 1024),
    ("large", 2 * 1024 * 1024),
]
PER_SIZE = 6
SEED = 20261114


def env_block() -> dict:
    cpu = ""
    try:
        cpu = subprocess.run(["lscpu"], capture_output=True, text=True).stdout
    except Exception:
        pass
    cpu_model = ""
    for line in cpu.splitlines():
        if line.strip().startswith("Model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    return {
        "cpu_model": cpu_model,
        "memory_mb":
            int(subprocess.run(["free", "-m"], capture_output=True, text=True)
                .stdout.splitlines()[1].split()[1]),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "seed": SEED,
        "timing": "time.perf_counter",
        "warmup": 3,
        "repeats": 5,
    }


def run() -> None:
    raw_dir = ROOT / "benchmark" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    docs_by_size = {
        label: [
            realistic_corpus(target_bytes=size, seed=SEED + i)
            for i in range(PER_SIZE)
        ]
        for label, size in SIZES
    }
    # Persist one corpus for reproducibility and strip the slow-branch doubt.
    corpus_path = ROOT / "benchmark" / "corpus.json"
    corpus_path.write_text(
        json.dumps(
            {label: [d.hex() for d in docs] for label, docs in docs_by_size.items()}
        )
    )

    def one(label: str, size_ref: int) -> tuple[dict, dict]:
        baseline_rows, opt_rows = [], []
        for i, data in enumerate(docs_by_size[label]):
            b = measure(baseline, data, warmup=3, repeats=5)
            g = measure(
                lambda d: dispatch(baseline, optimized, _guard_no_ff_len64, d),
                data,
                warmup=3,
                repeats=5,
            )
            baseline_rows.append({"doc": i, "median_s": b.median_s, "samples": b.samples})
            opt_rows.append({"doc": i, "median_s": g.median_s, "samples": g.samples})
            raw_dir.joinpath(f"baseline-{label}-{i}.json").write_text(
                json.dumps({"median_s": b.median_s, "samples_s": b.samples})
            )
            raw_dir.joinpath(f"optimized-{label}-{i}.json").write_text(
                json.dumps({"median_s": g.median_s, "samples_s": g.samples})
            )
        bmed = _median([r["median_s"] for r in baseline_rows])
        gmed = _median([r["median_s"] for r in opt_rows])
        return (
            {
                "size": label,
                "bytes": size_ref,
                "docs": PER_SIZE,
                "median_s": bmed,
                "per_doc": baseline_rows,
            },
            {
                "size": label,
                "bytes": size_ref,
                "docs": PER_SIZE,
                "median_s": gmed,
                "median_speedup": bmed / gmed,
                "per_doc": opt_rows,
            },
        )

    baseline_output = {"environment": env_block(), "sizes": {}}
    optimized_output = {"environment": env_block(), "sizes": {}}
    getrss = resource.getrusage(resource.RUSAGE_SELF)
    baseline_output["peak_rss_kb"] = getrss.ru_maxrss
    for label, size in SIZES:
        b, o = one(label, size)
        baseline_output["sizes"][label] = b
        optimized_output["sizes"][label] = o
    optimized_output["peak_rss_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    (ROOT / "benchmark" / "baseline.json").write_text(json.dumps(baseline_output, indent=2))
    (ROOT / "benchmark" / "optimized.json").write_text(json.dumps(optimized_output, indent=2))
    #
    for label in baseline_output["sizes"]:
        o = optimized_output["sizes"][label]
        print(f"  {label}: baseline {bmed_s(baseline_output, label):.6f}s "
              f"optimized {o['median_s']:.6f}s "
              f"speedup {o['median_speedup']:.3f}x")


def bmed_s(blob: dict, label: str) -> float:
    return blob["sizes"][label]["median_s"]


def _median(values):
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


if __name__ == "__main__":
    run()