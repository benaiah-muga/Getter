#!/usr/bin/env python3
"""Generate a trusted getter.job/v1 for the sum-squares example workload.

The trusted reference below uses the closed-form sum-of-squares identity, while
the Rust guest iterates over every integer in each partition. The two independent
methods must produce the same exact canonical bytes, which are hashed here. This
also keeps job generation fast for large recovery-test partitions.

The artifact must exist and is validated before the job is written:

* SHA-256 is computed (and optionally checked against --expected-sha256).
* The file must be a WebAssembly 1.0 module.
* It must have no imports and export memory, getter_alloc, and getter_execute.

Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Sequence

EXAMPLE_DIR = Path(__file__).resolve().parent
MAX_U128 = (1 << 128) - 1

REQUIREMENTS = {
    "cpu_slots": 1,
    "memory_bytes": 67_108_864,
    "output_bytes": 1_048_576,
    "fuel": 5_000_000_000,
}
MAX_ATTEMPTS = 3
REQUIRED_EXPORTS = ("memory", "getter_alloc", "getter_execute")

# Export kinds from the WebAssembly module format.
_EXPORT_KINDS = {0: "function", 1: "table", 2: "memory", 3: "global", 4: "tag"}


def positive_int(text: str) -> int:
    """argparse converter for integers greater than zero."""
    try:
        value = int(text, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {value}")
    return value


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a deterministic getter.job/v1 with trusted sum-of-squares "
            "hashes for the bundled Wasm workload."
        )
    )
    parser.add_argument(
        "--tasks",
        type=positive_int,
        default=12,
        help="number of contiguous partitions (default: 12)",
    )
    parser.add_argument(
        "--values",
        type=positive_int,
        default=12_000_000,
        help="number of integers in [0, values) to process (default: 12000000)",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        default=EXAMPLE_DIR / "sum_squares.wasm",
        help="Wasm artifact (default: <example>/sum_squares.wasm)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=EXAMPLE_DIR / "job.json",
        help="job JSON destination (default: <example>/job.json)",
    )
    parser.add_argument(
        "--expected-sha256",
        default=None,
        metavar="HEX",
        help="fail unless the artifact has this SHA-256",
    )
    parser.add_argument(
        "--timeout-secs",
        type=positive_int,
        default=10,
        help="per-task execution timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--lease-seconds",
        type=positive_int,
        default=20,
        help="task lease duration; must be at least timeout+5 (default: 20)",
    )
    return parser.parse_args(argv)


def read_u32(data: bytes, offset: int) -> tuple[int, int]:
    """Reads an unsigned LEB128-encoded u32 from a WebAssembly module."""
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated LEB128 integer in Wasm artifact")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
        if shift >= 35:
            raise ValueError("oversized LEB128 integer in Wasm artifact")
    if value > 0xFFFFFFFF:
        raise ValueError("LEB128 integer exceeds u32 in Wasm artifact")
    return value, offset


def read_name(data: bytes, offset: int, end: int) -> tuple[str, int]:
    """Reads a WebAssembly name (length-prefixed UTF-8) bounded by `end`."""
    length, offset = read_u32(data, offset)
    name_end = offset + length
    if name_end > end:
        raise ValueError("truncated name in Wasm artifact")
    return data[offset:name_end].decode("utf-8"), name_end


def validate_wasm(data: bytes) -> tuple[int, dict[str, str]]:
    """Validates magic, imports, and required exports; returns (imports, exports)."""
    if len(data) < 8 or data[:4] != b"\0asm" or data[4:8] != b"\x01\0\0\0":
        raise ValueError("artifact is not a WebAssembly 1.0 module")

    import_count = 0
    exports: dict[str, str] = {}
    offset = 8
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        section_size, offset = read_u32(data, offset)
        section_end = offset + section_size
        if section_end > len(data):
            raise ValueError("Wasm section extends past end of artifact")

        if section_id == 2:  # import section
            count, _ = read_u32(data, offset)
            import_count += count
        elif section_id == 7:  # export section
            count, cursor = read_u32(data, offset)
            for _ in range(count):
                if cursor >= section_end:
                    raise ValueError("truncated export in Wasm artifact")
                name, cursor = read_name(data, cursor, section_end)
                if cursor >= section_end:
                    raise ValueError("truncated export kind in Wasm artifact")
                kind = data[cursor]
                cursor += 1
                _, cursor = read_u32(data, cursor)
                if cursor > section_end:
                    raise ValueError("truncated export index in Wasm artifact")
                exports[name] = _EXPORT_KINDS.get(kind, f"kind-{kind}")

        offset = section_end

    if import_count:
        raise ValueError(
            f"artifact has {import_count} import(s); getter.abi.v1 forbids imports"
        )
    missing = [name for name in REQUIRED_EXPORTS if name not in exports]
    if missing:
        raise ValueError(
            "artifact is missing required export(s): " + ", ".join(missing)
        )
    if exports["memory"] != "memory":
        raise ValueError("artifact export 'memory' is not a memory")
    for name in ("getter_alloc", "getter_execute"):
        if exports[name] != "function":
            raise ValueError(f"artifact export {name!r} is not a function")

    return import_count, exports


def build_partitions(values: int, task_count: int) -> list[tuple[int, int]]:
    """Splits [0, values) into deterministic contiguous partitions."""
    base, extra = divmod(values, task_count)
    partitions = []
    start = 0
    for index in range(task_count):
        end = start + base + (1 if index < extra else 0)
        partitions.append((start, end))
        start = end
    if start != values:
        raise RuntimeError("internal error: partitions do not cover the range")
    return partitions


def reference_sum_squares(start: int, end: int) -> int:
    """Trusted closed-form reference for sum(i*i for i in [start, end)).

    The Wasm guest computes the same value by iteration. Using an independent
    formula here makes trusted job generation fast even for large ranges.
    """
    if start >= end:
        return 0

    def prefix(n: int) -> int:
        # Sum of squares for 0..n inclusive: n(n+1)(2n+1)/6.
        return n * (n + 1) * (2 * n + 1) // 6

    return prefix(end - 1) - prefix(start - 1)


def task_output(total: int) -> bytes:
    """The exact canonical guest output bytes for one task total."""
    return f'{{"value":"{total}"}}'.encode("ascii")


def output_sha256(total: int) -> str:
    return hashlib.sha256(task_output(total)).hexdigest()


def expected_digest(value: str) -> str:
    digest = value.strip().lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("--expected-sha256 must be a 64-character hexadecimal digest")
    return digest


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        if args.values > MAX_U128:
            raise ValueError(
                f"--values must fit in u128 (maximum {MAX_U128}), got {args.values}"
            )

        artifact = args.artifact.expanduser().resolve()
        out_path = args.out.expanduser().resolve()
        if artifact == out_path:
            raise ValueError("--out must not overwrite the Wasm artifact")
        if not artifact.is_file():
            raise ValueError(
                f"artifact not found: {artifact} (run ./scripts/build-example.sh first)"
            )

        artifact_bytes = artifact.read_bytes()
        if not artifact_bytes:
            raise ValueError(f"artifact is empty: {artifact}")
        imports, exports = validate_wasm(artifact_bytes)
        digest = hashlib.sha256(artifact_bytes).hexdigest()
        if args.expected_sha256 is not None:
            expected = expected_digest(args.expected_sha256)
            if digest != expected:
                raise ValueError(
                    f"artifact SHA-256 mismatch: expected {expected}, got {digest}"
                )

        relative_artifact = Path(
            os.path.relpath(artifact, start=out_path.parent)
        ).as_posix()

        partitions = build_partitions(args.values, args.tasks)
        tasks = []
        aggregate = 0
        for index, (start, end) in enumerate(partitions):
            total = reference_sum_squares(start, end)
            if total > MAX_U128:
                raise ValueError(
                    f"task-{index:03d} ({start}:{end}) sums to more than u128; "
                    "the guest would trap. Reduce --values or increase --tasks."
                )
            aggregate += total
            tasks.append(
                {
                    "id": f"task-{index:03d}",
                    "input": f"{start}:{end}",
                    "expected_output_sha256": output_sha256(total),
                }
            )

        if aggregate > MAX_U128:
            raise ValueError(
                "aggregate total exceeds u128; reduce --values."
            )

        if args.timeout_secs + 5 > args.lease_seconds:
            raise ValueError(
                "--lease-seconds must be at least --timeout-secs + 5"
            )
        requirements = dict(REQUIREMENTS)
        requirements["timeout_secs"] = args.timeout_secs

        job = {
            "protocol": "getter.job/v1",
            "name": "sum-of-squares",
            "description": (
                "Partitioned sum of squares over [0, "
                f"{args.values}) computed by the sum-squares reference workload."
            ),
            "workload": {
                "name": "sum-of-squares",
                "abi": "getter.abi.v1",
                "sha256": digest,
                "artifact": relative_artifact,
            },
            "tasks": tasks,
            "requirements": requirements,
            "verification": {"mode": "exact_sha256"},
            "aggregation": {"mode": "json_sum", "field": "value"},
            "expected_aggregate": {"total": str(aggregate)},
            "max_attempts": MAX_ATTEMPTS,
            "lease_seconds": args.lease_seconds,
        }

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(job, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"generate_job.py: error: {error}", file=sys.stderr)
        return 1

    export_list = ",".join(REQUIRED_EXPORTS)
    last_index = args.tasks - 1
    print(f"job: {out_path}")
    print(
        f"artifact: {relative_artifact} bytes={len(artifact_bytes)} "
        f"imports={imports} exports={export_list} sha256={digest}"
    )
    print(
        f"tasks: {args.tasks} (task-000..task-{last_index:03d}) "
        f"range=[0, {args.values}) total={aggregate}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
