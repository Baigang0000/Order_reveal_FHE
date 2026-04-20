#!/usr/bin/env python3

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


EXPECTED_DERIVED = {
    "f1": {"arity": 1, "lin": 1, "pbs": 1, "depth": 1},
    "f2": {"arity": 1, "lin": 2, "pbs": 1, "depth": 1},
    "f3": {"arity": 1, "lin": 2, "pbs": 2, "depth": 2},
    "f4": {"arity": 2, "lin": 1, "pbs": 1, "depth": 1},
    "f5": {"arity": 2, "lin": 2, "pbs": 1, "depth": 1},
    "f6": {"arity": 2, "lin": 3, "pbs": 2, "depth": 2},
}


def die(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def read_csv_rows(path: Path):
    with path.open("r", newline="") as handle:
        return list(csv.DictReader(handle))


def is_numeric(value: str) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def mean(values):
    return sum(values) / len(values)


def sample_stddev(values):
    if len(values) <= 1:
        return 0.0
    mu = mean(values)
    return math.sqrt(sum((value - mu) ** 2 for value in values) / (len(values) - 1))


def fmt(value: float) -> str:
    return f"{value:.3f}"


def write_csv(path: Path, rows, fieldnames):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def aggregate_threshold(sweep_root: Path):
    raw_dir = sweep_root / "raw" / "threshold"
    summary_dir = sweep_root / "summaries"
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        die(f"No threshold raw CSVs found in {raw_dir}")

    threshold_entries = []
    for path in files:
        for row in read_csv_rows(path):
            threshold_entries.append((path.name, row))

    example_row = threshold_entries[0][1]
    numeric_columns = [
        key
        for key, value in example_row.items()
        if key not in {"label", "mode"} and is_numeric(value)
    ]

    grouped = defaultdict(list)
    for source_name, row in threshold_entries:
        batch_size = int(row["batch_size"])
        mode = row["mode"]
        grouped[(batch_size, mode)].append((source_name, row))

    summary_rows = []
    errors = []

    for (batch_size, mode) in sorted(grouped.keys()):
        entries = grouped[(batch_size, mode)]
        if mode == "orhe":
            for source_name, row in entries:
                verify_tfhe = float(row["verify_tfhe_us"])
                if verify_tfhe != 0.0:
                    errors.append(
                        f"Threshold ORHE true-proof invariant violated in {source_name}: "
                        f"verify_tfhe_us={verify_tfhe} for batch size {batch_size}."
                    )

        out = {
            "batch_size": str(batch_size),
            "mode": mode,
            "num_runs": str(len(entries)),
        }
        for column in numeric_columns:
            if column == "batch_size":
                continue
            values = [float(row[column]) for _, row in entries]
            out[f"{column}_mean"] = fmt(mean(values))
            out[f"{column}_std"] = fmt(sample_stddev(values))
        summary_rows.append(out)

    fieldnames = ["batch_size", "mode", "num_runs"]
    for column in numeric_columns:
        if column == "batch_size":
            continue
        fieldnames.append(f"{column}_mean")
        fieldnames.append(f"{column}_std")

    summary_path = summary_dir / "threshold_summary.csv"
    write_csv(summary_path, summary_rows, fieldnames)
    return summary_rows, errors


def aggregate_derived(sweep_root: Path):
    raw_dir = sweep_root / "raw" / "derived"
    summary_dir = sweep_root / "summaries"
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        die(f"No derived raw CSVs found in {raw_dir}")

    entries = []
    metric_names = None
    errors = []

    for path in files:
        rows = read_csv_rows(path)
        if len(rows) != 1:
            errors.append(f"Expected exactly one data row in {path.name}, found {len(rows)}.")
            continue

        row = rows[0]
        member = row["family_member"]
        if member not in EXPECTED_DERIVED:
            errors.append(f"Unexpected derived member '{member}' in {path.name}.")
            continue

        expected = EXPECTED_DERIVED[member]
        actual = {
            "arity": int(row["arity"]),
            "lin": int(row["num_linear_stages"]),
            "pbs": int(row["num_pbs"]),
            "depth": int(row["pbs_depth"]),
        }
        if actual != expected:
            errors.append(
                f"Derived metadata mismatch for {member} in {path.name}: "
                f"expected {expected}, saw {actual}."
            )
            continue

        if int(row["num_runs"]) != 1:
            errors.append(f"Derived raw file {path.name} reported num_runs={row['num_runs']}; expected 1.")
            continue

        if metric_names is None:
            metric_names = [key[:-5] for key in row.keys() if key.endswith("_mean")]

        entries.append((path.name, row))

    seen_members = {row["family_member"] for _, row in entries}
    for member in EXPECTED_DERIVED:
        if member not in seen_members:
            errors.append(f"Missing derived member '{member}' from raw outputs.")

    if metric_names is None:
        metric_names = []

    grouped = defaultdict(list)
    for source_name, row in entries:
        grouped[row["family_member"]].append((source_name, row))

    summary_rows = []
    for member in sorted(grouped.keys()):
        expected = EXPECTED_DERIVED[member]
        samples = grouped[member]
        out = {
            "family_member": member,
            "arity": str(expected["arity"]),
            "lin": str(expected["lin"]),
            "num_linear_stages": str(expected["lin"]),
            "pbs": str(expected["pbs"]),
            "num_pbs": str(expected["pbs"]),
            "depth": str(expected["depth"]),
            "pbs_depth": str(expected["depth"]),
            "num_runs": str(len(samples)),
        }
        for metric_name in metric_names:
            values = [float(row[f"{metric_name}_mean"]) for _, row in samples]
            out[f"{metric_name}_mean"] = fmt(mean(values))
            out[f"{metric_name}_std"] = fmt(sample_stddev(values))
        summary_rows.append(out)

    fieldnames = [
        "family_member",
        "arity",
        "lin",
        "num_linear_stages",
        "pbs",
        "num_pbs",
        "depth",
        "pbs_depth",
        "num_runs",
    ]
    for metric_name in metric_names:
        fieldnames.append(f"{metric_name}_mean")
        fieldnames.append(f"{metric_name}_std")

    summary_path = summary_dir / "derived_summary.csv"
    write_csv(summary_path, summary_rows, fieldnames)
    return summary_rows, errors


def write_markdown(sweep_root: Path, threshold_rows, derived_rows, errors):
    summary_dir = sweep_root / "summaries"
    markdown_path = summary_dir / "summary.md"

    lines = []
    lines.append("# Paper Sweep Summary")
    lines.append("")
    lines.append("## Threshold")
    lines.append("")
    lines.append("| batch | mode | runs | exec tfhe mean (ms) | prover mean (ms) | verifier mean (ms) | verify_tfhe mean (us) | proof mean (MiB) | comm mean (KiB) |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in sorted(threshold_rows, key=lambda item: (int(item["batch_size"]), item["mode"])):
        lines.append(
            "| {batch} | {mode} | {runs} | {exec_ms:.3f} | {prover_ms:.3f} | {verifier_ms:.3f} | {verify_tfhe:.3f} | {proof_mib:.3f} | {comm_kib:.3f} |".format(
                batch=int(row["batch_size"]),
                mode=row["mode"],
                runs=int(row["num_runs"]),
                exec_ms=float(row["exec_tfhe_us_mean"]) / 1000.0,
                prover_ms=float(row["prover_us_mean"]) / 1000.0,
                verifier_ms=float(row["verifier_us_mean"]) / 1000.0,
                verify_tfhe=float(row["verify_tfhe_us_mean"]),
                proof_mib=float(row["proof_size_bytes_mean"]) / (1024.0 * 1024.0),
                comm_kib=float(row["total_online_comm_bytes_mean"]) / 1024.0,
            )
        )

    lines.append("")
    lines.append("## Derived")
    lines.append("")
    lines.append("| member | runs | arity | lin | pbs | depth | tfhe mean (ms) | prover mean (ms) | verifier mean (ms) | proof mean (KiB) | comm mean (KiB) |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in sorted(derived_rows, key=lambda item: item["family_member"]):
        lines.append(
            "| {member} | {runs} | {arity} | {lin} | {pbs} | {depth} | {tfhe_ms:.3f} | {prover_ms:.3f} | {verifier_ms:.3f} | {proof_kib:.3f} | {comm_kib:.3f} |".format(
                member=row["family_member"],
                runs=int(row["num_runs"]),
                arity=int(row["arity"]),
                lin=int(row["lin"]),
                pbs=int(row["pbs"]),
                depth=int(row["depth"]),
                tfhe_ms=float(row["tfhe_eval_us_mean"]) / 1000.0,
                prover_ms=float(row["prover_us_mean"]) / 1000.0,
                verifier_ms=float(row["verifier_us_mean"]) / 1000.0,
                proof_kib=float(row["proof_size_bytes_mean"]) / 1024.0,
                comm_kib=float(row["total_online_comm_bytes_mean"]) / 1024.0,
            )
        )

    lines.append("")
    lines.append("## Checks")
    lines.append("")
    if errors:
        for error in errors:
            lines.append(f"- Error: {error}")
    else:
        lines.append("- All aggregation checks passed.")

    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    if len(sys.argv) != 2:
        die("usage: aggregate_paper_sweep.py <sweep-root>")

    sweep_root = Path(sys.argv[1]).resolve()
    summary_dir = sweep_root / "summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)

    threshold_rows, threshold_errors = aggregate_threshold(sweep_root)
    derived_rows, derived_errors = aggregate_derived(sweep_root)
    errors = threshold_errors + derived_errors

    write_markdown(sweep_root, threshold_rows, derived_rows, errors)

    print(f"Wrote threshold summary to {summary_dir / 'threshold_summary.csv'}")
    print(f"Wrote derived summary to {summary_dir / 'derived_summary.csv'}")
    print(f"Wrote markdown summary to {summary_dir / 'summary.md'}")

    if errors:
        die("\n".join(errors))


if __name__ == "__main__":
    main()
