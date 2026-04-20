#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

RUNS_THRESHOLD=10
RUNS_DERIVED=10
BATCH_SIZES=(8 16 32 64)
DERIVED_MEMBERS=(f1 f2 f3 f4 f5 f6)
MAX_JOBS="${MAX_JOBS:-2}"
VALIDATE_DERIVED="${VALIDATE_DERIVED:-1}"
BUILD_DIR="${BUILD_DIR:-build-semantic-real-portable}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
DRY_RUN=0

THRESHOLD_TARGET="orhe_bench_threshold-nayuki-portable"
DERIVED_TARGET="orhe_bench_derived_registration-nayuki-portable"

usage() {
    cat <<'EOF'
usage: ./scripts/run_paper_sweep.sh [options]

options:
  --build-dir PATH           Build directory to use. Default: build-semantic-real-portable
  --max-jobs N               Override MAX_JOBS for bounded parallelism.
  --python-bin NAME          Python interpreter for aggregation. Default: python3
  --no-validate-derived      Disable derived --validate during the sweep.
  --dry-run                  Print planned commands without executing them.
  --help                     Show this help text.
EOF
}

while (($# > 0)); do
    case "$1" in
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --max-jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --python-bin)
            PYTHON_BIN="$2"
            shift 2
            ;;
        --no-validate-derived)
            VALIDATE_DERIVED=0
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if ! [[ "$MAX_JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "MAX_JOBS must be a positive integer." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_ROOT="$REPO_ROOT/$BUILD_DIR"
BUILD_LIB_DIR="$BUILD_ROOT/libtfhe"
AGGREGATE_SCRIPT="$SCRIPT_DIR/aggregate_paper_sweep.py"
THRESHOLD_EXE_BASE="$BUILD_ROOT/$THRESHOLD_TARGET"
DERIVED_EXE_BASE="$BUILD_ROOT/$DERIVED_TARGET"

resolve_executable() {
    local base="$1"
    if [[ -x "$base" ]]; then
        printf '%s\n' "$base"
        return 0
    fi
    if [[ -x "$base.exe" ]]; then
        printf '%s\n' "$base.exe"
        return 0
    fi
    echo "Could not find executable for $base" >&2
    exit 1
}

quote_command() {
    local out=""
    local part
    for part in "$@"; do
        if [[ -n "$out" ]]; then
            out+=" "
        fi
        printf -v part '%q' "$part"
        out+="$part"
    done
    printf '%s\n' "$out"
}

THRESHOLD_EXE="$THRESHOLD_EXE_BASE"
DERIVED_EXE="$DERIVED_EXE_BASE"

export PATH="$BUILD_ROOT:$BUILD_LIB_DIR:$PATH"
export LD_LIBRARY_PATH="$BUILD_ROOT:$BUILD_LIB_DIR:${LD_LIBRARY_PATH:-}"
export DYLD_LIBRARY_PATH="$BUILD_ROOT:$BUILD_LIB_DIR:${DYLD_LIBRARY_PATH:-}"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
SWEEP_ROOT="$REPO_ROOT/outputs/paper_sweep/$TIMESTAMP"
RAW_THRESHOLD_DIR="$SWEEP_ROOT/raw/threshold"
RAW_DERIVED_DIR="$SWEEP_ROOT/raw/derived"
LOG_THRESHOLD_DIR="$SWEEP_ROOT/logs/threshold"
LOG_DERIVED_DIR="$SWEEP_ROOT/logs/derived"
SUMMARY_DIR="$SWEEP_ROOT/summaries"

mkdir -p "$RAW_THRESHOLD_DIR" "$RAW_DERIVED_DIR" "$LOG_THRESHOLD_DIR" "$LOG_DERIVED_DIR" "$SUMMARY_DIR"

write_manifest() {
    local manifest_path="$SWEEP_ROOT/manifest.json"
    local readme_path="$SWEEP_ROOT/README.md"
    local batch_csv derived_csv

    batch_csv="$(IFS=,; echo "${BATCH_SIZES[*]}")"
    derived_csv="$(IFS=,; echo "${DERIVED_MEMBERS[*]}")"

    cat >"$manifest_path" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "repo_root": "$REPO_ROOT",
  "build_dir": "$BUILD_ROOT",
  "threshold_target": "$THRESHOLD_EXE",
  "derived_target": "$DERIVED_EXE",
  "runs_threshold": $RUNS_THRESHOLD,
  "runs_derived": $RUNS_DERIVED,
  "batch_sizes": [$batch_csv],
  "derived_members": ["${derived_csv//,/\",\"}"],
  "max_jobs": $MAX_JOBS,
  "validate_derived": $( [[ "$VALIDATE_DERIVED" == "1" ]] && echo true || echo false ),
  "multiprocessing_enabled": $( [[ "$MAX_JOBS" -gt 1 ]] && echo true || echo false ),
  "parallel_safety": {
    "separate_invocations_independent": true,
    "fixed_shared_output_files": false,
    "shared_proof_backend_process_state": false,
    "validation_requires_serialization": false,
    "note": "Executables only write to caller-provided output paths. TFHE RNG and proof-backend state are process-local. Bounded parallelism is enabled conservatively to avoid CPU oversubscription."
  }
}
EOF

    cat >"$readme_path" <<EOF
# Paper Sweep

Configuration:
- RUNS_THRESHOLD = $RUNS_THRESHOLD
- RUNS_DERIVED = $RUNS_DERIVED
- BATCH_SIZES = ${BATCH_SIZES[*]}
- DERIVED_MEMBERS = ${DERIVED_MEMBERS[*]}
- MAX_JOBS = $MAX_JOBS
- VALIDATE_DERIVED = $VALIDATE_DERIVED

Parallel safety decision:
- Separate benchmark invocations are independent.
- The threshold and derived executables only write to the explicit output path passed on the command line.
- Proof-backend and RNG state are process-local for each benchmark process; there is no shared mutable service to serialize around.
- Derived validation is also process-local and does not require global serialization.
- Parallelism is therefore enabled with bounded fan-out only; keep MAX_JOBS conservative because the jobs are CPU-heavy.

Raw derived CSV note:
- The current derived executable emits one summary row even for --runs 1. In this sweep, each raw derived CSV is therefore a single-sample summary file, which is the closest raw-per-run artifact supported by the current code.
- Aggregation only reads files under this sweep directory, so stale T1/T6/f7 build artifacts elsewhere do not affect the paper summaries.

Outputs:
- raw/threshold: one CSV per threshold invocation
- raw/derived: one CSV per derived invocation
- logs/*: stdout/stderr per job
- summaries/*: aggregated CSVs and markdown summary
EOF
}

RUNNING_PIDS=()
RUNNING_NAMES=()
RUNNING_CSVS=()
RUNNING_STDERRS=()

check_completed_jobs() {
    local block="$1"
    while true; do
        local had_completion=0
        local new_pids=()
        local new_names=()
        local new_csvs=()
        local new_stderrs=()
        local i

        for i in "${!RUNNING_PIDS[@]}"; do
            local pid="${RUNNING_PIDS[$i]}"
            local name="${RUNNING_NAMES[$i]}"
            local csv_path="${RUNNING_CSVS[$i]}"
            local stderr_path="${RUNNING_STDERRS[$i]}"

            if kill -0 "$pid" 2>/dev/null; then
                new_pids+=("$pid")
                new_names+=("$name")
                new_csvs+=("$csv_path")
                new_stderrs+=("$stderr_path")
                continue
            fi

            had_completion=1
            if ! wait "$pid"; then
                echo "Job '$name' failed. See $stderr_path" >&2
                exit 1
            fi
            if [[ ! -s "$csv_path" ]]; then
                echo "Job '$name' completed but did not produce a non-empty CSV at $csv_path" >&2
                exit 1
            fi
            echo "Completed $name"
        done

        RUNNING_PIDS=("${new_pids[@]}")
        RUNNING_NAMES=("${new_names[@]}")
        RUNNING_CSVS=("${new_csvs[@]}")
        RUNNING_STDERRS=("${new_stderrs[@]}")

        if [[ "$block" == "0" ]]; then
            break
        fi
        if ((${#RUNNING_PIDS[@]} == 0)); then
            break
        fi
        if ((had_completion == 1)); then
            break
        fi
        sleep 1
    done
}

start_job() {
    local name="$1"
    local csv_path="$2"
    local stdout_path="$3"
    local stderr_path="$4"
    shift 4

    while ((${#RUNNING_PIDS[@]} >= MAX_JOBS)); do
        check_completed_jobs 1
    done

    if ((DRY_RUN == 1)); then
        echo "[dry-run] $(quote_command "$@")"
        return
    fi

    echo "Starting $name"
    (
        cd "$REPO_ROOT"
        "$@" >"$stdout_path" 2>"$stderr_path"
    ) &
    RUNNING_PIDS+=("$!")
    RUNNING_NAMES+=("$name")
    RUNNING_CSVS+=("$csv_path")
    RUNNING_STDERRS+=("$stderr_path")
}

wait_for_all_jobs() {
    if ((DRY_RUN == 1)); then
        return
    fi
    while ((${#RUNNING_PIDS[@]} > 0)); do
        check_completed_jobs 1
    done
}

if ((DRY_RUN == 0)); then
    echo "Building benchmark targets..."
    cmake --build "$BUILD_ROOT" --target "$THRESHOLD_TARGET" "$DERIVED_TARGET" -j2
    THRESHOLD_EXE="$(resolve_executable "$THRESHOLD_EXE_BASE")"
    DERIVED_EXE="$(resolve_executable "$DERIVED_EXE_BASE")"
fi

write_manifest

echo "Sweep root: $SWEEP_ROOT"
echo "Parallel mode: $( [[ "$MAX_JOBS" -gt 1 ]] && echo "enabled (MAX_JOBS=$MAX_JOBS)" || echo "disabled" )"

threshold_job_count=$(( ${#BATCH_SIZES[@]} * RUNS_THRESHOLD ))
derived_job_count=$(( ${#DERIVED_MEMBERS[@]} * RUNS_DERIVED ))
echo "Threshold jobs: $threshold_job_count"
echo "Derived jobs: $derived_job_count"

for batch_size in "${BATCH_SIZES[@]}"; do
    for run_index in $(seq 1 "$RUNS_THRESHOLD"); do
        name="$(printf 'threshold_n%02d_run%02d' "$batch_size" "$run_index")"
        csv_path="$RAW_THRESHOLD_DIR/$name.csv"
        stdout_path="$LOG_THRESHOLD_DIR/$name.stdout.log"
        stderr_path="$LOG_THRESHOLD_DIR/$name.stderr.log"
        start_job "$name" "$csv_path" "$stdout_path" "$stderr_path" \
            "$THRESHOLD_EXE" --batch-size "$batch_size" --csv "$csv_path"
    done
done

for member_index in "${!DERIVED_MEMBERS[@]}"; do
    member="${DERIVED_MEMBERS[$member_index]}"
    for run_index in $(seq 1 "$RUNS_DERIVED"); do
        name="$(printf 'derived_%s_run%02d' "$member" "$run_index")"
        csv_path="$RAW_DERIVED_DIR/$name.csv"
        stdout_path="$LOG_DERIVED_DIR/$name.stdout.log"
        stderr_path="$LOG_DERIVED_DIR/$name.stderr.log"
        seed=$((1000 + member_index * 100 + run_index))

        args=(
            "$DERIVED_EXE"
            --runs 1
            --seed "$seed"
            --member "$member"
            --output "$csv_path"
        )
        if [[ "$VALIDATE_DERIVED" == "1" ]]; then
            args+=(--validate)
        fi

        start_job "$name" "$csv_path" "$stdout_path" "$stderr_path" "${args[@]}"
    done
done

wait_for_all_jobs

if ((DRY_RUN == 0)); then
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        echo "Python interpreter '$PYTHON_BIN' was not found." >&2
        exit 1
    fi
    echo "Aggregating summaries..."
    "$PYTHON_BIN" "$AGGREGATE_SCRIPT" "$SWEEP_ROOT"
fi

echo "Paper sweep automation prepared at $SWEEP_ROOT"
