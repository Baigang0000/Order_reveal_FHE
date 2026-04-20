# Paper Sweep

Configuration:
- RUNS_THRESHOLD = 10
- RUNS_DERIVED = 10
- BATCH_SIZES = 8, 16, 32, 64
- DERIVED_MEMBERS = f1, f2, f3, f4, f5, f6
- MAX_JOBS = 2
- VALIDATE_DERIVED = True

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
