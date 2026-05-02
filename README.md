# ORHE Benchmarking

This repository contains a TFHE-based prototype and benchmark harness for
Order-Revealing Homomorphic Encryption (ORHE). The code extends the upstream
TFHE library with ORHE ciphertext helpers, semantic proof hooks, Plonky2-backed
proof generation, and benchmark programs for threshold comparison,
derived-registration workloads, and attack/debug traces.

The current benchmark path is centered on the portable semantic build:

```text
build-semantic-real-portable
```

Older local build directories were experimental snapshots and are intentionally
not part of the maintained workflow.

## What Is Here

- `src/libtfhe/orhe*.cpp` and `src/include/orhe*.h`: ORHE C/C++ API, metrics,
  proof plumbing, semantic SignExt checkpoints, and proof backend bridge.
- `rust/orhe-proof-backend`: Rust static library that provides the Plonky2 proof
  backend used by the C++ ORHE code.
- `src/test/orhe_smoke.cpp`: smoke coverage for ORHE encryption, comparison,
  proof generation, and verification paths.
- `src/test/orhe_bench_threshold.cpp`: batched ORHE threshold-vs-plain-TFHE
  benchmark.
- `src/test/orhe_bench_derived_registration.cpp`: derived-registration family
  benchmark for `f1` through `f6`.
- `src/test/orhe_bench_attack.cpp`: attack/debug workload driver.
- `scripts/run_paper_sweep.*`: reproducible benchmark sweep runners.
- `scripts/aggregate_paper_sweep.*`: aggregation scripts for sweep outputs.
- `outputs/`: checked benchmark summaries and sanity outputs.

The TFHE code in `src/libtfhe` remains the base FHE implementation. ORHE-specific
work lives alongside it rather than replacing the underlying TFHE primitives.

## Prerequisites

- CMake 3.x or newer.
- A C and C++ compiler with C++11 support.
- Rust and Cargo for the real semantic proof backend.
- Python 3 for the aggregation script.
- On Windows, the maintained local build uses the Nayuki portable FFT target to
  avoid machine-specific AVX/SPQLIOS assumptions.

## Build

From the repository root:

```powershell
cmake -S src -B build-semantic-real-portable `
  -DCMAKE_BUILD_TYPE=optim `
  -DENABLE_FFTW=OFF `
  -DENABLE_NAYUKI_AVX=OFF `
  -DENABLE_NAYUKI_PORTABLE=ON `
  -DENABLE_ORHE_ATTACK_BENCHMARK=ON `
  -DENABLE_ORHE_BENCHMARK=ON `
  -DENABLE_ORHE_DERIVED_BENCHMARK=ON `
  -DENABLE_ORHE_SMOKE=ON `
  -DENABLE_SPQLIOS_AVX=OFF `
  -DENABLE_SPQLIOS_FMA=OFF `
  -DENABLE_TESTS=OFF

cmake --build build-semantic-real-portable
```

On Unix-like shells the same configuration is:

```bash
cmake -S src -B build-semantic-real-portable \
  -DCMAKE_BUILD_TYPE=optim \
  -DENABLE_FFTW=OFF \
  -DENABLE_NAYUKI_AVX=OFF \
  -DENABLE_NAYUKI_PORTABLE=ON \
  -DENABLE_ORHE_ATTACK_BENCHMARK=ON \
  -DENABLE_ORHE_BENCHMARK=ON \
  -DENABLE_ORHE_DERIVED_BENCHMARK=ON \
  -DENABLE_ORHE_SMOKE=ON \
  -DENABLE_SPQLIOS_AVX=OFF \
  -DENABLE_SPQLIOS_FMA=OFF \
  -DENABLE_TESTS=OFF

cmake --build build-semantic-real-portable
```

The benchmark sweep script can configure and build the same directory if it is
missing or incompatible.

## Run Smoke Test

After building, run the ORHE smoke executable from the build directory:

```powershell
.\build-semantic-real-portable\orhe_smoke-nayuki-portable.exe
```

or:

```bash
./build-semantic-real-portable/orhe_smoke-nayuki-portable
```

## Run Benchmark Sweep

Windows PowerShell:

```powershell
.\scripts\run_paper_sweep.ps1 -BuildDir build-semantic-real-portable -MaxJobs 2
```

Unix-like shell:

```bash
./scripts/run_paper_sweep.sh --build-dir build-semantic-real-portable --max-jobs 2
```

Each sweep writes raw CSVs, logs, a manifest, and summaries under:

```text
outputs/paper_sweep/<timestamp>/
```

The most recent checked summary in this repository reports threshold comparison
and derived-registration timings under
`outputs/paper_sweep/20260420_163102/summaries/summary.md`.

## Benchmark Targets

The maintained portable build emits these ORHE executables:

- `orhe_smoke-nayuki-portable`
- `orhe_bench_threshold-nayuki-portable`
- `orhe_bench_derived_registration-nayuki-portable`
- `orhe_bench_attack-nayuki-portable`

The paper sweep uses the threshold and derived-registration binaries by default.

## Repository Hygiene

Generated dependency caches and build outputs are ignored:

- `.cargo_orhe/`
- `rust/orhe-proof-backend/target/`
- local CMake build directories other than the maintained
  `build-semantic-real-portable/`

If a new benchmark run produces results worth preserving, commit the selected
files under `outputs/`; keep transient logs and intermediate build products out
of Git.

## License

This repository keeps the upstream TFHE Apache 2.0 license file. ORHE additions
are distributed with the same repository license unless noted otherwise.
