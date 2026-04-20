[CmdletBinding()]
param(
    [string]$BuildDir = 'build-semantic-real-portable',
    [int]$MaxJobs = 2,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Paper sweep configuration.
$RUNS_THRESHOLD = 10
$RUNS_DERIVED = 10
$BATCH_SIZES = @(8, 16, 32, 64)
$DERIVED_MEMBERS = @('f1', 'f2', 'f3', 'f4', 'f5', 'f6')
$MAX_JOBS = $MaxJobs
$VALIDATE_DERIVED = $true

$THRESHOLD_TARGET = 'orhe_bench_threshold-nayuki-portable'
$DERIVED_TARGET = 'orhe_bench_derived_registration-nayuki-portable'

function Resolve-ExecutablePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $exePath = "$BasePath.exe"
    if (Test-Path -LiteralPath $exePath) {
        return (Resolve-Path -LiteralPath $exePath).Path
    }
    if (Test-Path -LiteralPath $BasePath) {
        return (Resolve-Path -LiteralPath $BasePath).Path
    }

    throw "Could not find executable for '$BasePath'."
}

function New-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function New-JobSpec {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Kind,
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,
        [Parameter(Mandatory = $true)]
        [string]$StderrPath,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    return [pscustomobject]@{
        Name = $Name
        Kind = $Kind
        Executable = $Executable
        Arguments = $Arguments
        CsvPath = $CsvPath
        StdoutPath = $StdoutPath
        StderrPath = $StderrPath
        WorkingDirectory = $WorkingDirectory
    }
}

function Start-BenchmarkProcess {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Spec
    )

    Write-Host "Starting $($Spec.Name)"
    $process = Start-Process `
        -FilePath $Spec.Executable `
        -ArgumentList $Spec.Arguments `
        -WorkingDirectory $Spec.WorkingDirectory `
        -RedirectStandardOutput $Spec.StdoutPath `
        -RedirectStandardError $Spec.StderrPath `
        -PassThru `
        -NoNewWindow

    return [pscustomobject]@{
        Spec = $Spec
        Process = $process
        Completed = $false
    }
}

function Complete-BenchmarkProcess {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$RunningJob
    )

    if ($RunningJob.Completed) {
        return $RunningJob
    }

    if (-not $RunningJob.Process.HasExited) {
        return $RunningJob
    }

    $RunningJob.Completed = $true
    $exitCode = $RunningJob.Process.ExitCode
    if ($exitCode -ne 0) {
        throw "Job '$($RunningJob.Spec.Name)' failed with exit code $exitCode. See $($RunningJob.Spec.StderrPath)"
    }

    if (-not (Test-Path -LiteralPath $RunningJob.Spec.CsvPath)) {
        throw "Job '$($RunningJob.Spec.Name)' completed but did not produce '$($RunningJob.Spec.CsvPath)'."
    }

    $csvInfo = Get-Item -LiteralPath $RunningJob.Spec.CsvPath
    if ($csvInfo.Length -le 0) {
        throw "Job '$($RunningJob.Spec.Name)' produced an empty CSV at '$($RunningJob.Spec.CsvPath)'."
    }

    Write-Host "Completed $($RunningJob.Spec.Name)"
    return $RunningJob
}

function Invoke-JobQueue {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$JobSpecs,
        [Parameter(Mandatory = $true)]
        [int]$ThrottleLimit,
        [switch]$DryRunMode
    )

    if ($DryRunMode) {
        foreach ($spec in $JobSpecs) {
            Write-Host ("[dry-run] {0} {1}" -f $spec.Executable, ($spec.Arguments -join ' '))
        }
        return
    }

    $running = New-Object System.Collections.Generic.List[object]
    foreach ($spec in $JobSpecs) {
        while (($running | Where-Object { -not $_.Completed }).Count -ge $ThrottleLimit) {
            for ($i = 0; $i -lt $running.Count; ++$i) {
                $running[$i] = Complete-BenchmarkProcess -RunningJob $running[$i]
            }
            Start-Sleep -Seconds 1
        }

        $running.Add((Start-BenchmarkProcess -Spec $spec))
    }

    while (($running | Where-Object { -not $_.Completed }).Count -gt 0) {
        for ($i = 0; $i -lt $running.Count; ++$i) {
            $running[$i] = Complete-BenchmarkProcess -RunningJob $running[$i]
        }
        Start-Sleep -Seconds 1
    }
}

$repoRoot = (Resolve-Path -LiteralPath '.').Path
$buildRoot = (Resolve-Path -LiteralPath $BuildDir).Path
$buildLibDir = Join-Path $buildRoot 'libtfhe'

$thresholdExe = Resolve-ExecutablePath -BasePath (Join-Path $buildRoot $THRESHOLD_TARGET)
$derivedExe = Resolve-ExecutablePath -BasePath (Join-Path $buildRoot $DERIVED_TARGET)
$aggregateScript = (Resolve-Path -LiteralPath 'scripts/aggregate_paper_sweep.ps1').Path

if ($MAX_JOBS -lt 1) {
    throw "MAX_JOBS must be at least 1."
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$sweepRoot = Join-Path $repoRoot ("outputs\paper_sweep\{0}" -f $timestamp)
$rawThresholdDir = Join-Path $sweepRoot 'raw\threshold'
$rawDerivedDir = Join-Path $sweepRoot 'raw\derived'
$logThresholdDir = Join-Path $sweepRoot 'logs\threshold'
$logDerivedDir = Join-Path $sweepRoot 'logs\derived'
$summaryDir = Join-Path $sweepRoot 'summaries'

New-Directory -Path $rawThresholdDir
New-Directory -Path $rawDerivedDir
New-Directory -Path $logThresholdDir
New-Directory -Path $logDerivedDir
New-Directory -Path $summaryDir

$env:PATH = '{0};{1};{2}' -f $buildRoot, $buildLibDir, $env:PATH

$manifest = [ordered]@{
    timestamp = $timestamp
    repo_root = $repoRoot
    build_dir = $buildRoot
    threshold_target = $thresholdExe
    derived_target = $derivedExe
    runs_threshold = $RUNS_THRESHOLD
    runs_derived = $RUNS_DERIVED
    batch_sizes = $BATCH_SIZES
    derived_members = $DERIVED_MEMBERS
    max_jobs = $MAX_JOBS
    validate_derived = [bool]$VALIDATE_DERIVED
    multiprocessing_enabled = ($MAX_JOBS -gt 1)
    parallel_safety = [ordered]@{
        separate_invocations_independent = $true
        fixed_shared_output_files = $false
        shared_proof_backend_process_state = $false
        validation_requires_serialization = $false
        note = 'Executables only write to caller-provided output paths. TFHE RNG and proof-backend state are process-local. Bounded parallelism is enabled conservatively to avoid CPU oversubscription.'
    }
}

$manifestPath = Join-Path $sweepRoot 'manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath

$readmePath = Join-Path $sweepRoot 'README.md'
$readmeLines = @(
    '# Paper Sweep',
    '',
    'Configuration:',
    ("- RUNS_THRESHOLD = {0}" -f $RUNS_THRESHOLD),
    ("- RUNS_DERIVED = {0}" -f $RUNS_DERIVED),
    ("- BATCH_SIZES = {0}" -f ($BATCH_SIZES -join ', ')),
    ("- DERIVED_MEMBERS = {0}" -f ($DERIVED_MEMBERS -join ', ')),
    ("- MAX_JOBS = {0}" -f $MAX_JOBS),
    ("- VALIDATE_DERIVED = {0}" -f $VALIDATE_DERIVED),
    '',
    'Parallel safety decision:',
    '- Separate benchmark invocations are independent.',
    '- The threshold and derived executables only write to the explicit output path passed on the command line.',
    '- Proof-backend and RNG state are process-local for each benchmark process; there is no shared mutable service to serialize around.',
    '- Derived validation is also process-local and does not require global serialization.',
    '- Parallelism is therefore enabled with bounded fan-out only; keep MAX_JOBS conservative because the jobs are CPU-heavy.',
    '',
    'Raw derived CSV note:',
    '- The current derived executable emits one summary row even for --runs 1. In this sweep, each raw derived CSV is therefore a single-sample summary file, which is the closest raw-per-run artifact supported by the current code.',
    '- Aggregation only reads files under this sweep directory, so stale T1/T6/f7 build artifacts elsewhere do not affect the paper summaries.',
    '',
    'Outputs:',
    '- raw/threshold: one CSV per threshold invocation',
    '- raw/derived: one CSV per derived invocation',
    '- logs/*: stdout/stderr per job',
    '- summaries/*: aggregated CSVs and markdown summary'
)
Set-Content -LiteralPath $readmePath -Value $readmeLines

Write-Host "Sweep root: $sweepRoot"

if (-not $DryRun) {
    Write-Host 'Building benchmark targets...'
    & cmake --build $buildRoot --target $THRESHOLD_TARGET $DERIVED_TARGET -j2
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE."
    }
}

$thresholdJobs = New-Object System.Collections.Generic.List[object]
foreach ($batchSize in $BATCH_SIZES) {
    foreach ($runIndex in 1..$RUNS_THRESHOLD) {
        $name = ('threshold_n{0:D2}_run{1:D2}' -f $batchSize, $runIndex)
        $csvPath = Join-Path $rawThresholdDir ("$name.csv")
        $stdoutPath = Join-Path $logThresholdDir ("$name.stdout.log")
        $stderrPath = Join-Path $logThresholdDir ("$name.stderr.log")
        $args = @('--batch-size', [string]$batchSize, '--csv', $csvPath)
        $thresholdJobs.Add((New-JobSpec `
            -Name $name `
            -Kind 'threshold' `
            -Executable $thresholdExe `
            -Arguments $args `
            -CsvPath $csvPath `
            -StdoutPath $stdoutPath `
            -StderrPath $stderrPath `
            -WorkingDirectory $repoRoot))
    }
}

$derivedJobs = New-Object System.Collections.Generic.List[object]
for ($memberIndex = 0; $memberIndex -lt $DERIVED_MEMBERS.Count; ++$memberIndex) {
    $member = $DERIVED_MEMBERS[$memberIndex]
    foreach ($runIndex in 1..$RUNS_DERIVED) {
        $name = ('derived_{0}_run{1:D2}' -f $member, $runIndex)
        $csvPath = Join-Path $rawDerivedDir ("$name.csv")
        $stdoutPath = Join-Path $logDerivedDir ("$name.stdout.log")
        $stderrPath = Join-Path $logDerivedDir ("$name.stderr.log")
        $seed = 1000 + ($memberIndex * 100) + $runIndex
        $args = @('--runs', '1', '--seed', [string]$seed, '--member', $member, '--output', $csvPath)
        if ($VALIDATE_DERIVED) {
            $args += '--validate'
        }
        $derivedJobs.Add((New-JobSpec `
            -Name $name `
            -Kind 'derived' `
            -Executable $derivedExe `
            -Arguments $args `
            -CsvPath $csvPath `
            -StdoutPath $stdoutPath `
            -StderrPath $stderrPath `
            -WorkingDirectory $repoRoot))
    }
}

Write-Host ("Threshold jobs: {0}" -f $thresholdJobs.Count)
Write-Host ("Derived jobs: {0}" -f $derivedJobs.Count)
Write-Host ("Parallel mode: {0}" -f $(if ($MAX_JOBS -gt 1) { "enabled (MAX_JOBS=$MAX_JOBS)" } else { 'disabled' }))

Invoke-JobQueue -JobSpecs $thresholdJobs -ThrottleLimit $MAX_JOBS -DryRunMode:$DryRun
Invoke-JobQueue -JobSpecs $derivedJobs -ThrottleLimit $MAX_JOBS -DryRunMode:$DryRun

if (-not $DryRun) {
    Write-Host 'Aggregating summaries...'
    & $aggregateScript -SweepRoot $sweepRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Aggregation failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Paper sweep automation prepared at $sweepRoot"
