[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SweepRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-SampleStdDev {
    param(
        [Parameter(Mandatory = $true)]
        [double[]]$Values
    )

    if ($Values.Count -le 1) {
        return 0.0
    }

    $mean = ($Values | Measure-Object -Average).Average
    $sumSq = 0.0
    foreach ($value in $Values) {
        $delta = $value - $mean
        $sumSq += $delta * $delta
    }

    return [Math]::Sqrt($sumSq / ($Values.Count - 1))
}

function Format-Double {
    param(
        [Parameter(Mandatory = $true)]
        [double]$Value
    )

    return ('{0:F3}' -f $Value)
}

function Get-NumericColumns {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Row,
        [Parameter(Mandatory = $true)]
        [string[]]$Exclude
    )

    $columns = @()
    foreach ($property in $Row.PSObject.Properties) {
        if ($Exclude -contains $property.Name) {
            continue
        }

        $parsed = 0.0
        if ([double]::TryParse($property.Value, [ref]$parsed)) {
            $columns += $property.Name
        }
    }

    return $columns
}

function Test-ExpectedDerivedMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Row,
        [Parameter(Mandatory = $true)]
        [hashtable]$ExpectedMap
    )

    $member = [string]$Row.family_member
    if (-not $ExpectedMap.ContainsKey($member)) {
        throw "Unexpected derived member '$member' in raw output."
    }

    $expected = $ExpectedMap[$member]
    $actualArity = [int]$Row.arity
    $actualLin = [int]$Row.num_linear_stages
    $actualPbs = [int]$Row.num_pbs
    $actualDepth = [int]$Row.pbs_depth

    if ($actualArity -ne $expected.arity -or
        $actualLin -ne $expected.lin -or
        $actualPbs -ne $expected.pbs -or
        $actualDepth -ne $expected.depth) {
        throw (
            "Derived metadata mismatch for {0}: expected arity={1}, lin={2}, pbs={3}, depth={4}; " +
            "saw arity={5}, lin={6}, pbs={7}, depth={8}."
        ) -f $member, $expected.arity, $expected.lin, $expected.pbs, $expected.depth,
            $actualArity, $actualLin, $actualPbs, $actualDepth
    }
}

function Import-SingleRowCsv {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -ne 1) {
        throw "Expected exactly one data row in '$Path', found $($rows.Count)."
    }

    return $rows[0]
}

$SweepRoot = (Resolve-Path -LiteralPath $SweepRoot).Path
$rawThresholdDir = Join-Path $SweepRoot 'raw\threshold'
$rawDerivedDir = Join-Path $SweepRoot 'raw\derived'
$summaryDir = Join-Path $SweepRoot 'summaries'

New-Item -ItemType Directory -Force -Path $summaryDir | Out-Null

$warnings = New-Object System.Collections.Generic.List[string]
$errors = New-Object System.Collections.Generic.List[string]

$expectedDerived = @{
    'f1' = @{ arity = 1; lin = 1; pbs = 1; depth = 1 }
    'f2' = @{ arity = 1; lin = 2; pbs = 1; depth = 1 }
    'f3' = @{ arity = 1; lin = 2; pbs = 2; depth = 2 }
    'f4' = @{ arity = 2; lin = 1; pbs = 1; depth = 1 }
    'f5' = @{ arity = 2; lin = 2; pbs = 1; depth = 1 }
    'f6' = @{ arity = 2; lin = 3; pbs = 2; depth = 2 }
}

$thresholdFiles = @(Get-ChildItem -LiteralPath $rawThresholdDir -Filter '*.csv' | Sort-Object Name)
if ($thresholdFiles.Count -eq 0) {
    throw "No threshold raw CSVs found in '$rawThresholdDir'."
}

$thresholdRows = New-Object System.Collections.Generic.List[object]
foreach ($file in $thresholdFiles) {
    $rows = Import-Csv -LiteralPath $file.FullName
    foreach ($row in $rows) {
        $obj = [pscustomobject]@{
            source_file = $file.Name
            label = [string]$row.label
            mode = [string]$row.mode
            batch_size = [int]$row.batch_size
            raw = $row
        }
        $thresholdRows.Add($obj)
    }
}

$thresholdNumericColumns = Get-NumericColumns -Row $thresholdRows[0].raw -Exclude @('label', 'mode')
$thresholdSummaryRows = New-Object System.Collections.Generic.List[object]

foreach ($group in ($thresholdRows | Group-Object -Property { '{0}|{1}' -f $_.batch_size, $_.mode })) {
    $parts = $group.Name.Split('|')
    $batchSize = [int]$parts[0]
    $mode = $parts[1]

    if ($mode -eq 'orhe') {
        foreach ($entry in $group.Group) {
            $verifyTfhe = [double]$entry.raw.verify_tfhe_us
            if ($verifyTfhe -ne 0.0) {
                $errors.Add(
                    "Threshold ORHE true-proof invariant violated in $($entry.source_file): verify_tfhe_us=$verifyTfhe for batch size $batchSize."
                )
            }
        }
    }

    $rowData = [ordered]@{
        batch_size = $batchSize
        mode = $mode
        num_runs = $group.Count
    }

    foreach ($column in $thresholdNumericColumns) {
        if ($column -eq 'batch_size') {
            continue
        }

        $values = @()
        foreach ($entry in $group.Group) {
            $values += [double]$entry.raw.$column
        }

        $mean = ($values | Measure-Object -Average).Average
        $std = Get-SampleStdDev -Values $values
        $rowData["${column}_mean"] = Format-Double -Value $mean
        $rowData["${column}_std"] = Format-Double -Value $std
    }

    $thresholdSummaryRows.Add([pscustomobject]$rowData)
}

$thresholdSummaryPath = Join-Path $summaryDir 'threshold_summary.csv'
$thresholdSummaryRows |
    Sort-Object @{ Expression = { [int]$_.batch_size } }, @{ Expression = { [string]$_.mode } } |
    Export-Csv -LiteralPath $thresholdSummaryPath -NoTypeInformation

$derivedFiles = @(Get-ChildItem -LiteralPath $rawDerivedDir -Filter '*.csv' | Sort-Object Name)
if ($derivedFiles.Count -eq 0) {
    throw "No derived raw CSVs found in '$rawDerivedDir'."
}

$derivedRows = New-Object System.Collections.Generic.List[object]
$derivedMetricNames = @()

foreach ($file in $derivedFiles) {
    $row = Import-SingleRowCsv -Path $file.FullName
    Test-ExpectedDerivedMetadata -Row $row -ExpectedMap $expectedDerived

    if ([int]$row.num_runs -ne 1) {
        $errors.Add("Derived raw file '$($file.Name)' reported num_runs=$($row.num_runs); expected 1.")
    }

    if ($derivedMetricNames.Count -eq 0) {
        foreach ($property in $row.PSObject.Properties) {
            if ($property.Name -like '*_mean') {
                $derivedMetricNames += $property.Name.Substring(0, $property.Name.Length - 5)
            }
        }
    }

    $derivedRows.Add([pscustomobject]@{
        source_file = $file.Name
        family_member = [string]$row.family_member
        row = $row
    })
}

$seenMembers = @($derivedRows | Select-Object -ExpandProperty family_member -Unique)
foreach ($member in $expectedDerived.Keys) {
    if ($seenMembers -notcontains $member) {
        $errors.Add("Missing derived member '$member' from raw outputs.")
    }
}

$derivedSummaryRows = New-Object System.Collections.Generic.List[object]
foreach ($group in ($derivedRows | Group-Object -Property family_member)) {
    $member = $group.Name
    $expected = $expectedDerived[$member]

    $rowData = [ordered]@{
        family_member = $member
        arity = $expected.arity
        num_linear_stages = $expected.lin
        num_pbs = $expected.pbs
        pbs_depth = $expected.depth
        num_runs = $group.Count
    }

    foreach ($metricName in $derivedMetricNames) {
        $values = @()
        foreach ($entry in $group.Group) {
            $values += [double]$entry.row."${metricName}_mean"
        }

        $mean = ($values | Measure-Object -Average).Average
        $std = Get-SampleStdDev -Values $values
        $rowData["${metricName}_mean"] = Format-Double -Value $mean
        $rowData["${metricName}_std"] = Format-Double -Value $std
    }

    $derivedSummaryRows.Add([pscustomobject]$rowData)
}

$derivedSummaryPath = Join-Path $summaryDir 'derived_summary.csv'
$derivedSummaryRows |
    Sort-Object @{ Expression = { [string]$_.family_member } } |
    Export-Csv -LiteralPath $derivedSummaryPath -NoTypeInformation

$markdownPath = Join-Path $summaryDir 'summary.md'
$thresholdSummary = Import-Csv -LiteralPath $thresholdSummaryPath
$derivedSummary = Import-Csv -LiteralPath $derivedSummaryPath

$thresholdLines = @()
$thresholdLines += '# Paper Sweep Summary'
$thresholdLines += ''
$thresholdLines += '## Threshold'
$thresholdLines += ''
$thresholdLines += '| batch | mode | runs | exec tfhe mean (ms) | prover mean (ms) | verifier mean (ms) | verify_tfhe mean (us) | proof mean (MiB) | comm mean (KiB) |'
$thresholdLines += '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |'
foreach ($row in ($thresholdSummary | Sort-Object @{ Expression = { [int]$_.batch_size } }, @{ Expression = { [string]$_.mode } })) {
    $thresholdLines += (
        '| {0} | {1} | {2} | {3:N3} | {4:N3} | {5:N3} | {6:N3} | {7:N3} | {8:N3} |' -f
        [int]$row.batch_size,
        [string]$row.mode,
        [int]$row.num_runs,
        ([double]$row.exec_tfhe_us_mean / 1000.0),
        ([double]$row.prover_us_mean / 1000.0),
        ([double]$row.verifier_us_mean / 1000.0),
        [double]$row.verify_tfhe_us_mean,
        ([double]$row.proof_size_bytes_mean / 1MB),
        ([double]$row.total_online_comm_bytes_mean / 1KB)
    )
}

$thresholdLines += ''
$thresholdLines += '## Derived'
$thresholdLines += ''
$thresholdLines += '| member | runs | arity | lin | pbs | depth | tfhe mean (ms) | prover mean (ms) | verifier mean (ms) | proof mean (KiB) | comm mean (KiB) |'
$thresholdLines += '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |'
foreach ($row in ($derivedSummary | Sort-Object family_member)) {
    $thresholdLines += (
        '| {0} | {1} | {2} | {3} | {4} | {5} | {6:N3} | {7:N3} | {8:N3} | {9:N3} | {10:N3} |' -f
        [string]$row.family_member,
        [int]$row.num_runs,
        [int]$row.arity,
        [int]$row.num_linear_stages,
        [int]$row.num_pbs,
        [int]$row.pbs_depth,
        ([double]$row.tfhe_eval_us_mean / 1000.0),
        ([double]$row.prover_us_mean / 1000.0),
        ([double]$row.verifier_us_mean / 1000.0),
        ([double]$row.proof_size_bytes_mean / 1KB),
        ([double]$row.total_online_comm_bytes_mean / 1KB)
    )
}

$thresholdLines += ''
$thresholdLines += '## Checks'
$thresholdLines += ''

if ($warnings.Count -eq 0 -and $errors.Count -eq 0) {
    $thresholdLines += '- All aggregation checks passed.'
} else {
    foreach ($warning in $warnings) {
        $thresholdLines += "- Warning: $warning"
    }
    foreach ($error in $errors) {
        $thresholdLines += "- Error: $error"
    }
}

Set-Content -LiteralPath $markdownPath -Value $thresholdLines

if ($errors.Count -gt 0) {
    throw ($errors -join [Environment]::NewLine)
}

Write-Host "Wrote threshold summary to $thresholdSummaryPath"
Write-Host "Wrote derived summary to $derivedSummaryPath"
Write-Host "Wrote markdown summary to $markdownPath"
