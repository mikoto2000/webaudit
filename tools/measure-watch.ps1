# Windows / PowerShell 7. Build first:
# go build -o dist/watch-benchmark.exe ./tools/watch-benchmark
param(
    [ValidateSet('engine', 'reader', 'idle', 'hooks', 'simulated', 'soak')]
    [string]$Mode = 'engine',
    [int]$Lines = 10000,
    [int]$Files = 32,
    [string]$Duration = '10s',
    [switch]$Geo,
    [string]$BenchmarkPath,
    [string]$OutputDir
)
$ErrorActionPreference = 'Stop'
$measureRoot = Split-Path $PSScriptRoot -Parent
if (!$BenchmarkPath) { $BenchmarkPath = Join-Path $measureRoot 'dist/watch-benchmark.exe' }
if (!$OutputDir) { $OutputDir = Join-Path $measureRoot 'docs/measurements/watch' }
$measureBinary = (Resolve-Path -LiteralPath $BenchmarkPath).Path
$measureStart = [Diagnostics.ProcessStartInfo]::new()
$measureStart.FileName = $measureBinary
$measureStart.WorkingDirectory = $measureRoot
$measureStart.UseShellExecute = $false
$measureStart.CreateNoWindow = $true
$measureStart.RedirectStandardOutput = $true
$measureStart.RedirectStandardError = $true
foreach ($value in @('-mode', $Mode, '-lines', "$Lines", '-files', "$Files", '-duration', $Duration)) {
    $measureStart.ArgumentList.Add($value)
}
if ($Geo) { $measureStart.ArgumentList.Add('-geoip') }
$measureProcess = [Diagnostics.Process]::Start($measureStart)
try {
    $measureClock = [Diagnostics.Stopwatch]::StartNew()
    $measureOut = $measureProcess.StandardOutput.ReadToEndAsync()
    $measureErr = $measureProcess.StandardError.ReadToEndAsync()
    $measurePeak = 0L
    while (!$measureProcess.HasExited) {
        $measureProcess.Refresh()
        try { $measurePeak = [Math]::Max($measurePeak, $measureProcess.PeakWorkingSet64) } catch { }
        Start-Sleep -Milliseconds 50
    }
    $measureProcess.WaitForExit()
    $measureClock.Stop()
    $measureText = $measureOut.GetAwaiter().GetResult()
    $measureError = $measureErr.GetAwaiter().GetResult()
    if ($measureProcess.ExitCode -ne 0) { throw $measureError }
    $measureData = $measureText | ConvertFrom-Json
    $measureData | Add-Member source_commit (git -C $measureRoot rev-parse HEAD)
    $measureData | Add-Member scenario ([ordered]@{ lines = $Lines; files = $Files; duration = $Duration })
    $measureData | Add-Member process_cpu_seconds $measureProcess.TotalProcessorTime.TotalSeconds
    $measureData | Add-Member sampled_peak_working_set_bytes $measurePeak
    $measureData | Add-Member process_wall_seconds $measureClock.Elapsed.TotalSeconds
    $measureData | Add-Member cpu_one_core_percent (100 * $measureProcess.TotalProcessorTime.TotalSeconds / $measureClock.Elapsed.TotalSeconds)
    $measureData | Add-Member diagnostics $measureError.Trim()
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $measureSuffix = if ($Geo) { '-geoip' } else { '' }
    $measureData | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDir "$Mode$measureSuffix.json") -Encoding utf8
    $measureData
} finally {
    if (!$measureProcess.HasExited) { $measureProcess.Kill($true); $measureProcess.WaitForExit() }
    $measureProcess.Dispose()
}
