# PIVOT - regression tests
#
# Builds the tool, ingests the synthetic prefetch fixtures and checks the
# expected output of every command.
#
#   powershell -ExecutionPolicy Bypass -File tests\run_tests.ps1
#
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "bin\release\pivot.exe"
$tmp = Join-Path $env:TEMP ("pivot_test_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$store = Join-Path $tmp "test.store"
$json = Join-Path $tmp "test.json"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$script:pass = 0
$script:fail = 0

function Check($name, $condition, $detail) {
    if ($condition) {
        $script:pass++
        Write-Host ("  [ok]   " + $name) -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host ("  [FAIL] " + $name) -ForegroundColor Red
        if ($detail) { Write-Host ("         " + $detail) -ForegroundColor DarkGray }
    }
}

function Run($argv) {
    $out = & $exe @argv 2>&1 | Out-String
    return @{ text = $out; code = $LASTEXITCODE }
}

Write-Host "== build ==" -ForegroundColor Cyan
Push-Location $root
& cmd /c "build.bat release" | Out-Null
Pop-Location
Check "pivot.exe exists" (Test-Path $exe) $exe

Write-Host "== ingest ==" -ForegroundColor Cyan
$r = Run @("ingest", (Join-Path $root "tests\fixtures"), "--store", $store)
Check "ingest reports 8 records" ($r.text -match "8 records") $r.text
Check "ingest skips nothing" ($r.text -match "0 skipped") $r.text

Write-Host "== prefetch parsing ==" -ForegroundColor Cyan
$r = Run @("show", "pfhash:7438817f", "--store", $store, "-v")
Check "v30 executable parsed" ($r.text -match "executable\s+: TestApp\.exe") $r.text
Check "v30 run count parsed" ($r.text -match "run_count\s+: 3") $r.text
Check "v30 volume serial parsed" ($r.text -match "volume_serial\s+: 1234abcd") $r.text
Check "v30 device path parsed" ($r.text -match "device\s+: C:") $r.text
$r = Run @("show", "path:explorer.exe", "--store", $store, "-v")
Check "v17 executable parsed" ($r.text -match "executable\s+: explorer\.exe") $r.text
Check "v17 version parsed" ($r.text -match "version\s+: 17") $r.text
$r = Run @("show", "path:notepad.exe", "--store", $store, "-v")
Check "v26 executable parsed" ($r.text -match "executable\s+: notepad\.exe") $r.text

Write-Host "== hash resolution ==" -ForegroundColor Cyan
$r = Run @("resolve", "pfhash:7438817f", "--store", $store, "--candidates", (Join-Path $root "tests\candidates.txt"))
Check "hash resolves to a candidate path" ($r.text -match [regex]::Escape("C:\Program Files\TestApp\TestApp.exe")) $r.text
Check "resolution names the algorithm" ($r.text -match "ror13-add") $r.text
$r = Run @("unresolved", "--store", $store, "--candidates", (Join-Path $root "tests\candidates.txt"))
Check "nothing unresolved with candidates" ($r.text -match "0 unresolved") $r.text
$r = Run @("unresolved", "--store", $store)
Check "3 unresolved without candidates" ($r.text -match "3 unresolved") $r.text

Write-Host "== index and timeline ==" -ForegroundColor Cyan
$r = Run @("stats", "--store", $store)
Check "stats counts 8 records" ($r.text -match "records\s+: 8") $r.text
Check "stats counts 3 prefetch records" ($r.text -match "prefetch\s+3") $r.text
Check "stats counts 5 ref records" ($r.text -match "prefetch\.ref\s+5") $r.text
$r = Run @("timeline", "--store", $store, "--from", "2025-12-31", "--to", "2026-01-02")
Check "timeline has 3 entries" ($r.text -match "3 entries") $r.text
$r = Run @("ids", "--store", $store, "--limit", "100")
Check "ids contain the prefetch hash" ($r.text -match "pfhash:7438817f") $r.text
Check "ids contain the volume serial" ($r.text -match "vserial:1234abcd") $r.text
Check "ids contain no garbage" ($r.text -notmatch "path:\uFFFD") $r.text

Write-Host "== json export ==" -ForegroundColor Cyan
$r = Run @("ingest", (Join-Path $root "tests\fixtures"), "--store", $store, "--json", $json)
if (-not (Test-Path $json)) { Write-Host ("         ingest said: " + $r.text) -ForegroundColor DarkGray }
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = "C:\Users\rrifa\AppData\Local\Programs\Python\Python311\python.exe" }
if (Test-Path $py) {
    $check = & $py -c "import json,sys; d=json.load(open(sys.argv[1],encoding='utf-8')); print(len(d))" $json
    Check "json export parses" ($check -eq "8") "records in json: $check"
} else {
    Write-Host "  [skip] python not available for the json check" -ForegroundColor Yellow
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-Host ""
Write-Host ("passed: " + $script:pass + "   failed: " + $script:fail) -ForegroundColor Cyan
if ($script:fail -gt 0) { exit 1 }
exit 0
