<#
.SYNOPSIS
  QA acceptance track for a FRESH m3c-tools v2.10.0 install on a Windows target device.

.DESCRIPTION
  Windows twin of scripts/qa-target-device.sh. Runs the automatable checks and prints a
  PASS/FAIL line per check plus a summary. Exits non-zero if any REQUIRED check fails.

  Windows reality (by design):
    * record / devices / screenshot are macOS-only  -> here they must FAIL (expected-unsupported)
    * plaud has only the LEGACY surface (auth/list/check/sync/fix-times) -> 'plaud dev' is NOT present
  So the mac-only capture checks are NOT run as expected-PASS; instead the "unsupported" gate
  asserts they fail correctly.

  OFFLINE by default. Network stages (check-er1, transcript smoke) run only with -Online or
  when $env:QA_ONLINE = '1'. Read-only, idempotent, safe to re-run. NEVER prints ER1_API_KEY
  or any secret (key presence is checked with a quiet match).

.PARAMETER Online
  Also run the network stages (check-er1, transcript smoke).

.PARAMETER Help
  Show usage and exit.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\qa-target-device.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\qa-target-device.ps1 -Online

.NOTES
  Env overrides:
    $env:M3C                 path to m3c-tools.exe (wins over PATH/build)
    $env:M3C_ENV             extra config file to inspect first
    $env:QA_ONLINE = '1'     same as -Online
    $env:M3C_EXPECT_VERSION  expected release version (default 2.10.0)
#>
param(
    [switch]$Online,
    [switch]$Help
)
# NB: deliberately NOT [CmdletBinding()]: a plain script collects unmatched tokens
# (e.g. -h / --help) into $args instead of throwing a parameter-binding error.

$ErrorActionPreference = 'Continue'   # a native non-zero exit must not abort the run

if ($Help -or $args -contains '-h' -or $args -contains '--help') {
    Get-Help -Detailed $MyInvocation.MyCommand.Path
    exit 0
}

$ExpectVersion = if ($env:M3C_EXPECT_VERSION) { $env:M3C_EXPECT_VERSION } else { '2.10.0' }
if ($env:QA_ONLINE -eq '1') { $Online = $true }

# ---- counters + printers ---------------------------------------------------
$script:ReqPass = 0; $script:ReqFail = 0; $script:SoftWarn = 0; $script:SoftPass = 0; $script:Skipped = 0
function Write-Pass($m){ Write-Host "  [PASS] $m" -ForegroundColor Green;  $script:ReqPass++ }
function Write-Fail($m,$fix){ Write-Host "  [FAIL] $m" -ForegroundColor Red; if($fix){ Write-Host "         -> $fix" -ForegroundColor Yellow }; $script:ReqFail++ }
function Write-Warn($m,$fix){ Write-Host "  [WARN] $m" -ForegroundColor Yellow; if($fix){ Write-Host "         -> $fix" }; $script:SoftWarn++ }
function Write-Soft($m){ Write-Host "  [ ok ] $m" -ForegroundColor Cyan; $script:SoftPass++ }
function Write-Skip($m){ Write-Host "  [SKIP] $m" -ForegroundColor Cyan; $script:Skipped++ }
function Write-Stage($m){ Write-Host ""; Write-Host "== $m ==" -ForegroundColor Cyan }

# ---- run a native command, capture stdout, return @{ Code; Out } -----------
# stderr (the [config]/[auth] noise) is discarded; we grade stdout + exit code.
function Invoke-M3C {
    param([string]$Bin, [string[]]$Arguments)   # NB: not $Args (a PS automatic variable)
    $out = & $Bin @Arguments 2>$null
    return @{ Code = $LASTEXITCODE; Out = ($out | Out-String) }
}

Write-Host "m3c-tools - QA target-device acceptance track (Windows)" -ForegroundColor Cyan
Write-Host ("platform=Windows  mode={0}  expect-version={1}" -f ($(if($Online){'ONLINE'}else{'offline'}), $ExpectVersion))

# ===========================================================================
# Stage A - Binary integrity & runs
# ===========================================================================
Write-Stage "Stage A - Binary integrity & runs"

# A1: locate binary. Explicit $env:M3C is authoritative (no fallback); else PATH, then build\.
$Bin = $null
if ($env:M3C) {
    if (Test-Path -LiteralPath $env:M3C -PathType Leaf) { $Bin = $env:M3C }
    else { Write-Fail "A1 binary: `$env:M3C=$($env:M3C) is not a file" "point M3C at m3c-tools.exe (or clear it to auto-discover)" }
} else {
    $cmd = Get-Command m3c-tools -ErrorAction SilentlyContinue
    $cands = @()
    if ($cmd) { $cands += $cmd.Source }
    $cands += ".\m3c-tools.exe"
    $cands += ".\build\windows\m3c-tools.exe"
    $cands += (Join-Path $PSScriptRoot "..\build\windows\m3c-tools.exe")
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { $Bin = (Resolve-Path -LiteralPath $c).Path; break } }
    if (-not $Bin) { Write-Fail "A1 binary located" "not on PATH / .\build\windows\m3c-tools.exe - install v$ExpectVersion or set `$env:M3C" }
}
if (-not $Bin) {
    Write-Host ""; Write-Host "== SUMMARY ==" -ForegroundColor Cyan
    Write-Host ("  required: {0} passed / {1} FAILED   soft: {2} ok / {3} warn   skipped: {4}" -f $ReqPass,$ReqFail,$SoftPass,$SoftWarn,$Skipped)
    Write-Host "  RESULT: FAIL (m3c-tools binary not found - nothing else could run)" -ForegroundColor Red
    exit 1
}
Write-Pass "A1 binary located: $Bin"

# A2: version prints a real version (stdout is clean; [config]/[auth] noise is on stderr).
$r = Invoke-M3C -Bin $Bin -Arguments @('version')
if ($r.Code -eq 0) {
    $line = ($r.Out -split "`r?`n" | Where-Object { $_ -match '^m3c-tools ' } | Select-Object -First 1)
    if ($line) {
        $tok = ($line -split '\s+')[1]
        if     ($tok -eq $ExpectVersion) { Write-Pass "A2 version = $ExpectVersion" }
        elseif ($tok -eq 'dev')          { Write-Warn "A2 version prints 'dev' (unreleased/local build)" "install the official v$ExpectVersion artifact for real acceptance" }
        else                             { Write-Warn "A2 version = $tok (expected $ExpectVersion)" "confirm this is the intended release" }
    } else { Write-Fail "A2 version output not recognized" "expected 'm3c-tools $ExpectVersion (commit=..., built=...)'" }
} else { Write-Fail "A2 version command failed (exit $($r.Code))" "wrong platform/arch binary - re-check A1 / re-download" }

# ===========================================================================
# Stage B - Config present & valid  (never echoes values)
# ===========================================================================
Write-Stage "Stage B - Config present & valid"

$cfgFiles = New-Object System.Collections.Generic.List[string]
function Add-Cfg($p) {
    if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) {
        $full = (Resolve-Path -LiteralPath $p).Path
        if (-not $cfgFiles.Contains($full)) { $cfgFiles.Add($full) }
    }
}
Add-Cfg $env:M3C_ENV
Add-Cfg ".\.env"
Add-Cfg (Join-Path $PSScriptRoot "..\.env")
Add-Cfg (Join-Path $env:USERPROFILE ".m3c-tools.env")
$apFile = Join-Path $env:USERPROFILE ".m3c-tools\active-profile"
if (Test-Path -LiteralPath $apFile -PathType Leaf) {
    $ap = (Get-Content -LiteralPath $apFile -TotalCount 1 -ErrorAction SilentlyContinue)
    if ($ap) { Add-Cfg (Join-Path $env:USERPROFILE (".m3c-tools\profiles\{0}.env" -f $ap.Trim())) }
}

if ($cfgFiles.Count -gt 0) {
    Write-Pass ("B1 config source exists: {0}" -f ($cfgFiles -join ', '))
} else {
    Write-Fail "B1 config source exists" "copy .env.example -> .env, or run 'm3c-tools login', or 'm3c-tools config create'"
}

# Key presence WITHOUT printing the value: Select-String -Quiet returns only a boolean.
function Test-Key([string]$key) {
    foreach ($f in $cfgFiles) {
        if (Select-String -LiteralPath $f -Pattern ("^\s*{0}=[^\s#]" -f $key) -Quiet -ErrorAction SilentlyContinue) { return $true }
    }
    return $false
}

if (Test-Key 'ER1_API_URL')    { Write-Pass "B2 ER1_API_URL set" }    else { Write-Fail "B2 ER1_API_URL set" "add ER1_API_URL=https://onboarding.guide/upload_2 (or your local URL)" }
if (Test-Key 'ER1_CONTEXT_ID') { Write-Pass "B3 ER1_CONTEXT_ID set" } else { Write-Fail "B3 ER1_CONTEXT_ID set" "add ER1_CONTEXT_ID=<id>; 'm3c-tools login' fills this in" }
if (Test-Key 'ER1_API_KEY')    { Write-Soft "B4 ER1_API_KEY set" }    else { Write-Warn "B4 ER1_API_KEY not in config (OK if device-token auth is active)" "run 'm3c-tools login' for a device token, or set ER1_API_KEY - see doctor Authentication" }

# ===========================================================================
# Stage C - Offline self-check (doctor)
# ===========================================================================
Write-Stage "Stage C - Offline self-check (doctor)"
$doc = Invoke-M3C -Bin $Bin -Arguments @('doctor')
if ($doc.Out -match 'Config Consistency') { Write-Pass "C1 doctor produced a diagnostics report" }
else { Write-Fail "C1 doctor did not produce a report" "profile likely broken - 'm3c-tools config list' / 'config switch <name>'" }
if ($Online) {
    if ($doc.Code -eq 0 -and $doc.Out -match 'ALL CHECKS PASSED') { Write-Pass "C2 doctor full pass (ALL CHECKS PASSED)" }
    else {
        $firstBad = ($doc.Out -split "`r?`n" | Where-Object { $_ -match 'FAIL|✗|!  ' } | Select-Object -First 1)
        Write-Fail "C2 doctor full pass (exit $($doc.Code))" ("first issue: {0}; fix the named subsystem then re-run" -f ($(if($firstBad){$firstBad.Trim()}else{'see doctor output'})))
    }
} else { Write-Skip "C2 doctor full pass - ONLINE only (re-run with -Online)" }

# ===========================================================================
# Stage D - Online ER1 connectivity  (ONLINE only)
# ===========================================================================
Write-Stage "Stage D - Online ER1 connectivity"
if ($Online) {
    $er1 = Invoke-M3C -Bin $Bin -Arguments @('check-er1')
    if ($er1.Code -eq 0 -and $er1.Out -match 'REACHABLE' -and $er1.Out -match 'Auth check: OK') {
        Write-Pass "D1 check-er1 REACHABLE + auth OK"
    } elseif ($er1.Out -match 'UNREACHABLE') {
        Write-Fail "D1 check-er1 UNREACHABLE" "check network/VPN + ER1_API_URL; 'm3c-tools doctor' localizes DNS/TLS/health"
    } elseif ($er1.Out -match 'Auth check: FAILED') {
        Write-Fail "D1 check-er1 auth FAILED" "token/API-key invalid or expired - run 'm3c-tools login' or fix ER1_API_KEY"
    } else {
        Write-Fail "D1 check-er1 failed (exit $($er1.Code))" "possible transient network error - re-run; if it persists check connectivity"
    }
} else { Write-Skip "D1 check-er1 - ONLINE only (re-run with -Online)" }

# ===========================================================================
# Stage E - Core capture smoke test
# ===========================================================================
Write-Stage "Stage E - Core capture smoke test"
if ($Online) {
    $tr = Invoke-M3C -Bin $Bin -Arguments @('transcript','dQw4w9WgXcQ','--list')
    if ($tr.Code -eq 0 -and $tr.Out.Trim()) {
        $n = (($tr.Out -split "`r?`n") | Where-Object { $_.Trim() }).Count
        Write-Pass "E1 transcript --list smoke ($n track(s))"
    } else {
        Write-Fail "E1 transcript --list smoke (exit $($tr.Code))" "YouTube 429/network? tool degrades gracefully - retry later or set YT_PROXY_URL"
    }
} else { Write-Skip "E1 transcript smoke - ONLINE only (re-run with -Online)" }

# E2: whisper presence (offline, soft). setup --check exits 1 while venv absent even if a
# system whisper exists, so grade on the 'Whisper:' line, not the exit code.
$setup = Invoke-M3C -Bin $Bin -Arguments @('setup','--check')
$whLines = ($setup.Out -split "`r?`n" | Where-Object { $_ -match '^\s*Whisper:' })
if ($whLines -and ($whLines | Where-Object { $_ -notmatch '\(not installed\)' })) {
    Write-Soft "E2 whisper present"
} else {
    Write-Warn "E2 whisper not installed (optional - only for local audio transcription)" "run 'm3c-tools setup' or put a 'whisper' binary on PATH"
}

# ===========================================================================
# Stage F - Windows-specific
# ===========================================================================
Write-Stage "Stage F - Windows-specific"

# F-win-2 (required): legacy plaud surface present (auth/list/check/sync/fix-times); NO 'plaud dev'.
$help = Invoke-M3C -Bin $Bin -Arguments @('help')
if ($help.Out -match 'plaud auth' -and $help.Out -match 'plaud list') {
    Write-Pass "F-win-2 legacy plaud surface present (auth/list/check/sync/fix-times)"
} else {
    Write-Fail "F-win-2 legacy plaud surface not found in help" "wrong/old binary - reinstall m3c-tools-windows-amd64.zip for v$ExpectVersion"
}

# F-win-1: systray/menubar entry wired (help lists it); actual launch is a manual step.
if ($help.Out -match 'menubar') { Write-Soft "F-win-1 systray/menubar command present (launch is a manual step)" }
else { Write-Warn "F-win-1 menubar command not found in help" "wrong/old binary - reinstall v$ExpectVersion" }

# F-win-3 (required, expected-FAIL gate): macOS-only commands must be UNSUPPORTED here.
$unsupportedOk = $true
foreach ($c in @('record','devices','screenshot')) {
    $u = Invoke-M3C -Bin $Bin -Arguments @($c)
    if ($u.Code -eq 0) { $unsupportedOk = $false; Write-Host "         (unexpected: '$c' returned success on Windows)" -ForegroundColor Yellow }
}
# 'plaud dev' must not be a valid subcommand on Windows (legacy plaud only).
$pd = Invoke-M3C -Bin $Bin -Arguments @('plaud','dev','status')
if ($pd.Code -eq 0) { $unsupportedOk = $false; Write-Host "         (unexpected: 'plaud dev status' returned success on Windows)" -ForegroundColor Yellow }
if ($unsupportedOk) {
    Write-Pass "F-win-3 macOS-only commands correctly unsupported (record/devices/screenshot/plaud dev all fail)"
} else {
    Write-Fail "F-win-3 a macOS-only command unexpectedly succeeded" "this is the wrong build - a Windows m3c-tools must not expose mac-only capture"
}

# ===========================================================================
# Summary
# ===========================================================================
Write-Host ""; Write-Host "== SUMMARY ==" -ForegroundColor Cyan
$failColor = if ($ReqFail -gt 0) { 'Red' } else { 'Gray' }
Write-Host ("  required: {0} passed / " -f $ReqPass) -NoNewline
Write-Host ("{0} FAILED" -f $ReqFail) -ForegroundColor $failColor -NoNewline
Write-Host ("   soft: {0} ok / {1} warn   skipped: {2}" -f $SoftPass,$SoftWarn,$Skipped)
if (-not $Online) { Write-Host "  note: offline mode - online stages (C2/D1/E1) were skipped; re-run with -Online" -ForegroundColor Yellow }
if ($ReqFail -gt 0) {
    Write-Host ("  RESULT: FAIL - {0} required check(s) failed" -f $ReqFail) -ForegroundColor Red
    exit 1
}
$suffix = if ($SoftWarn -gt 0) { " (with $SoftWarn warning(s))" } else { "" }
Write-Host ("  RESULT: PASS - all required checks passed{0}" -f $suffix) -ForegroundColor Green
exit 0
