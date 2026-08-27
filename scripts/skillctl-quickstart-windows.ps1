<#
.SYNOPSIS
  Windows quickstart SMOKE TEST for skillctl: walks the author->sign->verify->trust
  lifecycle end-to-end in a throwaway temp dir and prints PASS/FAIL per step.

.DESCRIPTION
  The Windows twin of the demo/kup-training/run-and-prove.sh proof: each lifecycle
  step is executed and asserted (exit code + load-bearing artifact), with a green
  [PASS] / red [FAIL] line and a final summary. Exits non-zero iff any REQUIRED
  step failed (exit 0 iff every required step passed) -- safe to wire into CI.

  Lifecycle walked (all OFFLINE -- no network, no live registry):
    1. version     skillctl version prints a non-empty version string
    2. keygen      skillctl keygen --out <tmp>\author        (author.priv + author.pub)
    3. pack        skillctl pack a throwaway skill dir into <tmp>\demo.skb
    4. sign        skillctl sign --key <tmp>\author.priv <tmp>\demo.skb
    5. verify-sig  skillctl verify-sig --pubkey <tmp>\author.pub <tmp>\demo.skb  (exit 0)
    6. trust add   skillctl trust add --registry <sandbox-url> --pubkey <tmp>\author.pub
    7. tamper      flip a byte in a COPY of the .skb, re-point the sidecar sig at the
                   tampered digest, and assert verify-sig REFUSES it (fail-closed:
                   ideal exit 11 = author signature invalid; any non-zero = refused)

  Design notes (why this is safe + idempotent):
    * Everything happens in a fresh %TEMP%\skillctl-quickstart-<guid> dir, removed on
      exit (keep it with -KeepWork). A new GUID each run makes the script re-runnable.
    * `skillctl trust add` writes ~/.claude/skill-trust-roots.yaml. skillctl resolves
      that home via $HOME first on ALL platforms (pkg/skillctl/verify/home.go), so we
      point $env:HOME at the sandbox dir for the run -- the REAL user trust roots are
      never touched. (env change is process-local and dies with this PowerShell.)
    * NEVER prints a private key, signature bytes, or any secret. Only public paths,
      digests, and exit codes are shown.
    * `--registry self` is NOT valid -- validateRegistryURL requires https:// (or
      loopback http://). We pin a never-contacted https:// sandbox URL; nothing on the
      network is ever reached (trust add only writes local YAML).

.PARAMETER KeepWork
  Do not delete the temp working dir on exit (for debugging). Its path is printed.

.PARAMETER Help
  Show usage and exit.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\skillctl-quickstart-windows.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\skillctl-quickstart-windows.ps1 -KeepWork

.NOTES
  Locate the binary (first match wins):
    $env:SKILLCTL                                   explicit path (authoritative)
    skillctl / skillctl.exe on PATH
    %LOCALAPPDATA%\Programs\skillctl\skillctl.exe   default install location
#>
param(
    [switch]$KeepWork,
    [switch]$Help
)
# NB: deliberately NOT [CmdletBinding()] -- a plain script collects unmatched tokens
# (e.g. -h / --help) into $args instead of throwing a parameter-binding error.

$ErrorActionPreference = 'Continue'   # a native non-zero exit must not abort the run

if ($Help -or $args -contains '-h' -or $args -contains '--help') {
    Get-Help -Detailed $MyInvocation.MyCommand.Path
    exit 0
}

# ---- counters + printers ---------------------------------------------------
$script:ReqPass = 0; $script:ReqFail = 0; $script:Skipped = 0
# Sandbox state (set once we redirect $HOME / create the temp dir).
$script:Work = $null; $script:OrigHome = $null; $script:HomeRedirected = $false
function Write-Pass($m){ Write-Host "  [PASS] $m" -ForegroundColor Green; $script:ReqPass++ }
function Write-Fail($m,$fix){ Write-Host "  [FAIL] $m" -ForegroundColor Red; if($fix){ Write-Host "         -> $fix" -ForegroundColor Yellow }; $script:ReqFail++ }
function Write-Skip($m,$why){ Write-Host "  [SKIP] $m" -ForegroundColor Cyan; if($why){ Write-Host "         -> $why" }; $script:Skipped++ }
function Write-Stage($m){ Write-Host ""; Write-Host "== $m ==" -ForegroundColor Cyan }

# ---- run skillctl, capture stdout, return @{ Code; Out } -------------------
# stderr ([config]/[auth] noise) is discarded; we grade stdout + exit code.
function Invoke-Skillctl {
    param([string]$Bin, [string[]]$Arguments)   # NB: not $Args (a PS automatic variable)
    $out = & $Bin @Arguments 2>$null
    return @{ Code = $LASTEXITCODE; Out = ($out | Out-String) }
}

# ---- summary + exit --------------------------------------------------------
# Central exit point so the temp dir cleanup and $HOME restore always run.
function Complete-Run {
    # Restore $HOME only if we actually redirected it (process-local, but polite
    # if this script is dot-sourced).
    if ($script:HomeRedirected) {
        if ($null -ne $script:OrigHome) { $env:HOME = $script:OrigHome }
        else { Remove-Item Env:\HOME -ErrorAction SilentlyContinue }
    }
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        if ($KeepWork) { Write-Host "  work dir kept: $script:Work" -ForegroundColor Yellow }
        else { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Write-Host ""; Write-Host "== SUMMARY ==" -ForegroundColor Cyan
    $failColor = if ($script:ReqFail -gt 0) { 'Red' } else { 'Gray' }
    Write-Host ("  required: {0} passed / " -f $script:ReqPass) -NoNewline
    Write-Host ("{0} FAILED" -f $script:ReqFail) -ForegroundColor $failColor -NoNewline
    Write-Host ("   skipped: {0}" -f $script:Skipped)
    if ($script:ReqFail -gt 0) {
        Write-Host ("  RESULT: FAIL - {0} required step(s) failed" -f $script:ReqFail) -ForegroundColor Red
        exit 1
    }
    Write-Host "  RESULT: PASS - skillctl quickstart lifecycle green" -ForegroundColor Green
    exit 0
}

Write-Host "skillctl - Windows quickstart smoke test (author -> sign -> verify -> trust -> tamper)" -ForegroundColor Cyan

# ===========================================================================
# Locate skillctl.exe
# ===========================================================================
Write-Stage "Locate skillctl"
$Bin = $null
if ($env:SKILLCTL) {
    if (Test-Path -LiteralPath $env:SKILLCTL -PathType Leaf) { $Bin = (Resolve-Path -LiteralPath $env:SKILLCTL).Path }
    else { Write-Fail "skillctl located: `$env:SKILLCTL=$($env:SKILLCTL) is not a file" "point SKILLCTL at skillctl.exe (or clear it to auto-discover)" }
} else {
    $cmd = Get-Command skillctl -ErrorAction SilentlyContinue
    $cands = @()
    if ($cmd) { $cands += $cmd.Source }
    if ($env:LOCALAPPDATA) { $cands += (Join-Path $env:LOCALAPPDATA "Programs\skillctl\skillctl.exe") }
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { $Bin = (Resolve-Path -LiteralPath $c).Path; break } }
    if (-not $Bin) { Write-Fail "skillctl located" "not via `$env:SKILLCTL / PATH / %LOCALAPPDATA%\Programs\skillctl - build it (go build ./cmd/skillctl) or set `$env:SKILLCTL" }
}
if (-not $Bin) { Complete-Run }
Write-Pass "skillctl located: $Bin"

# ===========================================================================
# Sandbox: fresh temp work dir + $HOME redirect (so trust add cannot clobber
# the real ~/.claude/skill-trust-roots.yaml)
# ===========================================================================
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("skillctl-quickstart-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$script:Work = $Work
$script:OrigHome = if (Test-Path Env:\HOME) { $env:HOME } else { $null }
$env:HOME = $Work   # sandbox trust-roots writes (verify/home.go honors $HOME on all platforms)
$script:HomeRedirected = $true
Write-Host "  work dir: $Work"

# ===========================================================================
# Step 1 - version
# ===========================================================================
Write-Stage "Step 1 - version"
$r = Invoke-Skillctl -Bin $Bin -Arguments @('version')
$ver = ($r.Out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
if ($r.Code -eq 0 -and $ver) { Write-Pass "version prints '$($ver.Trim())'" }
else { Write-Fail "version failed (exit $($r.Code))" "wrong/broken binary - re-check the located skillctl.exe" }

# ===========================================================================
# Step 2 - keygen
# ===========================================================================
Write-Stage "Step 2 - keygen"
$authorStem = Join-Path $Work "author"
$priv = "$authorStem.priv"; $pub = "$authorStem.pub"
$keygenOk = $false
$r = Invoke-Skillctl -Bin $Bin -Arguments @('keygen','--out',$authorStem)
if ($r.Code -eq 0 -and (Test-Path -LiteralPath $priv -PathType Leaf) -and (Test-Path -LiteralPath $pub -PathType Leaf)) {
    Write-Pass "keygen wrote author.priv + author.pub"   # deliberately NOT echoing key contents
    $keygenOk = $true
} else {
    Write-Fail "keygen did not produce both key files (exit $($r.Code))" "check 'skillctl keygen --out <stem>' writes <stem>.priv and <stem>.pub"
}

# ===========================================================================
# Step 3 - pack a throwaway skill dir into demo.skb
# ===========================================================================
Write-Stage "Step 3 - pack"
$skillDir = Join-Path $Work "skill"
New-Item -ItemType Directory -Path $skillDir -Force | Out-Null
# Minimal SKILL.md. Pack only REQUIRES the file to exist (skillbundle.Pack os.Stat);
# name/version come from CLI flags, not the front-matter. Mirror the house front-matter
# so the fixture reads like a real skill.
$skillMd = @"
---
name: skillctl-quickstart-smoke
version: 0.0.1
governance_level: green
---

# skillctl-quickstart-smoke

Throwaway skill packed by scripts\skillctl-quickstart-windows.ps1 to prove the
author -> sign -> verify -> trust lifecycle runs on Windows. Not for install.
"@
Set-Content -LiteralPath (Join-Path $skillDir "SKILL.md") -Value $skillMd -Encoding UTF8
$bundle = Join-Path $Work "demo.skb"
$packOk = $false
if ($keygenOk) {
    $r = Invoke-Skillctl -Bin $Bin -Arguments @('pack','--skill',$skillDir,'-o',$bundle,'--name','skillctl-quickstart-smoke','--version','0.0.1')
    if ($r.Code -eq 0 -and (Test-Path -LiteralPath $bundle -PathType Leaf) -and ((Get-Item -LiteralPath $bundle).Length -ge 128)) {
        Write-Pass "pack wrote demo.skb ($((Get-Item -LiteralPath $bundle).Length) bytes)"
        $packOk = $true
    } else {
        Write-Fail "pack did not produce a non-trivial demo.skb (exit $($r.Code))" "pack needs --skill/-o/--name/--version and a SKILL.md in the skill dir"
    }
} else {
    Write-Skip "pack" "keygen failed - nothing to sign afterwards"
}

# ===========================================================================
# Step 4 - sign  (flags BEFORE the positional bundle: Go flag stops at first non-flag)
# ===========================================================================
Write-Stage "Step 4 - sign"
$signOk = $false
if ($packOk) {
    $r = Invoke-Skillctl -Bin $Bin -Arguments @('sign','--key',$priv,$bundle)
    # sign writes <bundle>.<digest_hex>.author.sig next to the bundle.
    $sig = Get-ChildItem -LiteralPath $Work -Filter "demo.skb.*.author.sig" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($r.Code -eq 0 -and $sig) {
        Write-Pass "sign wrote detached signature ($($sig.Name))"
        $signOk = $true
    } else {
        Write-Fail "sign did not produce a signature (exit $($r.Code))" "check 'skillctl sign --key <priv> <bundle>' (flag before the bundle arg)"
    }
} else {
    Write-Skip "sign" "pack did not produce a bundle"
}

# ===========================================================================
# Step 5 - verify-sig  (expect exit 0)
# ===========================================================================
Write-Stage "Step 5 - verify-sig"
$verifyOk = $false
if ($signOk) {
    $r = Invoke-Skillctl -Bin $Bin -Arguments @('verify-sig','--pubkey',$pub,$bundle)
    if ($r.Code -eq 0) {
        Write-Pass "verify-sig accepts the genuine bundle (exit 0)"
        $verifyOk = $true
    } else {
        Write-Fail "verify-sig rejected a genuine bundle (exit $($r.Code))" "sign/verify key mismatch, or sidecar sig name drift"
    }
} else {
    Write-Skip "verify-sig" "no signature to verify"
}

# ===========================================================================
# Step 6 - trust add  (offline: writes local YAML only, sandboxed via $HOME)
# ===========================================================================
Write-Stage "Step 6 - trust add"
if ($keygenOk) {
    # `--registry self` is invalid (validateRegistryURL requires https:// or loopback
    # http://). Pin a never-contacted https:// sandbox URL; trust add only writes YAML.
    $registry = "https://skillctl-quickstart.invalid/api/skills"
    $r = Invoke-Skillctl -Bin $Bin -Arguments @('trust','add','--registry',$registry,'--pubkey',$pub)
    $trustFile = Join-Path $Work ".claude\skill-trust-roots.yaml"
    if ($r.Code -eq 0 -and (Test-Path -LiteralPath $trustFile -PathType Leaf) -and
        (Select-String -LiteralPath $trustFile -Pattern ([regex]::Escape($registry)) -Quiet -ErrorAction SilentlyContinue)) {
        Write-Pass "trust add pinned the author pubkey (sandboxed trust-roots.yaml)"
    } else {
        Write-Fail "trust add did not pin the registry (exit $($r.Code))" "check 'skillctl trust add --registry <https-url> --pubkey <pub>'"
    }
} else {
    Write-Skip "trust add" "no pubkey to pin"
}

# ===========================================================================
# Step 7 - tamper check  (fail-closed: a modified bundle must NOT verify)
# ===========================================================================
Write-Stage "Step 7 - tamper check (fail-closed)"
if ($verifyOk) {
    $tamperDir = Join-Path $Work "tamper"
    New-Item -ItemType Directory -Path $tamperDir -Force | Out-Null
    $tampered = Join-Path $tamperDir "tampered.skb"
    Copy-Item -LiteralPath $bundle -Destination $tampered -Force

    # Flip one byte in the COPY (xor 0xFF always changes the value; length preserved).
    $bytes = [System.IO.File]::ReadAllBytes($tampered)
    $idx = [int][math]::Floor($bytes.Length / 2)
    $bytes[$idx] = $bytes[$idx] -bxor 0xFF
    [System.IO.File]::WriteAllBytes($tampered, $bytes)

    # verify-sig recomputes the digest and looks for <bundle>.<newdigest>.author.sig.
    # Re-point the ORIGINAL (valid-for-original-bytes) sig at the tampered digest so the
    # refusal is the strong crypto path (exit 11 = signature invalid) rather than the
    # weaker "sig file not found" (exit 1). Both are fail-closed; 11 is the real proof.
    $origSig = Get-ChildItem -LiteralPath $Work -Filter "demo.skb.*.author.sig" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($origSig) {
        $newHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tampered).Hash.ToLower()
        $tamperSig = Join-Path $tamperDir ("tampered.skb." + $newHash + ".author.sig")
        Copy-Item -LiteralPath $origSig.FullName -Destination $tamperSig -Force
    }

    $r = Invoke-Skillctl -Bin $Bin -Arguments @('verify-sig','--pubkey',$pub,$tampered)
    if ($r.Code -eq 11) {
        Write-Pass "tamper REFUSED with exit 11 (author signature invalid) - fail-closed proven"
    } elseif ($r.Code -ne 0) {
        Write-Pass "tamper REFUSED with exit $($r.Code) (non-zero, fail-closed; ideal is 11)"
    } else {
        Write-Fail "CRITICAL: verify-sig ACCEPTED a tampered bundle (fail-OPEN)" "a modified .skb must never verify - this is a trust-chain breach"
    }
} else {
    Write-Skip "tamper check" "genuine verify-sig did not pass, so a tamper delta is not meaningful"
}

Complete-Run
