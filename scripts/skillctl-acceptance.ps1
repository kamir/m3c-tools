<#
.SYNOPSIS
  skillctl-acceptance.ps1: the SPEC-0406 acceptance rehearsal, by hand.

.DESCRIPTION
  The twin of scripts/skillctl-acceptance.sh: same steps, same ids, same report,
  so a run from a Mac and a run from a Windows box compare line by line. When you
  change one, change the other; the pair is only useful while it stays a pair.

  It sits one level above scripts/skillctl-test.ps1. That one asks "can this
  machine build and test skillctl". This one asks "does this machine REFUSE
  correctly", which is the only half of the question a machine can answer alone.

  WHAT IT RUNS, and why it stops where it does.

  Two parties live in two separate HOME directories with two separate keys, and a
  third directory stands in for the untrusted transport. The script drives the
  real binary through:

    R1   this machine is usable                                (doctor)
    R2   the build under test is named in the report            (version)
    R3a  the sender packs a skill                               (pack)
    R3b  the sender signs it                                    (sign)
    R3c  the sender checks their OWN work before sending        (verify-sig)
    R3d  the artifact travels, unaltered, and still verifies    (verify-sig)
    R3e  an artifact ALTERED after signing is refused           (verify-sig, exit 10)
    R3f  the refusal names the cause, not a missing file        (AC-08)
    R4a..R4f  the same in the other direction                   (symmetry)

  It stops before install. `install --bundle` needs the BundleMeta envelope, and
  that envelope carries author, registry AND governance signatures: a script that
  minted it would have to hold every key, and a run in which one actor holds every
  key demonstrates nothing about two actors. The install half therefore lives in
  the automated regression, which builds each party's keys in isolation:

      go test ./cmd/skillctl/ -run TestAcceptance_TwoParty -v

  and in the real two-machine run, SPEC-0406 section 4.

.PARAMETER Skillctl
  The binary under test. Defaults to .\build\skillctl.exe, then PATH.

.PARAMETER Work
  Workspace directory. Defaults to a temp dir, removed unless -Keep.

.PARAMETER Keep
  Keep the workspace so the artifacts can be inspected.

.NOTES
  Exit: 0 every step passed; 1 a step failed; 2 usage or setup error.
#>
[CmdletBinding()]
param(
  [string]$Skillctl = "",
  [string]$Work = "",
  [switch]$Keep
)

$ErrorActionPreference = 'Continue'

$script:Ids = @(); $script:States = @(); $script:Notes = @()
$script:Failed = $false
$script:LastOut = ""

function Record {
  param([string]$Id, [string]$State, [string]$Note)
  $script:Ids += $Id; $script:States += $State; $script:Notes += $Note
  if ($State -eq 'FAIL') { $script:Failed = $true }
}

# Step runs a command and compares the exit code against the one SPEC-0406
# predicts. A step that fails for the WRONG reason is a failure: "non-zero" is
# not a result, it is the absence of one.
function Step {
  param([string]$Id, [int]$Want, [string]$Label, [string]$HomeDir, [string[]]$ArgList)
  $old = $env:HOME; $oldUp = $env:USERPROFILE
  $env:HOME = $HomeDir; $env:USERPROFILE = $HomeDir
  try {
    $script:LastOut = (& $script:Bin @ArgList 2>&1 | Out-String)
    $rc = $LASTEXITCODE
  } finally {
    $env:HOME = $old; $env:USERPROFILE = $oldUp
  }
  if ($rc -eq $Want) {
    Record $Id 'PASS' $Label
    Write-Host ("  {0,-5} PASS  {1} (exit {2})" -f $Id, $Label, $rc) -ForegroundColor Green
  } else {
    Record $Id 'FAIL' ("{0}: wanted exit {1}, got {2}" -f $Label, $Want, $rc)
    Write-Host ("  {0,-5} FAIL  {1}: wanted exit {2}, got {3}" -f $Id, $Label, $Want, $rc) -ForegroundColor Red
    ($script:LastOut -split "`n") | ForEach-Object { Write-Host ("          " + $_) }
  }
}

# Says checks the PREVIOUS step's output for a phrase. This is the AC-08 check:
# a refusal that exits correctly and explains the wrong thing still sends its
# reader after the wrong problem.
function Says {
  param([string]$Id, [string]$Needle, [string]$Label)
  if ($script:LastOut -like ("*" + $Needle + "*")) {
    Record $Id 'PASS' $Label
    Write-Host ("  {0,-5} PASS  {1}" -f $Id, $Label) -ForegroundColor Green
  } else {
    Record $Id 'FAIL' ("{0}: output never mentioned '{1}'" -f $Label, $Needle)
    Write-Host ("  {0,-5} FAIL  {1}: output never mentioned {2}" -f $Id, $Label, $Needle) -ForegroundColor Red
    ($script:LastOut -split "`n") | ForEach-Object { Write-Host ("          " + $_) }
  }
}

# ---- setup ---------------------------------------------------------------

if (-not $Skillctl) {
  if (Test-Path ".\build\skillctl.exe") { $Skillctl = ".\build\skillctl.exe" }
  elseif (Get-Command skillctl -ErrorAction SilentlyContinue) { $Skillctl = (Get-Command skillctl).Source }
  else {
    Write-Error "no skillctl found: build it (go build -o build\skillctl.exe .\cmd\skillctl) or pass -Skillctl"
    exit 2
  }
}
$script:Bin = (Resolve-Path $Skillctl).Path

if (-not $Work) {
  $Work = Join-Path ([System.IO.Path]::GetTempPath()) ("skillctl-acc-" + [guid]::NewGuid().ToString("N").Substring(0,8))
}
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$Version = (& $script:Bin version 2>$null | Select-Object -First 1)
if (-not $Version) { Write-Error "the binary at $script:Bin does not answer 'version'"; exit 2 }

Write-Host "skillctl acceptance rehearsal (SPEC-0406)"
Write-Host "binary  : $script:Bin"
Write-Host "version : $Version"
Write-Host ("platform: {0} {1}" -f [System.Environment]::OSVersion.Platform, $env:PROCESSOR_ARCHITECTURE)
Write-Host "work    : $Work"
Write-Host ""

$Transport = Join-Path $Work "transport"
New-Item -ItemType Directory -Force -Path $Transport | Out-Null

# OneParty sets up a home, a key and a demo skill. Each party gets its own of
# everything: a shared value here would quietly weaken the whole exercise.
function OneParty {
  param([string]$Who, [string]$Skill, [string]$Greeting)
  $src = Join-Path $Work "$Who\src\$Skill"
  New-Item -ItemType Directory -Force -Path $src | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $Work "$Who\keys") | Out-Null
  Set-Content -Path (Join-Path $src "SKILL.md") -Value "# $Skill`n`n$Greeting" -NoNewline
  $old = $env:HOME; $oldUp = $env:USERPROFILE
  $env:HOME = (Join-Path $Work $Who); $env:USERPROFILE = $env:HOME
  try { & $script:Bin keygen --out (Join-Path $Work "$Who\keys\$Who") | Out-Null }
  finally { $env:HOME = $old; $env:USERPROFILE = $oldUp }
}

Write-Host "== Phase 1: both sides check their installation =="
OneParty -Who "mirko" -Skill "mirko-demo-skill" -Greeting "Hello from Mirko"
OneParty -Who "eric"  -Skill "eric-demo-skill"  -Greeting "Hello from Eric"

$MirkoHome = Join-Path $Work "mirko"
$EricHome  = Join-Path $Work "eric"

# doctor is asked ONCE, about THIS machine, and deliberately not twice as if it
# were two of them.
#
# Two reasons. It reports the real environment, which is the point of the
# command, and a sandboxed answer would say nothing useful. And on Windows a
# SHIPPING build ignores $HOME for the trust-root path by design (WIN-09
# confinement), so a per-party sandbox would silently collapse into one machine
# here while still looking like two on the Unix twin. A check whose meaning
# changes between the twins is worse than a check that only runs once.
Step -Id "R1" -Want 0 -Label "this machine is usable (doctor)" -HomeDir $env:USERPROFILE -ArgList @("doctor")
Says -Id "R2" -Needle $Version -Label "the build under test is named in the report"

# Exchange plays one direction: sender seals, the artifact travels, the recipient
# checks it, then a tampered copy is checked too.
function Exchange {
  param([string]$Who, [string]$Skill, [string]$Px)
  $home = Join-Path $Work $Who
  $key  = Join-Path $Work "$Who\keys\$Who"
  $skb  = Join-Path $home "$Skill@1.0.0.skb"
  $src  = Join-Path $home "src\$Skill"

  Step -Id "$($Px)a" -Want 0 -Label "$Who`: packs the skill" -HomeDir $home `
    -ArgList @("pack","--skill",$src,"-o",$skb,"--name",$Skill,"--version","1.0.0")
  Step -Id "$($Px)b" -Want 0 -Label "$Who`: signs it" -HomeDir $home `
    -ArgList @("sign","--key","$key.priv",$skb)
  Step -Id "$($Px)c" -Want 0 -Label "$Who`: checks their OWN work before sending" -HomeDir $home `
    -ArgList @("verify-sig","--pubkey","$key.pub",$skb)

  # The artifact travels. Its signature travels with it, which is what actually
  # happens when someone sends you a signed file.
  Copy-Item $skb $Transport
  Get-ChildItem -Path (Split-Path $skb) -Filter ((Split-Path $skb -Leaf) + ".*.author.sig") |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $Transport $_.Name) }
  $arrived = Join-Path $Transport (Split-Path $skb -Leaf)

  Step -Id "$($Px)d" -Want 0 -Label "the unaltered artifact still verifies after transport" -HomeDir $home `
    -ArgList @("verify-sig","--pubkey","$key.pub",$arrived)

  # Now the tamper: a copy, altered, with the signature NOT re-made.
  $bad = Join-Path $Transport "$Skill-tampered.skb"
  Copy-Item $arrived $bad
  Get-ChildItem -Path $Transport -Filter ((Split-Path $arrived -Leaf) + ".*.author.sig") |
    ForEach-Object {
      $suffix = $_.Name.Substring((Split-Path $arrived -Leaf).Length + 1)
      Copy-Item $_.FullName (Join-Path $Transport ("$Skill-tampered.skb." + $suffix))
    }
  $bytes = [System.IO.File]::ReadAllBytes($bad)
  $bytes[200] = $bytes[200] -bxor 0xFF
  [System.IO.File]::WriteAllBytes($bad, $bytes)

  Step -Id "$($Px)e" -Want 10 -Label "the altered artifact is REFUSED" -HomeDir $home `
    -ArgList @("verify-sig","--pubkey","$key.pub",$bad)
  Says -Id "$($Px)f" -Needle "changed after signing" -Label "the refusal names the cause, not a missing file"
}

Write-Host ""
Write-Host "== Eric to Mirko =="
Exchange -Who "eric" -Skill "eric-demo-skill" -Px "R3"

Write-Host ""
Write-Host "== Mirko to Eric (symmetry: neither side has a privileged role) =="
Exchange -Who "mirko" -Skill "mirko-demo-skill" -Px "R4"

# ---- summary -------------------------------------------------------------

Write-Host ""
Write-Host "========================================"
if ($script:Failed) { Write-Host " FAIL" } else { Write-Host " PASS (rehearsal)" }
Write-Host "========================================"
Write-Host ""
Write-Host ("Platform : {0} {1}" -f [System.Environment]::OSVersion.Platform, $env:PROCESSOR_ARCHITECTURE)
Write-Host "Binary   : $script:Bin"
Write-Host "Version  : $Version"
Write-Host ""
for ($i = 0; $i -lt $script:Ids.Count; $i++) {
  $c = switch ($script:States[$i]) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } }
  Write-Host ("  {0,-5} {1,-5} {2}" -f $script:Ids[$i], $script:States[$i], $script:Notes[$i]) -ForegroundColor $c
}

Write-Host @"

WHAT THIS RUN DID NOT ESTABLISH
  * that two machines and two people were involved: both parties ran here,
  * that a fingerprint was compared over a SECOND channel (SPEC-0406 section 3.2),
    which is what makes "the recipient need not trust the transport" TRUE
    rather than merely asserted,
  * that a human understood any of the output,
  * the install half (T05, T09, T12, T14, T15). That needs the BundleMeta
    envelope, which carries author, registry AND governance signatures; a
    script that minted it would hold every key, and a run where one actor
    holds every key demonstrates nothing about two actors.

  For the install half:  go test ./cmd/skillctl/ -run TestAcceptance_TwoParty -v
  For the acceptance:    SPEC-0406 section 4, with a person on each end.

  A rehearsal reported as a passed acceptance is the failure this note exists
  to prevent.
"@

if ($Keep) { Write-Host ""; Write-Host "workspace kept: $Work" }
elseif (Test-Path $Work) { Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue }

if ($script:Failed) { exit 1 }
exit 0
