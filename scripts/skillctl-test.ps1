<#
.SYNOPSIS
  Quick local skillctl verification for Windows: clone/update, build, test, smoke.

.DESCRIPTION
  Stage 1 of the local trust check. It answers one practical question:

    "Can this machine reproducibly build the current master, and does the
     skillctl test suite pass here?"

  Six steps, each PASS/FAIL, with a summary table at the end. Exit code is 0
  only if every required step passed, so it is safe to wire into a gate.

    1. prerequisites   git + go present, Go new enough for this module
    2. repository      clone, or fetch and fast-forward an existing checkout
    3. dependencies    go mod download + go mod verify
    4. build           go build ./cmd/skillctl, then skillctl version
    5. tests           go test [-race] over the skillctl packages
    6. smoke           skillctl --help exits 0

  This is deliberately NOT the full trust/release suite (no lint, no
  govulncheck, no gosec, no coverage gate, no e2e). Those come in stage 2.

  Scope of step 5: by default the same package set the release gate runs
  (./cmd/skillctl/... ./pkg/skillctl/...), because a bare `go test ./...` in
  this repo also pulls in packages that need the network, an ER1 server,
  whisper, or a microphone, and their failures say nothing about skillctl.
  Use -Full to run everything anyway.

  Race detector: on Windows the race detector needs cgo and a C toolchain
  (gcc, e.g. mingw-w64). If none is found the tests still run, and the race
  step is reported SKIP instead of silently passing.

  Nothing here touches your real trust roots: no skillctl subcommand that
  writes state is invoked.

.PARAMETER RepoDir
  Where the checkout lives. Default: $HOME\m3c-tools.

.PARAMETER RepoUrl
  Clone URL. Default: the public GitHub repository.

.PARAMETER Ref
  Branch to test. Default: master (the active branch; `main` is abandoned).

.PARAMETER Full
  Run `go test ./...` instead of only the skillctl packages. Expect failures
  from packages that need network, hardware, or a running ER1 server.

.PARAMETER NoRace
  Never use the race detector, even if a C toolchain is available.

.PARAMETER Help
  Show this help and exit.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\skillctl-test.ps1

.EXAMPLE
  irm https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.ps1 | iex
#>
[CmdletBinding()]
param(
  [string] $RepoDir = (Join-Path $HOME 'm3c-tools'),
  [string] $RepoUrl = 'https://github.com/kamir/m3c-tools.git',
  [string] $Ref     = 'master',
  [switch] $Full,
  [switch] $NoRace,
  [switch] $Help
)

$ErrorActionPreference = 'Stop'

# PowerShell 7.4+ turns a non-zero exit code from a native command into a
# terminating error when ErrorActionPreference is Stop. That would abort this
# script with a raw exception before it can print which step failed. Turn it
# off, so 5.1 and 7.x behave the same and every native call is judged by the
# explicit $LASTEXITCODE checks below.
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
  $PSNativeCommandUseErrorActionPreference = $false
}

# $PSCommandPath is empty when the script arrives through `irm | iex`; there is
# no file for Get-Help to read then, and the one-liner runs with defaults anyway.
if ($Help) {
  if ($PSCommandPath) { Get-Help -Detailed $PSCommandPath }
  else { Write-Host 'Save the script to a file to see its help, or read scripts/skillctl-test.ps1 in the repository.' }
  exit 0
}

# Minimum Go toolchain, kept in step with the `go` directive in go.mod.
$MinGo = [Version]'1.25.0'

$Results = [ordered]@{}
$Failed  = $false

function Write-Head($text) {
  Write-Host ''
  Write-Host '========================================'
  Write-Host " $text"
  Write-Host '========================================'
  Write-Host ''
}

function Set-Result($name, $state) {
  $Results[$name] = $state
  if ($state -eq 'FAIL') { $script:Failed = $true }
}

# Stop with the summary printed, never with a bare exception: a half-finished
# run that says which step died is more useful than a stack trace.
function Stop-Run($message) {
  Write-Host ''
  Write-Host "ERROR: $message" -ForegroundColor Red
  Write-Summary
  exit 1
}

function Assert-ExitOk($what) {
  if ($LASTEXITCODE -ne 0) { Stop-Run "$what failed (exit $LASTEXITCODE)." }
}

function Write-Summary {
  Write-Host ''
  if ($script:Failed) {
    Write-Host '========================================'
    Write-Host ' FAIL'
    Write-Host '========================================'
  } else {
    Write-Host '========================================'
    Write-Host ' PASS'
    Write-Host '========================================'
  }
  Write-Host ''
  Write-Host "Repository : $RepoDir"
  Write-Host "Ref        : $Ref"
  if ($script:Commit)  { Write-Host "Commit     : $($script:Commit)" }
  if ($script:Binary)  { Write-Host "Binary     : $($script:Binary)" }
  if ($script:Version) { Write-Host "Version    : $($script:Version)" }
  Write-Host ''
  foreach ($k in $Results.Keys) {
    $state = $Results[$k]
    $color = switch ($state) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } }
    Write-Host ("  {0,-12} {1}" -f $k, $state) -ForegroundColor $color
  }
  Write-Host ''
}

Write-Head 'skillctl: Windows test run'

# 1. Prerequisites ----------------------------------------------------------
Write-Host '[1/6] Checking prerequisites...'

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Stop-Run 'Git is not installed or not on PATH. See https://git-scm.com/download/win'
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Stop-Run 'Go is not installed or not on PATH. See https://go.dev/dl/'
}

$GitVersion = (git --version) -join ''
$GoVersionRaw = (go version) -join ''
Write-Host "  $GitVersion"
Write-Host "  $GoVersionRaw"

# "go version go1.25.1 windows/amd64" gives the number between "go" and the
# first space; a release candidate ("go1.26rc1") is normalised to its base.
$m = [regex]::Match($GoVersionRaw, 'go(\d+\.\d+(\.\d+)?)')
if ($m.Success) {
  $goVer = [Version]($m.Groups[1].Value + $(if ($m.Groups[2].Success) { '' } else { '.0' }))
  if ($goVer -lt $MinGo) {
    Stop-Run "Go $goVer is older than the $MinGo this module requires. Upgrade from https://go.dev/dl/"
  }
}

$Gcc = Get-Command gcc -ErrorAction SilentlyContinue
$UseRace = (-not $NoRace) -and ($null -ne $Gcc)
if ($UseRace) {
  Write-Host "  C toolchain: $($Gcc.Source) (race detector available)"
} elseif ($NoRace) {
  Write-Host '  race detector: disabled by -NoRace'
} else {
  Write-Host '  race detector: unavailable (no gcc on PATH; install mingw-w64 to enable)'
}
Set-Result 'Prereqs' 'PASS'

# 2. Repository -------------------------------------------------------------
Write-Host ''
Write-Host "[2/6] Getting current m3c-tools ($Ref)..."

if (Test-Path (Join-Path $RepoDir '.git')) {
  Set-Location $RepoDir
  $dirty = (git status --porcelain) -join "`n"
  if ($dirty) {
    Stop-Run "The checkout at $RepoDir has local changes. Commit, stash, or point -RepoDir somewhere else."
  }
  git fetch origin $Ref;               Assert-ExitOk 'git fetch'
  git checkout $Ref;                   Assert-ExitOk 'git checkout'
  git merge --ff-only "origin/$Ref";   Assert-ExitOk 'git merge --ff-only'
} else {
  git clone --branch $Ref $RepoUrl $RepoDir; Assert-ExitOk 'git clone'
  Set-Location $RepoDir
}

$script:Commit = (git rev-parse HEAD) -join ''
Write-Host "  Testing commit: $($script:Commit)"
Set-Result 'Repo' 'PASS'

# 3. Dependencies -----------------------------------------------------------
Write-Host ''
Write-Host '[3/6] Verifying dependencies...'
go mod download; Assert-ExitOk 'go mod download'
go mod verify;   Assert-ExitOk 'go mod verify'
Set-Result 'Deps' 'PASS'

# 4. Build ------------------------------------------------------------------
Write-Host ''
Write-Host '[4/6] Building skillctl...'

# build\ is git-ignored, so a test run never dirties the checkout.
$BinDir = Join-Path $RepoDir 'build'
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$script:Binary = Join-Path $BinDir 'skillctl.exe'

go build -o $script:Binary ./cmd/skillctl; Assert-ExitOk 'go build'
if (-not (Test-Path $script:Binary)) { Stop-Run 'skillctl.exe was not created.' }
Write-Host "  Build OK: $($script:Binary)"

$script:Version = (& $script:Binary version) -join ''
Assert-ExitOk 'skillctl version'
if (-not $script:Version) { Stop-Run 'skillctl version printed nothing.' }
Write-Host "  Version: $($script:Version)"
Set-Result 'Build' 'PASS'

# 5. Tests ------------------------------------------------------------------
Write-Host ''
Write-Host '[5/6] Running Go tests...'
Write-Host '      This can take a few minutes.'
Write-Host ''

$pkgs = if ($Full) { @('./...') } else { @('./cmd/skillctl/...', './pkg/skillctl/...') }
if ($Full) {
  Write-Host '  -Full: the whole module, including packages that need network or hardware.'
}

$testArgs = @('test', '-count=1')
if ($UseRace) { $testArgs += '-race' }
$testArgs += $pkgs

Write-Host "  go $($testArgs -join ' ')"
Write-Host ''
# The race detector is a cgo runtime; be explicit rather than relying on
# whatever CGO_ENABLED the toolchain defaulted to on this machine.
if ($UseRace) { $env:CGO_ENABLED = '1' }
& go @testArgs
if ($LASTEXITCODE -ne 0) {
  Set-Result 'Tests' 'FAIL'
  Set-Result 'Race'  $(if ($UseRace) { 'FAIL' } else { 'SKIP' })
  Write-Summary
  exit 1
}
Set-Result 'Tests' 'PASS'
Set-Result 'Race'  $(if ($UseRace) { 'PASS' } else { 'SKIP' })

# 6. Smoke ------------------------------------------------------------------
Write-Host ''
Write-Host '[6/6] Running skillctl smoke test...'
& $script:Binary --help | Out-Null
if ($LASTEXITCODE -ne 0) {
  Set-Result 'CLI smoke' 'FAIL'
  Write-Summary
  exit 1
}
Set-Result 'CLI smoke' 'PASS'

Write-Summary
if ($script:Failed) { exit 1 }
Write-Host 'skillctl builds and tests clean on this machine.'
Write-Host 'Next: stage 2, the local CI gate: scripts\skillctl-enterprise-test.ps1'
Write-Host ''
exit 0
