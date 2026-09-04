<#
.SYNOPSIS
  The local, offline-capable twin of our CI for Windows. Stage 2 of the trust
  check: runs the gates we merge and release on, then prints a trust report.

.DESCRIPTION
  Stage 1 (scripts\skillctl-test.ps1) answers "does it build and do the tests
  pass here". This answers the harder question:

    "Would this tree pass the gates we actually merge and release on?"

  Every gate runs, none fails fast, each reports PASS / FAIL / SKIP. Exit 0 iff
  no gate FAILED (with -Strict, iff none was skipped either).

    stage1         build + tests + CLI smoke (scripts\skillctl-test.ps1)
    vet            go vet
    lint           golangci-lint (pinned v2.13.2, as in ci.yml)
    mod-tidy       go mod tidy must be a no-op (go.mod/go.sum restored after)
    docaudit       every real CLI flag documented, every documented flag real
    prose          no U+2014 em dash in the tracked tree
    pins           every pinned install one-liner resolves, digests match
    boundary       the public/private plane boundary gate
    coverage       the .testcoverage.yml ratchet over the skillctl trust surface
    govulncheck    CVEs reachable from our code (pinned v1.7.0)
    gosec          SAST, judged against docs\security\gosec-inci-baseline.txt
    gitleaks       secret scan over the full history (config-aware)
    trust-surface  the windows-gate.yml parity run, WITH the test tag (see below)
    lifecycle      offline author/sign/verify/trust/tamper proof, fail-closed

  THE TAG THAT MATTERS ON WINDOWS. A shipping Windows build deliberately
  ignores $HOME for the trust-root and token-key paths, because an environment
  variable is attacker-settable. The hermetic trust tests inject $HOME, so on
  Windows they only run for real under `-tags allow_home_override_test`, which
  is exactly what .github/workflows/windows-gate.yml does. Stage 1 runs the
  untagged suite (shipping behaviour); the trust-surface gate here runs the
  tagged one. A trust decision gated on a fetch or a registry that is never
  exercised hermetically is how an over-broad fail-closed once survived local
  runs and two adversarial reviews. That is why this gate exists separately.

  WHAT IT IS NOT. Not the release: no tagging, no signing, no publish, no
  provenance. SLSA provenance, cosign/OIDC signing, Code Scanning ingestion and
  the cross-compile matrix live server-side. A green report here is not a
  substitute for a green PR.

  TOOLS. golangci-lint, gosec and go-test-coverage are installed on demand at
  the versions CI pins, into (go env GOPATH)\bin. -NoInstall forbids that and a
  missing tool reports SKIP. govulncheck runs via `go run ...@v1.7.0`. gitleaks
  is never auto-installed: CI verifies its release tarball against a pinned
  SHA-256, and a convenience script should not fake that.

  POSIX GATES. prose, pins, boundary and the gosec diff gate are shell scripts.
  prose is reimplemented here natively. The others run only if a working `bash`
  is on PATH (Git for Windows provides one; the gosec diff gate also needs jq),
  and report SKIP otherwise.

.PARAMETER RepoDir
  Where the checkout lives. Default: $HOME\m3c-tools.

.PARAMETER Ref
  Branch to test. Default: master.

.PARAMETER Full
  Widen the Go gates from the skillctl trust surface to ./...

.PARAMETER NoInstall
  Never install a missing tool; report SKIP instead.

.PARAMETER Strict
  A skipped gate also fails the run.

.PARAMETER SkipStage1
  Do not re-run scripts\skillctl-test.ps1 (build + tests + smoke).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\skillctl-enterprise-test.ps1

.EXAMPLE
  irm https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.ps1 | iex
#>
[CmdletBinding()]
param(
  [string] $RepoDir = (Join-Path $HOME 'm3c-tools'),
  [string] $RepoUrl = 'https://github.com/kamir/m3c-tools.git',
  [string] $Ref     = 'master',
  [switch] $Full,
  [switch] $NoInstall,
  [switch] $Strict,
  [switch] $SkipStage1,
  [switch] $Help
)

$ErrorActionPreference = 'Stop'

# PowerShell 7.4+ turns a non-zero native exit code into a terminating error
# under ErrorActionPreference Stop. Every gate here is judged by its exit code,
# so turn that off and keep 5.1 and 7.x identical.
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
  $PSNativeCommandUseErrorActionPreference = $false
}

if ($Help) {
  if ($PSCommandPath) { Get-Help -Detailed $PSCommandPath }
  else { Write-Host 'Save the script to a file to see its help, or read scripts/skillctl-enterprise-test.ps1 in the repository.' }
  exit 0
}

# Pinned exactly as .github/workflows/{ci,coverage-gate,gosec}.yml pin them.
$GolangciVersion  = 'v2.13.2'
$GovulncheckVersion = 'v1.7.0'
$GosecVersion     = 'v2.29.0'
$CoverageVersion  = 'v2.19.0'

$Gates   = [System.Collections.ArrayList]::new()
$NPass = 0; $NFail = 0; $NSkip = 0

function Add-Gate($name, $state, $note) {
  [void]$Gates.Add([pscustomobject]@{ Name = $name; State = $state; Note = $note })
  switch ($state) {
    'PASS' { $script:NPass++ }
    'FAIL' { $script:NFail++ }
    'SKIP' { $script:NSkip++ }
  }
}

function Write-GateHead($name) {
  Write-Host ''
  Write-Host '----------------------------------------'
  Write-Host ">>> $name" -ForegroundColor DarkGray
}

# Invoke-Gate: run a native command, stream its output, record the verdict.
function Invoke-Gate {
  param([string]$Name, [scriptblock]$Body)
  Write-GateHead $Name
  $global:LASTEXITCODE = 0
  try { & $Body } catch {
    Write-Host "  $($_.Exception.Message)"
    $global:LASTEXITCODE = 1
  }
  if ($LASTEXITCODE -eq 0) {
    Write-Host "  [PASS] $Name" -ForegroundColor Green
    Add-Gate $Name 'PASS' ''
  } else {
    Write-Host "  [FAIL] $Name (exit $LASTEXITCODE)" -ForegroundColor Red
    Add-Gate $Name 'FAIL' ''
  }
}

function Skip-Gate($name, $reason) {
  Write-GateHead $name
  Write-Host "  [SKIP] $name ($reason)" -ForegroundColor Yellow
  Add-Gate $name 'SKIP' $reason
}

function Stop-Setup($message) {
  Write-Host ''
  Write-Host "ERROR: $message" -ForegroundColor Red
  exit 2
}

Write-Host ''
Write-Host '========================================'
Write-Host ' skillctl: enterprise gate (Windows)'
Write-Host '========================================'
Write-Host ''
Write-Host '  This runs the CI gates locally and takes several minutes.'
Write-Host ''

# --- setup -----------------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Stop-Setup 'Git is not installed or not on PATH.' }
if (-not (Get-Command go  -ErrorAction SilentlyContinue)) { Stop-Setup 'Go is not installed or not on PATH. See https://go.dev/dl/' }

if (Test-Path (Join-Path $RepoDir '.git')) {
  Set-Location $RepoDir
  if ((git status --porcelain) -join '') {
    Stop-Setup "The checkout at $RepoDir has local changes. Commit, stash, or point -RepoDir somewhere else."
  }
} else {
  git clone --branch $Ref $RepoUrl $RepoDir
  if ($LASTEXITCODE -ne 0) { Stop-Setup 'git clone failed.' }
  Set-Location $RepoDir
}

$GoBinDir = Join-Path (((go env GOPATH) -join '').Trim()) 'bin'
$env:PATH = "$GoBinDir;$env:PATH"

function Test-Tool($command, $module) {
  if (Get-Command $command -ErrorAction SilentlyContinue) { return $true }
  if ($NoInstall) { return $false }
  Write-Host "  installing $module into $GoBinDir (needs the network) ..."
  go install $module 2>&1 | Out-Null
  return [bool](Get-Command $command -ErrorAction SilentlyContinue)
}

# A usable POSIX shell? Git for Windows ships one. A WSL stub with no distro
# installed answers `bash --version` with an error, which is why this probes
# rather than testing for the file.
$Bash = $null
$bashCmd = Get-Command bash -ErrorAction SilentlyContinue
if ($bashCmd) {
  & $bashCmd.Source -c 'exit 0' 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { $Bash = $bashCmd.Source }
}

$Scope = if ($Full) { @('./...') } else { @('./cmd/skillctl/...', './pkg/skillctl/...') }

Write-Host "  repo   : $RepoDir"
Write-Host "  scope  : $($Scope -join ' ')"
Write-Host "  bash   : $(if ($Bash) { $Bash } else { 'not available (POSIX gates will be skipped)' })"

# --- 1. stage 1 -------------------------------------------------------------
if ($SkipStage1) {
  Skip-Gate 'stage1' '-SkipStage1'
} else {
  Invoke-Gate 'stage1' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoDir 'scripts\skillctl-test.ps1') -RepoDir $RepoDir -Ref $Ref
  }
}

# The gates below want a binary; stage 1 leaves one in build\, but not if it was
# skipped or failed.
$Binary = Join-Path $RepoDir 'build\skillctl.exe'
if (-not (Test-Path $Binary)) { go build -o $Binary ./cmd/skillctl 2>&1 | Out-Null }

# --- 2. vet -----------------------------------------------------------------
Invoke-Gate 'vet' { & go vet @Scope }

# --- 3. golangci-lint -------------------------------------------------------
if (Test-Tool 'golangci-lint' "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$GolangciVersion") {
  Invoke-Gate 'lint' { & golangci-lint run --timeout=5m @Scope }
} else {
  Skip-Gate 'lint' "golangci-lint $GolangciVersion not installed"
}

# --- 4. go mod tidy is a no-op ----------------------------------------------
# CD-T4 in ci.yml. `go mod tidy` MUTATES go.mod/go.sum, so restore them either
# way: a QA run must not leave the checkout rewritten.
Invoke-Gate 'mod-tidy' {
  & go mod tidy
  if ($LASTEXITCODE -eq 0) { & git diff --exit-code go.mod go.sum }
}
& git checkout -- go.mod go.sum 2>&1 | Out-Null

# --- 5. docaudit ------------------------------------------------------------
Invoke-Gate 'docaudit' {
  & go test -count=1 ./cmd/docaudit/ | Out-Null
  if ($LASTEXITCODE -eq 0) { & go run ./cmd/docaudit -cli all }
}

# --- 6. prose (native: the shell gate needs POSIX tools) --------------------
# scripts/check-no-emdash.sh is the canonical gate. This is the same rule over
# the same file set: every tracked, non-exempt file, literal U+2014.
Write-GateHead 'prose'
$emdash = [char]0x2014
$exempt = '^(pkg/skillctl/bodyscan/testdata/|demo/kup-training/artifacts/)'
$hits = @()
foreach ($f in (git ls-files)) {
  if ($f -match $exempt) { continue }
  $p = Join-Path $RepoDir $f
  $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
  # Skip directories, submodule entries and anything too big to be prose: the
  # shell gate skips binaries via grep -I, this skips them by size.
  if ($null -eq $item -or $item.PSIsContainer -or $item.Length -gt 2MB) { continue }
  try {
    $text = [System.IO.File]::ReadAllText($p)
  } catch { continue }
  if ($text.IndexOf($emdash) -ge 0) { $hits += $f }
}
if ($hits.Count -eq 0) {
  Write-Host '  [PASS] prose (no U+2014 in the tracked tree)' -ForegroundColor Green
  Add-Gate 'prose' 'PASS' ''
} else {
  Write-Host "  [FAIL] prose: $($hits.Count) file(s) contain an em dash" -ForegroundColor Red
  $hits | Select-Object -First 20 | ForEach-Object { Write-Host "         $_" }
  Add-Gate 'prose' 'FAIL' ''
}

# --- 7. the remaining POSIX shell gates -------------------------------------
if ($Bash) {
  Invoke-Gate 'pins'     { & $Bash ./scripts/check-install-pins.sh }
  Invoke-Gate 'boundary' { & $Bash ./tools/boundary-gate.sh }
} else {
  Skip-Gate 'pins'     'no working bash on PATH'
  Skip-Gate 'boundary' 'no working bash on PATH'
}

# --- 8. coverage ratchet ----------------------------------------------------
# .testcoverage.yml reads `profile: cover.out` at the repo root. *.out is
# git-ignored, and it is removed again below.
if (Test-Tool 'go-test-coverage' "github.com/vladopajic/go-test-coverage/v2@$CoverageVersion") {
  Invoke-Gate 'coverage' {
    & go test ./pkg/skillctl/... ./cmd/skillctl/... -covermode=atomic -coverprofile=cover.out | Out-Null
    if ($LASTEXITCODE -eq 0) { & go-test-coverage --config .testcoverage.yml }
  }
  Remove-Item -LiteralPath (Join-Path $RepoDir 'cover.out') -ErrorAction SilentlyContinue
} else {
  Skip-Gate 'coverage' "go-test-coverage $CoverageVersion not installed"
}

# --- 9. govulncheck ---------------------------------------------------------
# Fails only on vulnerabilities REACHABLE from our code. Needs the network for
# the vulnerability database (and for `go run` to fetch the tool).
Invoke-Gate 'govulncheck' { & go run "golang.org/x/vuln/cmd/govulncheck@$GovulncheckVersion" @Scope }

# --- 10. gosec against the committed baseline -------------------------------
# The diff gate is the honest form: this tree has ~500 triaged pre-existing
# findings (docs\security\gosec-baseline.md), so an absolute count says nothing.
# What must never happen is a NEW finding.
if (-not $Bash) {
  Skip-Gate 'gosec' 'the diff gate is a POSIX shell script; no working bash on PATH'
} elseif (-not (Get-Command jq -ErrorAction SilentlyContinue)) {
  Skip-Gate 'gosec' 'jq is not installed (the diff gate needs it)'
} elseif (Test-Tool 'gosec' "github.com/securego/gosec/v2/cmd/gosec@$GosecVersion") {
  Invoke-Gate 'gosec' { & $Bash ./scripts/gosec-diff-gate.sh }
} else {
  Skip-Gate 'gosec' "gosec $GosecVersion not installed"
}

# --- 11. gitleaks -----------------------------------------------------------
if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
  Invoke-Gate 'gitleaks' { & gitleaks git . --config .gitleaks.toml --no-banner --redact }
} else {
  Skip-Gate 'gitleaks' 'not on PATH; see the pinned install in .github/workflows/ci.yml'
}

# --- 12. trust surface, the windows-gate.yml parity run ---------------------
# WITH -tags allow_home_override_test, and no -run allow-list: both are
# deliberate in CI. Without the tag the hermetic trust tests cannot inject
# $HOME on Windows, and a suite that skips them is not evidence.
Invoke-Gate 'trust-surface' {
  & go test -tags allow_home_override_test -count=1 -timeout=300s ./pkg/skillctl/... ./cmd/skillctl/... ./evaluation/...
}

# --- 13. lifecycle smoke (offline, sandboxed) -------------------------------
# The quickstart proof sandboxes its trust-root writes through $HOME, which a
# SHIPPING Windows build ignores on purpose. Build the sandbox binary with the
# tag, exactly as skillctl-windows-smoke.yml does, so the proof cannot touch the
# real %USERPROFILE%\.claude.
$SandboxBin = Join-Path $RepoDir 'build\skillctl-sandbox.exe'
go build -tags allow_home_override_test -o $SandboxBin ./cmd/skillctl 2>&1 | Out-Null
if (Test-Path $SandboxBin) {
  $env:SKILLCTL = $SandboxBin
  Invoke-Gate 'lifecycle' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoDir 'scripts\skillctl-quickstart-windows.ps1')
  }
  Remove-Item Env:\SKILLCTL -ErrorAction SilentlyContinue
} else {
  Skip-Gate 'lifecycle' 'could not build the sandbox binary (-tags allow_home_override_test)'
}

# --- trust report -----------------------------------------------------------
Write-Host ''
Write-Host '========================================'
if ($NFail -gt 0) {
  Write-Host ' TRUST REPORT: FAIL' -ForegroundColor Red
} elseif ($NSkip -gt 0 -and $Strict) {
  Write-Host ' TRUST REPORT: FAIL (strict: a gate was skipped)' -ForegroundColor Red
} elseif ($NSkip -gt 0) {
  Write-Host " TRUST REPORT: PASS with $NSkip skipped" -ForegroundColor Yellow
} else {
  Write-Host ' TRUST REPORT: PASS' -ForegroundColor Green
}
Write-Host '========================================'
Write-Host ''
Write-Host "Platform   : Windows $([System.Environment]::OSVersion.Version) ($env:PROCESSOR_ARCHITECTURE)"
Write-Host "PowerShell : $($PSVersionTable.PSVersion)"
Write-Host "Repository : $RepoDir"
Write-Host "Commit     : $((git rev-parse HEAD) -join '')"
Write-Host "Scope      : $($Scope -join ' ')"
Write-Host "Go         : $(((go version) -join '') -replace '^go version ', '')"
Write-Host ''
foreach ($g in $Gates) {
  $color = switch ($g.State) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } }
  Write-Host ("  {0,-14} {1,-4}  {2}" -f $g.Name, $g.State, $g.Note) -ForegroundColor $color
}
Write-Host ''
Write-Host ("  {0} passed, {1} failed, {2} skipped" -f $NPass, $NFail, $NSkip)
Write-Host ''
if ($NSkip -gt 0) {
  Write-Host 'A skipped gate is not a passed gate. Each one is listed above with its'
  Write-Host 'reason, so a missing local tool is never read as evidence.'
  Write-Host ''
}
Write-Host 'Server-side only, never covered here: SLSA provenance, cosign/OIDC signing,'
Write-Host 'Code Scanning ingestion, and the cross-compile matrix. Read the PR.'
Write-Host ''

if ($NFail -gt 0) { exit 1 }
if ($Strict -and $NSkip -gt 0) { exit 1 }
exit 0
