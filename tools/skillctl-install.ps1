<#
.SYNOPSIS
  skillctl installer (Windows) — native PowerShell mirror of tools/skillctl-install.sh.

.DESCRIPTION
  Fetch the windows/amd64 binary from a GitHub release, VERIFY provenance over
  SHA256SUMS, then verify the binary's SHA-256 (integrity), then install to a user
  program dir and put it on the user PATH. Fail-closed, verify-before-install.

  Provenance has two tracks, exactly like the shell installer:
    TRACK 1 (PRIMARY) — keyless cosign / GitHub OIDC (SPEC-0253). cosign is the
      primary path and is AUTO-FETCHED (pinned + self-verified) when not on PATH.
      A cosign bundle that is present but does NOT verify is a HARD FAIL (an
      attacker must not be able to force a downgrade). A fully ABSENT bundle falls
      through to track 2.
    TRACK 2 (FALLBACK) — pinned ed25519 (SEC-M2), used only when track 1 did not
      verify AND openssl.exe is available. Windows does not ship openssl, so unlike
      the shell installer this is a conditional fallback, not a hard prerequisite;
      if NEITHER track can verify, we REFUSE.

.PARAMETER ReleaseBase
  Base URL of the release assets. Env fallback: $env:RELEASE_BASE. Default:
  https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.3.1

.PARAMETER InstallDir
  Install directory. Env fallback: $env:INSTALL_DIR. Default:
  %LOCALAPPDATA%\Programs\skillctl

.NOTES
  Usage (one-liner) — a published release ships this file as install.ps1 with its
  RELEASE_BASE already baked in to that release, so the ... is pre-filled there:
    irm .../install.ps1 | iex

  Env overrides:
    $env:RELEASE_BASE               release base URL (see -ReleaseBase)
    $env:INSTALL_DIR                install directory (see -InstallDir)
    $env:SKILLCTL_COSIGN_IDENTITY   override the cosign certificate-identity regexp
    $env:SKILLCTL_REQUIRE_COSIGN=1  require cosign provenance; refuse if not verifiable

  Portable across Windows PowerShell 5.1 and PowerShell 7+. Requires network access;
  cosign is auto-fetched (pinned) if absent. openssl.exe is only needed for the
  ed25519 fallback on releases that carry no cosign bundle.
#>
param(
    [string]$ReleaseBase,
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
# Native tools (cosign, curl.exe, openssl, skillctl) report failure via their EXIT
# CODE, which we check explicitly. Do NOT let a native non-zero exit throw (this is
# the PowerShell 7.4+ default) — it would break our $LASTEXITCODE-based control flow.
$PSNativeCommandUseErrorActionPreference = $false
# Invoke-WebRequest's progress bar makes downloads crawl on Windows PowerShell 5.1.
$ProgressPreference = 'SilentlyContinue'

# --- Prelude: ensure TLS 1.2 for Windows PowerShell 5.1 (whose default is often SSL3/TLS1). ---
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# ============================================================================
# Constants
# ============================================================================

# SEC-M2: pin the release-key fingerprint. The signature alone proves only that
# SHA256SUMS was signed by WHATEVER key sits next to it at the same origin — an
# origin compromise can swap key + sig + binaries together and still "verify".
# Pinning the expected fingerprint here narrows that hole: the fetched key must
# match this exact value or we refuse. CAVEAT: when this script is delivered via
# `irm … | iex`, the script (and this pin) is itself fetched from the release
# origin, so the pin only fully closes the hole for a run from a reviewed
# CHECKOUT, where the in-repo INFRA/skillctl-release.pub is preferred below. For
# the highest assurance, clone the repo and run this script from the checkout.
# Fingerprint = sha256 of the raw 32-byte ed25519 key (DER SPKI tail).
$EXPECTED_FP   = 'sha256:5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2'

# cosign auto-fetch pin. If cosign is not already on PATH we download THIS exact
# release and verify its OWN SHA-256 against $COSIGN_SHA256 before ever executing
# it — never run a cosign.exe whose hash does not match the pin.
# $COSIGN_SHA256 is the value published in sigstore's cosign_checksums.txt for
# cosign-windows-amd64.exe at $COSIGN_VERSION. Re-confirm before cutting a release:
#   https://github.com/sigstore/cosign/releases/download/<ver>/cosign_checksums.txt
$COSIGN_VERSION = 'v2.4.3'
$COSIGN_URL     = "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-windows-amd64.exe"
$COSIGN_SHA256  = 'a2ac24e197111c9430cb2a98f10a641164381afb83df036504868e4ea5720800'

$COSIGN_ISSUER  = 'https://token.actions.githubusercontent.com'

# The ONLY windows asset — no windows/arm64 build exists.
$ASSET = 'skillctl-windows-amd64.exe'

# ============================================================================
# Resolve params from args -> env -> default
# ============================================================================
if (-not $ReleaseBase) {
    $ReleaseBase = if ($env:RELEASE_BASE) { $env:RELEASE_BASE }
                   else { 'https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.3.1' }
}
if (-not $InstallDir) {
    $InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR }
                  else { Join-Path $env:LOCALAPPDATA 'Programs\skillctl' }
}
# cosign certificate-identity regexp — same value the release workflow pins.
$idRegex = if ($env:SKILLCTL_COSIGN_IDENTITY) { $env:SKILLCTL_COSIGN_IDENTITY }
           else { '^https://github.com/kamir/m3c-tools/\.github/workflows/skillctl-release\.yml@refs/tags/skillctl/v' }

# SEC: an env-supplied cosign identity or release base relaxes the trust anchor —
# a poisoned environment could repoint verification at an attacker-signed release.
# We still honor the overrides (they are legitimate for testing), but warn loudly.
if ($env:SKILLCTL_COSIGN_IDENTITY) {
    $host.UI.WriteErrorLine("WARNING: SKILLCTL_COSIGN_IDENTITY overrides the pinned cosign identity — provenance is only as trustworthy as this regexp.")
}
if ($env:RELEASE_BASE) {
    $host.UI.WriteErrorLine("WARNING: RELEASE_BASE overrides the default release origin ($env:RELEASE_BASE).")
}

$haveCurl = [bool](Get-Command curl.exe -ErrorAction SilentlyContinue)

# ============================================================================
# Helpers
# ============================================================================
function Write-Info($m) { Write-Host $m -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "OK: $m" -ForegroundColor Green }

# Fail-closed: emit to the ERROR stream (mirrors the shell's `>&2`) and exit
# non-zero. The finally block still runs and cleans up the temp dir.
function Die($m) {
    $host.UI.WriteErrorLine($m)
    exit 1
}

# Download $Url to $OutFile. Primary: Invoke-WebRequest -UseBasicParsing; fall back
# to curl.exe if present. Returns $true on success. On failure: $false when
# -Optional, else Die (mirrors the shell's `fetch()` / `set -e`).
function Invoke-Download {
    param([string]$Url, [string]$OutFile, [switch]$Optional)
    $ok = $false
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
        $ok = $true
    } catch {
        $ok = $false
    }
    if (-not $ok -and $haveCurl) {
        & curl.exe -fsSL -o $OutFile $Url 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $OutFile)) { $ok = $true }
    }
    if (-not $ok) {
        if (Test-Path -LiteralPath $OutFile) {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        }
        if ($Optional) { return $false }
        Die "download failed: $Url"
    }
    return $true
}

# Convenience: fetch "$ReleaseBase/$Name" into the temp dir.
function Fetch {
    param([string]$Name, [switch]$Optional)
    return (Invoke-Download -Url "$ReleaseBase/$Name" -OutFile (Join-Path $tmp $Name) -Optional:$Optional)
}

# sha256 hex (lowercase) of a file.
function Get-Sha256Hex($path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower()
}

# ============================================================================
# Main
# ============================================================================
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("skillctl-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Info "skillctl installer (Windows)"
    Write-Host "  release: $ReleaseBase"
    Write-Host "  target:  $InstallDir"

    Write-Info "Fetching manifest"
    Fetch 'SHA256SUMS' | Out-Null
    $sumsPath = Join-Path $tmp 'SHA256SUMS'

    $verified = $false

    # === Provenance track 1 (PRIMARY): keyless cosign / GitHub OIDC (SPEC-0253). ===
    # cosign is the primary path. If it is not on PATH we auto-fetch a PINNED cosign
    # and verify its own SHA-256 before using it. When cosign is available AND the
    # release carries a cosign bundle, verify SHA256SUMS against the EXPECTED workflow
    # OIDC identity (no key to trust — the signer is the release workflow itself).
    # A present-but-invalid bundle is a HARD FAIL (no silent downgrade); a fully
    # ABSENT bundle falls through to the pinned-ed25519 track below.
    $cosignExe = $null
    $cmd = Get-Command cosign -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command cosign.exe -ErrorAction SilentlyContinue }
    if ($cmd) { $cosignExe = $cmd.Source }

    if (-not $cosignExe) {
        Write-Info "cosign not on PATH — fetching pinned cosign $COSIGN_VERSION (windows/amd64)"
        $cosignDl = Join-Path $tmp 'cosign.exe'
        if (Invoke-Download -Url $COSIGN_URL -OutFile $cosignDl -Optional) {
            if ($COSIGN_SHA256 -eq 'REPLACE_WITH_PINNED_SHA256') {
                # SEC: never run an UNPINNED cosign. If the pin is unset, we cannot
                # trust the downloaded cosign — skip the cosign track entirely.
                Write-Info "cosign pin is not set (COSIGN_SHA256) — refusing to run unverified cosign; skipping cosign track"
            } else {
                $dlHash = Get-Sha256Hex $cosignDl
                if ($dlHash -ieq $COSIGN_SHA256) {
                    Unblock-File -LiteralPath $cosignDl -ErrorAction SilentlyContinue
                    $cosignExe = $cosignDl
                    Write-Ok "pinned cosign verified ($COSIGN_SHA256)"
                } else {
                    # SEC: never USE a cosign whose hash != pin. Do not set $cosignExe;
                    # fall through to the ed25519 track (as if cosign were absent).
                    $host.UI.WriteErrorLine("downloaded cosign SHA-256 does not match the pin — refusing to use it")
                    $host.UI.WriteErrorLine("  expected: $COSIGN_SHA256")
                    $host.UI.WriteErrorLine("  got:      $dlHash")
                }
            }
        } else {
            Write-Info "could not download pinned cosign — will try the ed25519 fallback"
        }
    }

    if ($cosignExe) {
        $bundlePath = Join-Path $tmp 'SHA256SUMS.cosign.bundle'
        if (Fetch 'SHA256SUMS.cosign.bundle' -Optional) {
            Write-Info "Verifying cosign keyless provenance over SHA256SUMS (GitHub OIDC)"
            & $cosignExe verify-blob $sumsPath `
                --bundle $bundlePath `
                --certificate-identity-regexp $idRegex `
                --certificate-oidc-issuer $COSIGN_ISSUER 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "cosign keyless provenance verified (signed by the release workflow)"
                $verified = $true
            } else {
                Die @"
COSIGN VERIFICATION FAILED — a bundle is present but did not verify against the
expected workflow identity; refusing to install (no silent downgrade to ed25519).
"@
            }
        }
        # A fully absent bundle: fall through to track 2 (no error).
    }

    if ($env:SKILLCTL_REQUIRE_COSIGN -eq '1' -and -not $verified) {
        Die "SKILLCTL_REQUIRE_COSIGN=1 but no verifiable cosign provenance was found — refusing."
    }

    # === Provenance track 2 (FALLBACK): pinned ed25519 (SEC-M2). ===
    # Reached when cosign is absent/unusable or the release carries no cosign bundle.
    # Windows does not ship openssl, so this track is CONDITIONAL on openssl.exe being
    # present (the shell installer can hard-require openssl; here we cannot).
    if (-not $verified) {
        $osslCmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
        if (-not $osslCmd) { $osslCmd = Get-Command openssl -ErrorAction SilentlyContinue }

        if ($osslCmd) {
            $openssl = $osslCmd.Source
            $haveSig   = Fetch 'SHA256SUMS.sig' -Optional
            $havePubDl = Fetch 'skillctl-release.pub' -Optional

            # SEC-M2: prefer the in-repo, version-controlled release key when this
            # script runs from a checkout — it is reviewed and cannot be swapped by an
            # origin compromise. Search a few likely roots relative to the script.
            $scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
                         elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
                         else { $null }
            $pubkey = if ($havePubDl) { Join-Path $tmp 'skillctl-release.pub' } else { $null }
            if ($scriptDir) {
                foreach ($cand in @(
                    (Join-Path $scriptDir '..\INFRA\skillctl-release.pub'),
                    (Join-Path $scriptDir 'INFRA\skillctl-release.pub'),
                    (Join-Path $scriptDir 'skillctl-release.pub'))) {
                    if ($cand -and (Test-Path -LiteralPath $cand -PathType Leaf)) {
                        Write-Info "Using in-repo release key: $cand"
                        $pubkey = (Resolve-Path -LiteralPath $cand).Path
                        break
                    }
                }
            }

            if ($haveSig -and $pubkey) {
                Write-Info "Verifying ed25519 signature over SHA256SUMS (provenance)"
                & $openssl pkeyutl -verify -pubin -inkey $pubkey -rawin `
                    -in $sumsPath -sigfile (Join-Path $tmp 'SHA256SUMS.sig') 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Die "SIGNATURE VERIFICATION FAILED — refusing to install"
                }

                # Fingerprint = sha256 of the raw 32-byte ed25519 key (DER SPKI tail) —
                # the same derivation used for trust-roots + the published fingerprint.
                $derPath = Join-Path $tmp 'skillctl-release.der'
                & $openssl pkey -pubin -in $pubkey -outform DER -out $derPath 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $derPath)) {
                    Die "could not derive release-key fingerprint — refusing to install"
                }
                $der = [System.IO.File]::ReadAllBytes($derPath)
                if ($der.Length -lt 32) { Die "unexpected release-key DER length — refusing to install" }
                $raw = $der[($der.Length - 32)..($der.Length - 1)]
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $fpHex = ([System.BitConverter]::ToString($sha.ComputeHash([byte[]]$raw)) -replace '-', '').ToLower()
                } finally {
                    $sha.Dispose()
                }
                $fp = "sha256:$fpHex"

                # SEC-M2: fail closed unless the key's fingerprint matches the pin.
                # Without this, a signature that merely verifies against a co-located
                # key would pass — defeating the point of signing.
                if ($fp -ne $EXPECTED_FP) {
                    Die @"
RELEASE KEY FINGERPRINT MISMATCH — refusing to install
  expected: $EXPECTED_FP
  got:      $fp
"@
                }
                Write-Ok "signed by the pinned skillctl release key ($fp)"
                $verified = $true
            } else {
                Write-Info "ed25519 fallback unavailable (missing signature or public key at the release)"
            }
        } else {
            Write-Info "openssl.exe not found — cannot use the ed25519 fallback"
        }
    }

    # Fail-closed: if NEITHER track verified provenance, refuse.
    if (-not $verified) {
        Die @"
No verifiable provenance for SHA256SUMS — refusing to install (fail-closed).
Neither cosign (keyless/OIDC, primary) nor an openssl ed25519 fallback could verify it.
Fix: install cosign so provenance can be verified:
  https://docs.sigstore.dev/cosign/system_config/installation/
(or provide openssl.exe if this release carries the ed25519 signature + key.)
"@
    }

    # === Integrity: verify the binary's SHA-256 against the (now-trusted) manifest. ===
    Write-Info "Fetching $ASSET"
    Fetch $ASSET | Out-Null

    Write-Info "Verifying SHA-256 (integrity)"
    $expected = $null
    foreach ($l in (Get-Content -LiteralPath $sumsPath)) {
        # SHA256SUMS line: "<hex>  <name>" (optionally "<hex> *<name>" in binary mode).
        if ($l -match ('(?<h>[0-9A-Fa-f]{64})\s+\*?' + [regex]::Escape($ASSET) + '\s*$')) {
            $expected = $Matches['h']
            break
        }
    }
    if (-not $expected) { Die "$ASSET not in SHA256SUMS" }
    $actual = Get-Sha256Hex (Join-Path $tmp $ASSET)
    if ($expected -ine $actual) {
        Die "checksum mismatch: $expected != $actual"
    }
    Write-Ok $expected

    # === Install + PATH ===
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $target = Join-Path $InstallDir 'skillctl.exe'
    Move-Item -LiteralPath (Join-Path $tmp $ASSET) -Destination $target -Force
    Unblock-File -LiteralPath $target -ErrorAction SilentlyContinue
    Write-Ok "installed: $target"

    # Persist to the USER PATH idempotently (only if not already a member).
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $members = @()
    if ($userPath) { $members = $userPath -split ';' | Where-Object { $_ -ne '' } }
    $already = $false
    foreach ($p in $members) {
        if ($p.TrimEnd('\') -ieq $InstallDir.TrimEnd('\')) { $already = $true; break }
    }
    if (-not $already) {
        $newPath = if ($userPath -and $userPath.Trim()) { ($userPath.TrimEnd(';') + ';' + $InstallDir) }
                   else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Info "Added $InstallDir to your user PATH (new terminals will pick it up)."
    } else {
        Write-Info "$InstallDir already on your user PATH."
    }
    # Make it usable in THIS session too.
    if (($env:Path -split ';') -notcontains $InstallDir) {
        $env:Path = "$env:Path;$InstallDir"
    }

    Write-Host ""
    & $target version 2>$null

    Write-Host ""
    Write-Host "Installed / next steps:" -ForegroundColor Green
    Write-Host "  - Binary: $target"
    Write-Host "  - Open a NEW terminal (PATH was updated), then run: skillctl --help"
}
finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
