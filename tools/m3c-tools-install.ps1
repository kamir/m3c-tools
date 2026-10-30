<#
.SYNOPSIS
  m3c-tools installer (Windows): the PowerShell counterpart of tools/m3c-tools-install.sh.

.DESCRIPTION
  Fetch the windows/amd64 archive from the newest m3c-tools release, verify provenance
  over checksums.txt, verify the archive's SHA-256, then install to a user program dir
  and add it to the user PATH. No admin rights.

  Cosign is the primary track. A cosign found on PATH runs only if it matches the pinned
  SHA-256; otherwise the pinned build is downloaded and checked first. A bundle that is
  present but does not verify is a hard failure. With no bundle, the pinned ed25519
  signature is the fallback and needs openssl.exe.

.EXAMPLE
  irm <url>/m3c-tools-install.ps1 | iex
#>
[CmdletBinding()]
param(
    [string]$InstallDir = $(if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\m3c-tools' }),
    [string]$ReleaseBase = $env:RELEASE_BASE
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$EXPECTED_FP = 'sha256:5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2'
$COSIGN_VERSION = 'v2.4.3'
$COSIGN_URL = "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-windows-amd64.exe"
$COSIGN_SHA256 = 'a2ac24e197111c9430cb2a98f10a641164381afb83df036504868e4ea5720800'
$COSIGN_ISSUER = 'https://token.actions.githubusercontent.com'
$COSIGN_ID_REGEX = '^https://github.com/kamir/m3c-tools/\.github/workflows/release\.yml@refs/tags/v'
$ASSET = 'm3c-tools-windows-amd64.zip'

function Die($m) { Write-Host "ERROR: $m" -ForegroundColor Red; throw $m }
function Get-Sha256Hex($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Get-NewestM3cTag {
    $feed = (Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/kamir/m3c-tools/releases.atom' -TimeoutSec 20).Content
    $m = [regex]::Match($feed, 'releases/tag/(v[0-9][^"<]*)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

if ($ReleaseBase) {
    Write-Warning "RELEASE_BASE overrides the default release origin ($ReleaseBase)"
} else {
    $tag = Get-NewestM3cTag
    if (-not $tag) { Die 'could not determine the newest release. Set RELEASE_BASE to name one.' }
    $ReleaseBase = "https://github.com/kamir/m3c-tools/releases/download/$tag"
    Write-Host "m3c-tools-install: newest release is $tag"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('m3c-tools-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

function Fetch($name) {
    $path = Join-Path $tmp $name
    Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBase/$name" -OutFile $path
    return $path
}

function Get-TrustedCosign {
    $found = Get-Command cosign.exe -ErrorAction SilentlyContinue
    if ($found -and (Get-Sha256Hex $found.Source) -eq $COSIGN_SHA256) { return $found.Source }
    $path = Join-Path $tmp 'cosign.exe'
    Invoke-WebRequest -UseBasicParsing -Uri $COSIGN_URL -OutFile $path
    if ((Get-Sha256Hex $path) -ne $COSIGN_SHA256) { Die 'the downloaded cosign does not match the pinned SHA-256' }
    return $path
}

try {
    Write-Host 'Fetching manifest'
    $sums = Fetch 'checksums.txt'

    $bundle = $null
    try { $bundle = Fetch 'checksums.txt.cosign.bundle' } catch { $bundle = $null }

    if ($bundle) {
        Write-Host 'Verifying cosign keyless provenance over checksums.txt (GitHub OIDC)'
        $cosign = Get-TrustedCosign
        $saved = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $cosign verify-blob $sums --bundle $bundle --certificate-identity-regexp $COSIGN_ID_REGEX --certificate-oidc-issuer $COSIGN_ISSUER 2>&1 | Out-Null
        $rc = $LASTEXITCODE
        $ErrorActionPreference = $saved
        if ($rc -ne 0) { Die 'COSIGN VERIFICATION FAILED: refusing to install (no silent downgrade to ed25519)' }
        Write-Host 'OK: cosign keyless provenance verified (signed by the release workflow)'
    } else {
        $openssl = Get-Command openssl.exe -ErrorAction SilentlyContinue
        if (-not $openssl) { Die 'this release has no cosign bundle, and openssl.exe is missing: nothing can verify it' }
        $sig = Fetch 'checksums.txt.sig'
        $pub = Fetch 'skillctl-release.pub'
        & $openssl.Source pkeyutl -verify -pubin -inkey $pub -rawin -in $sums -sigfile $sig | Out-Null
        if ($LASTEXITCODE -ne 0) { Die 'SIGNATURE VERIFICATION FAILED: refusing to install' }
        $der = Join-Path $tmp 'pub.der'
        & $openssl.Source pkey -pubin -in $pub -outform DER -out $der | Out-Null
        $bytes = [IO.File]::ReadAllBytes($der)
        $raw = $bytes[($bytes.Length - 32)..($bytes.Length - 1)]
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash([byte[]]$raw)
        $fp = 'sha256:' + (-join ($hash | ForEach-Object { $_.ToString('x2') }))
        if ($fp -ne $EXPECTED_FP) { Die "RELEASE KEY FINGERPRINT MISMATCH: expected $EXPECTED_FP, got $fp" }
        Write-Host "OK: signed by the pinned release key ($fp)"
    }

    Write-Host "Fetching $ASSET"
    $archive = Fetch $ASSET
    Write-Host 'Verifying SHA-256 (integrity)'
    $expected = $null
    foreach ($l in (Get-Content -LiteralPath $sums)) {
        if ($l -match ('(?<h>[0-9A-Fa-f]{64})\s+\*?' + [regex]::Escape($ASSET) + '\s*$')) { $expected = $Matches['h']; break }
    }
    if (-not $expected) { Die "$ASSET not in checksums.txt" }
    $actual = Get-Sha256Hex $archive
    if ($expected -ine $actual) { Die "checksum mismatch: $expected != $actual" }
    Write-Host "OK: $expected"

    $extracted = Join-Path $tmp 'x'
    Expand-Archive -LiteralPath $archive -DestinationPath $extracted -Force
    $binary = Get-ChildItem -LiteralPath $extracted -Recurse -Filter 'm3c-tools*.exe' | Select-Object -First 1
    if (-not $binary) { Die 'the archive holds no m3c-tools.exe' }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $target = Join-Path $InstallDir 'm3c-tools.exe'
    Move-Item -LiteralPath $binary.FullName -Destination $target -Force
    Unblock-File -LiteralPath $target -ErrorAction SilentlyContinue
    Write-Host "Installed: $target"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $members = @(); if ($userPath) { $members = $userPath -split ';' | Where-Object { $_ } }
    if (-not ($members | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') })) {
        $newPath = if ($userPath) { $userPath.TrimEnd(';') + ';' + $InstallDir } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "Added $InstallDir to your user PATH (new terminals pick it up)."
    }
    $env:Path = "$env:Path;$InstallDir"

    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $target version
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $saved
    if ($rc -ne 0) { Die 'the binary is installed but does not start on this machine' }
    Write-Host 'Next: open a new terminal, then run: m3c-tools transcript dQw4w9WgXcQ'
}
finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
