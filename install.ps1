# franken-node PowerShell installer
#
# Usage:
#   irm https://raw.githubusercontent.com/Dicklesworthstone/franken_node/main/install.ps1 | iex
#
# With options (download, then invoke as a scriptblock):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Dicklesworthstone/franken_node/main/install.ps1))) -Version v0.1.0 -EasyMode
#
# Options:
#   -Version vX.Y.Z   Install a specific release tag (default: latest)
#   -Dest DIR         Install dir (default: %USERPROFILE%\.local\bin)
#   -EasyMode         Add the install dir to your User PATH
#   -Verify           Also verify after install (candidates are always checked)
#   -NoVerify         Skip checksum + signature verification (testing only)
#
# Release asset: franken-node-x86_64-pc-windows-msvc.zip (+ .sha256, + .sigstore.json)
#
Param(
  [string]$Version = "",
  [string]$Dest = "$HOME\.local\bin",
  [string]$Owner = "Dicklesworthstone",
  [string]$Repo = "franken_node",
  [string]$Checksum = "",
  [string]$ChecksumUrl = "",
  [string]$SigstoreBundleUrl = "",
  [string]$CosignIdentityRegex = "",
  [string]$CosignOidcIssuer = "",
  [string]$ArtifactUrl = "",
  [switch]$EasyMode,
  [switch]$Verify,
  [switch]$NoVerify
)

$ErrorActionPreference = "Stop"
$BinaryName = "franken-node"

function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

function Test-UserPathContains {
  param([string]$PathValue, [string]$PathToFind)
  if ([string]::IsNullOrEmpty($PathValue)) { return $false }
  foreach ($entry in $PathValue.Split(';')) {
    if ($entry.TrimEnd('\') -ieq $PathToFind.TrimEnd('\')) { return $true }
  }
  return $false
}

function Assert-RegularInstallFile {
  param([string]$Path)
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw "Install path must be a regular file, not a directory or link: $Path"
  }
}

function Get-InstallFileHash {
  param([string]$Path)
  # Use the framework implementation directly: checksum verification must not
  # depend on the Get-FileHash utility cmdlet being discoverable.
  $algorithm = [System.Security.Cryptography.SHA256]::Create()
  try {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
      return [System.BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace("-", "").ToLowerInvariant()
    } finally {
      $stream.Dispose()
    }
  } finally {
    $algorithm.Dispose()
  }
}

function Assert-InstallBinary {
  param([string]$Path, [ValidateRange(1, 10000)][int]$TimeoutMillis = 10000)
  # Native nonzero exits do not throw in Windows PowerShell. Check ExitCode
  # explicitly, and never let an interactive/broken candidate hang an upgrade.
  $process = New-Object System.Diagnostics.Process
  $process.StartInfo.FileName = $Path
  $process.StartInfo.Arguments = "--version"
  $process.StartInfo.UseShellExecute = $false
  $process.StartInfo.CreateNoWindow = $true
  $process.StartInfo.RedirectStandardInput = $true
  try {
    if (-not $process.Start()) { throw "Could not start candidate: $Path" }
    $process.StandardInput.Close()
    if (-not $process.WaitForExit($TimeoutMillis)) {
      if ([System.Environment]::Version.Major -ge 5) { $process.Kill($true) }
      else { $process.Kill() }
      if (-not $process.WaitForExit(1000)) { throw "Candidate cleanup is unproven: $Path" }
      throw "Candidate version probe timed out: $Path"
    }
    if ($process.ExitCode -ne 0) {
      throw "Candidate version probe exited $($process.ExitCode): $Path"
    }
  } finally {
    $process.Dispose()
  }
}

function Install-VerifiedBinary {
  param([string]$Source, [string]$Destination, [switch]$PostVerify)
  Assert-RegularInstallFile $Source
  $destinationRoot = [System.IO.Path]::GetFullPath($Destination)
  if (-not (Test-Path -LiteralPath $destinationRoot)) {
    New-Item -ItemType Directory -Path $destinationRoot -ErrorAction Stop | Out-Null
  }
  $directory = Get-Item -LiteralPath $destinationRoot -Force -ErrorAction Stop
  if (-not $directory.PSIsContainer -or ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw "Install destination must be a directory, not a link: $destinationRoot"
  }
  $installedPath = Join-Path $destinationRoot "$BinaryName.exe"
  $lockPath = Join-Path $destinationRoot ".$BinaryName.install.lock"
  if (Test-Path -LiteralPath $lockPath) { Assert-RegularInstallFile $lockPath }
  # A stable exclusive handle serializes cooperating installers. Keep the lock
  # file after release; deleting it would let another process lock a new inode.
  $lock = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate,
    [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  try {
    if (Test-Path -LiteralPath $installedPath) { Assert-RegularInstallFile $installedPath }
    $identity = [System.Guid]::NewGuid().ToString("N")
    $staged = Join-Path $destinationRoot ".$BinaryName.install.$identity.exe"
    $backup = Join-Path $destinationRoot ".$BinaryName.previous.$identity.exe"
    $failed = Join-Path $destinationRoot ".$BinaryName.failed.$identity.exe"
    $sourceHash = Get-InstallFileHash $Source
    # Stage next to the destination, never across volumes and never over an
    # existing file. Failure evidence is retained instead of discarded.
    [System.IO.File]::Copy($Source, $staged, $false)
    $stageHandle = [System.IO.File]::Open($staged, [System.IO.FileMode]::Open,
      [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try { $stageHandle.Flush($true) } finally { $stageHandle.Dispose() }
    if ((Get-InstallFileHash $staged) -ne $sourceHash) {
      throw "Staged candidate differs from its source; previous installation preserved"
    }
    try { Assert-InstallBinary $staged }
    catch { throw "Candidate cannot run; previous installation preserved. $($_.Exception.Message)" }
    if ((Get-InstallFileHash $staged) -ne $sourceHash) {
      throw "Candidate changed during validation; previous installation preserved"
    }
    if (Test-Path -LiteralPath $installedPath) {
      Assert-RegularInstallFile $installedPath
      [System.IO.File]::Replace($staged, $installedPath, $backup)
    } else {
      [System.IO.File]::Move($staged, $installedPath)
    }
    try {
      if ($PostVerify) {
        Write-Info "Running self-test..."
        Assert-InstallBinary $installedPath
      }
      if ((Get-InstallFileHash $installedPath) -ne $sourceHash) {
        throw "Installed candidate changed during verification"
      }
    } catch {
      $verificationError = $_.Exception.Message
      try {
        if ([System.IO.File]::Exists($backup)) {
          [System.IO.File]::Replace($backup, $installedPath, $failed)
          $recovery = "prior installation restored"
        } else {
          [System.IO.File]::Move($installedPath, $failed)
          $recovery = "no prior installation existed; candidate withheld"
        }
      } catch {
        throw "Post-install verification failed; restoration is unproven. Inspect $backup and $installedPath. $verificationError; $($_.Exception.Message)"
      }
      throw "Post-install verification failed; $recovery, failed candidate retained at $failed. $verificationError"
    }
    if ($PostVerify) { Write-Ok "Self-test passed" }
    if ([System.IO.File]::Exists($backup)) { Write-Info "Previous installation retained at $backup" }
    Write-Ok "Installed $BinaryName -> $installedPath"
    return $installedPath
  } finally {
    $lock.Dispose()
  }
}

Write-Host ""
Write-Host "franken-node installer" -ForegroundColor Green
Write-Host "franken_engine verified compute node" -ForegroundColor DarkGray
Write-Host ""

# Resolve latest version if not specified
if ((-not $Version) -and (-not $ArtifactUrl)) {
  Write-Info "Resolving latest version..."
  try {
    $apiUrl = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{"Accept"="application/vnd.github.v3+json"} -ErrorAction Stop
    $Version = $release.tag_name
    Write-Info "Resolved latest version: $Version"
  } catch {
    try {
      $redirectUrl = "https://github.com/$Owner/$Repo/releases/latest"
      Invoke-WebRequest -Uri $redirectUrl -MaximumRedirection 0 -ErrorAction Stop | Out-Null
    } catch {
      if ($_.Exception.Response.Headers.Location) {
        $location = $_.Exception.Response.Headers.Location.ToString()
        $extracted = $location -replace ".*/tag/", ""
        if ($extracted -match "^v[0-9]" -and $extracted -notmatch "/") {
          $Version = $extracted
          Write-Info "Resolved latest version via redirect: $Version"
        }
      }
    }
    if (-not $Version) {
      Write-Err "Could not resolve latest release. Re-run with -Version vX.Y.Z or -ArtifactUrl."
      exit 1
    }
  }
}

# Determine target
if (-not [Environment]::Is64BitProcess) {
  Write-Err "32-bit Windows is not supported. Please use a 64-bit system."
  exit 1
}
$target = "x86_64-pc-windows-msvc"
$zip = "$BinaryName-$target.zip"

if (-not $CosignIdentityRegex) {
  $CosignIdentityRegex = "^https://github.com/$Owner/$Repo/.github/workflows/.*@refs/tags/.*$"
}
if (-not $CosignOidcIssuer) {
  $CosignOidcIssuer = "https://token.actions.githubusercontent.com"
}

if ($ArtifactUrl) {
  $url = $ArtifactUrl
} else {
  $url = "https://github.com/$Owner/$Repo/releases/download/$Version/$zip"
}

# Unique temp dir so concurrent installers cannot collide
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("franken_node_install_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
$zipFile = Join-Path $tmp $zip

Write-Info "Downloading $url"
try {
  Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
} catch {
  Write-Err "Failed to download artifact: $_"
  Write-Err "No prebuilt Windows asset for $Version? See the Releases page or build from source."
  exit 1
}

# Verify checksum (unless -NoVerify)
if (-not $NoVerify) {
  $checksumToUse = $Checksum
  if (-not $checksumToUse) {
    if (-not $ChecksumUrl) { $ChecksumUrl = "$url.sha256" }
    Write-Info "Fetching checksum from $ChecksumUrl"
    try {
      # Download to a file rather than reading .Content: GitHub serves .sha256 as
      # application/octet-stream, which Windows PowerShell 5.1 surfaces as a byte
      # array (no .Trim()). Reading the saved file as text avoids that.
      $shaFile = Join-Path $tmp "$zip.sha256"
      Invoke-WebRequest -Uri $ChecksumUrl -OutFile $shaFile -UseBasicParsing
      $checksumToUse = (Get-Content $shaFile -Raw).Trim().Split(' ')[0]
    } catch {
      Write-Err "Checksum file not found or invalid; refusing to install."
      exit 1
    }
  }
  $hash = Get-InstallFileHash $zipFile
  if ($hash -ne $checksumToUse.ToLowerInvariant()) {
    Write-Err "Checksum mismatch! Expected $checksumToUse, got $hash"
    exit 1
  }
  Write-Ok "Checksum verified"

  # Sigstore/cosign (best-effort)
  if (Get-Command cosign -ErrorAction SilentlyContinue) {
    if (-not $SigstoreBundleUrl) { $SigstoreBundleUrl = "$url.sigstore.json" }
    $bundleFile = Join-Path $tmp ([System.IO.Path]::GetFileName($SigstoreBundleUrl))
    try {
      Invoke-WebRequest -Uri $SigstoreBundleUrl -OutFile $bundleFile -UseBasicParsing
      & cosign verify-blob --bundle $bundleFile --certificate-identity-regexp $CosignIdentityRegex --certificate-oidc-issuer $CosignOidcIssuer $zipFile | Out-Null
      if ($LASTEXITCODE -ne 0) { Write-Err "Signature verification failed"; exit 1 }
      Write-Ok "Signature verified (cosign)"
    } catch {
      Write-Warn "Sigstore bundle not found; skipping signature verification"
    }
  } else {
    Write-Warn "cosign not found; skipping signature verification"
  }
} else {
  Write-Warn "Verification skipped (-NoVerify)"
}

# Extract
Write-Info "Extracting..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
$extractDir = Join-Path $tmp "extract"
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $extractDir)

$candidates = @()
if (Test-Path -LiteralPath $extractDir) {
  $candidates = @(Get-ChildItem -LiteralPath $extractDir -Recurse -Filter "$BinaryName.exe" -File)
}
if ($candidates.Count -ne 1) {
  Write-Err "Archive must contain exactly one $BinaryName.exe; found $($candidates.Count)"
  exit 1
}

# Install
try {
  $installed = Install-VerifiedBinary -Source $candidates[0].FullName -Destination $Dest -PostVerify:$Verify
} catch {
  Write-Err "Installation failed: $($_.Exception.Message)"
  exit 1
}

# PATH management
$path = [Environment]::GetEnvironmentVariable("PATH", "User")
if (-not (Test-UserPathContains -PathValue $path -PathToFind $Dest)) {
  if ($EasyMode) {
    if ([string]::IsNullOrEmpty($path)) {
      [Environment]::SetEnvironmentVariable("PATH", $Dest, "User")
    } else {
      [Environment]::SetEnvironmentVariable("PATH", "$path;$Dest", "User")
    }
    Write-Ok "Added $Dest to User PATH (restart your shell)"
  } else {
    Write-Warn "$Dest is not on PATH. Add it, or re-run with -EasyMode"
  }
}

# Cleanup
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

Write-Host ""
Write-Ok "Done. franken-node installed at: $installed"
Write-Info "Run 'franken-node --help' to get started."
Write-Info "Uninstall: Remove-Item '$installed'"
