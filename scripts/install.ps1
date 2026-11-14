<#
.SYNOPSIS
  Install Universal Dev Security for the current user (no administrator rights).

.DESCRIPTION
  Creates a dedicated virtual environment in %LOCALAPPDATA%\UDS\venv and installs
  UDS from a local wheel (verified against SHA256SUMS when present) or a pip
  specification. It does NOT install scanners and does NOT change PATH unless
  -AddToPath is given (user PATH only).

.EXAMPLE
  .\scripts\install.ps1 -Wheel .\dist\1.0.0\universal_dev_security-1.0.0-py3-none-any.whl
#>
[CmdletBinding()]
param(
    [string]$Wheel,
    [string]$Spec,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "UDS"),
    [switch]$AddToPath
)
$ErrorActionPreference = "Stop"

if (-not $Wheel -and -not $Spec) { throw "Provide -Wheel <path> or -Spec <pip specification>." }

function Find-Python {
    foreach ($candidate in @(@("py", "-3"), @("python"))) {
        $exe = $candidate[0]
        $extra = @($candidate | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $ok = & $exe @extra -c "import sys; print(sys.version_info >= (3, 11))" 2>$null
        if ($LASTEXITCODE -eq 0 -and $ok -eq "True") { return ,$candidate }
    }
    return $null
}
$python = Find-Python
if (-not $python) { throw "Python 3.11 or newer is required. Install it from https://www.python.org/downloads/" }
$pythonExtra = @($python | Select-Object -Skip 1)

if ($Wheel) {
    $Wheel = (Resolve-Path $Wheel).Path
    $sums = Join-Path (Split-Path $Wheel) "SHA256SUMS"
    if (Test-Path $sums) {
        $name = Split-Path $Wheel -Leaf
        $expected = (Get-Content $sums | Where-Object { $_ -match "\s$([regex]::Escape($name))$" }) -split "\s+" | Select-Object -First 1
        $actual = (Get-FileHash -Algorithm SHA256 $Wheel).Hash.ToLowerInvariant()
        if (-not $expected -or $expected -ne $actual) { throw "Checksum verification failed for $name." }
        Write-Host "Checksum verified: $name"
    } else {
        Write-Warning "No SHA256SUMS next to the wheel; integrity was not verified."
    }
}

$venv = Join-Path $InstallDir "venv"
& $python[0] @pythonExtra -m venv $venv
if ($LASTEXITCODE -ne 0) { throw "Could not create the virtual environment." }
$venvPython = Join-Path $venv "Scripts\python.exe"
& $venvPython -m pip install --upgrade pip | Out-Null
if ($Wheel) { & $venvPython -m pip install --upgrade $Wheel } else { & $venvPython -m pip install --upgrade $Spec }
if ($LASTEXITCODE -ne 0) { throw "pip installation failed." }

$scripts = Join-Path $venv "Scripts"
& (Join-Path $scripts "uds.exe") --version

if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ";") -notcontains $scripts) {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$scripts", "User")
        Write-Host "Added $scripts to your user PATH. Open a new terminal to use 'uds'."
    }
} else {
    Write-Host "Installed. Add this folder to your PATH to use 'uds' everywhere (or re-run with -AddToPath):"
    Write-Host "  $scripts"
}
Write-Host "Next: install scanners from their official sources, then run 'uds doctor'."
