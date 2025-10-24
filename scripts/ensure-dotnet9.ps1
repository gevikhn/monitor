Param(
    [string]$Version = "9.0.0",
    [string]$InstallDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$isWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)

function Get-InstalledDotnetRuntimes {
    $dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnetCmd) {
        return @()
    }

    $lines = & $dotnetCmd.Path --list-runtimes 2>$null
    if (-not $lines) {
        return @()
    }

    return $lines |
        ForEach-Object {
            if ($_ -match "^\s*(?<name>[\w\.\-]+)\s+(?<version>\d+\.\d+\.\d+)") {
                [PSCustomObject]@{
                    Name    = $Matches.name
                    Version = [Version]$Matches.version
                }
            }
        }
}

function Test-DotnetRuntimeInstalled([Version]$minimumVersion) {
    $runtimes = Get-InstalledDotnetRuntimes
    foreach ($runtime in $runtimes) {
        if ($runtime.Name -eq "Microsoft.NETCore.App" -and $runtime.Version -ge $minimumVersion) {
            return $true
        }
    }

    return $false
}

if (-not $InstallDir) {
    if ($isWindows) {
        $InstallDir = Join-Path $env:LOCALAPPDATA "Microsoft\dotnet"
    } else {
        $InstallDir = "$HOME/.dotnet"
    }
}

Write-Host "Checking for Microsoft.NETCore.App runtime >= $Version..."
$minimumVersion = [Version]$Version

if (Test-DotnetRuntimeInstalled -minimumVersion $minimumVersion) {
    Write-Host "Required .NET runtime already present."
    exit 0
}

Write-Host "Runtime not found. Downloading dotnet-install script..."
$tempDir = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ("dotnet-install-" + [Guid]::NewGuid())) -Force

try {
    $installScript = Join-Path $tempDir.FullName "dotnet-install.ps1"
    Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile $installScript

    Write-Host "Installing .NET runtime $Version to '$InstallDir'..."
    & $installScript -Runtime dotnet -Version $Version -InstallDir $InstallDir

    Write-Host ".NET runtime installation finished."
    Write-Host ""
    Write-Host "If 'dotnet' is not found automatically, add the following path to your PATH environment variable:"
    Write-Host "  $InstallDir"

    if (-not (Test-DotnetRuntimeInstalled -minimumVersion $minimumVersion)) {
        Write-Warning "The runtime was installed, but it is not visible to the current shell. You might need to restart the terminal or update PATH."
    } else {
        Write-Host "Verified: Microsoft.NETCore.App runtime >= $Version is now available."
    }
}
finally {
    if (Test-Path $tempDir.FullName) {
        Remove-Item $tempDir.FullName -Recurse -Force
    }
}
