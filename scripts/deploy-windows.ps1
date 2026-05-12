[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublishDir,

    [Parameter(Mandatory = $true)]
    [string]$DeployRoot,

    [string]$ReleaseRoot = "",
    [string]$ServiceStopCommand = "",
    [string]$ServiceStartCommand = "",
    [string]$HealthcheckUrl = "",
    [string]$AppSettingsProductionJsonBase64 = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-RobocopyMirror {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    & robocopy $Source $Destination /MIR /R:2 /W:2 /NFL /NDL /NP
    $exitCode = $LASTEXITCODE
    if ($exitCode -gt 7) {
        throw "robocopy failed with exit code $exitCode"
    }
}

function Invoke-OptionalCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Command)) {
        Write-Host "$Label was skipped."
        return
    }

    Write-Host "${Label}: $Command"
    Invoke-Expression $Command

    if (-not $?) {
        throw "$Label failed."
    }
}

function Write-ProductionSettings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetReleaseDir,

        [Parameter(Mandatory = $true)]
        [string]$ActiveDir,

        [AllowEmptyString()]
        [string]$EncodedSettings
    )

    $targetPath = Join-Path $TargetReleaseDir "appsettings.Production.json"
    $currentPath = Join-Path $ActiveDir "appsettings.Production.json"

    if (-not [string]::IsNullOrWhiteSpace($EncodedSettings)) {
        $bytes = [Convert]::FromBase64String($EncodedSettings)
        [System.IO.File]::WriteAllBytes($targetPath, $bytes)
        Write-Host "Wrote appsettings.Production.json from GitHub Secret."
        return
    }

    if (Test-Path $currentPath) {
        Copy-Item $currentPath $targetPath -Force
        Write-Host "Copied existing appsettings.Production.json from active deployment."
        return
    }

    Write-Host "No production settings file was supplied."
}

function Invoke-Healthcheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Host "Healthcheck was skipped."
        return
    }

    $maxAttempts = 12
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
                Write-Host "Healthcheck succeeded: $Url"
                return
            }
        }
        catch {
            Write-Host "Healthcheck attempt $attempt/$maxAttempts failed: $($_.Exception.Message)"
        }

        Start-Sleep -Seconds 5
    }

    throw "Healthcheck failed: $Url"
}

if (-not (Test-Path $PublishDir)) {
    throw "PublishDir does not exist: $PublishDir"
}

$releaseBaseDir = if ([string]::IsNullOrWhiteSpace($ReleaseRoot)) {
    Join-Path $DeployRoot "releases"
}
else {
    $ReleaseRoot
}

$activeDir = Join-Path $DeployRoot "current"
$backupBaseDir = Join-Path $DeployRoot "backups"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$releaseDir = Join-Path $releaseBaseDir $timestamp
$backupDir = Join-Path $backupBaseDir $timestamp

New-Item -ItemType Directory -Path $releaseBaseDir -Force | Out-Null
New-Item -ItemType Directory -Path $backupBaseDir -Force | Out-Null

Invoke-RobocopyMirror -Source $PublishDir -Destination $releaseDir
Write-ProductionSettings -TargetReleaseDir $releaseDir -ActiveDir $activeDir -EncodedSettings $AppSettingsProductionJsonBase64

Invoke-OptionalCommand -Command $ServiceStopCommand -Label "Stop command"

if (Test-Path $activeDir) {
    Invoke-RobocopyMirror -Source $activeDir -Destination $backupDir
}

Invoke-RobocopyMirror -Source $releaseDir -Destination $activeDir
Invoke-OptionalCommand -Command $ServiceStartCommand -Label "Start command"
Invoke-Healthcheck -Url $HealthcheckUrl

Write-Host "Deployment completed. Active directory: $activeDir"
