[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ProjectId,

    [string] $Region = "us-west1",

    [string] $Repository = "auth",

    [string] $ImageName = "authfoundation-api",

    [string] $Tag = ""
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

if ([string]::IsNullOrWhiteSpace($Tag)) {
    $gitTag = & git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($gitTag)) {
        $Tag = $gitTag.Trim()
    }
    else {
        $Tag = Get-Date -Format "yyyyMMddHHmmss"
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$contextPath = Join-Path $repoRoot "AuthFoundation"
$imageUri = "${Region}-docker.pkg.dev/${ProjectId}/${Repository}/${ImageName}:${Tag}"

Invoke-Checked "gcloud" @("config", "set", "project", $ProjectId)
Invoke-Checked "gcloud" @(
    "services",
    "enable",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com"
)

& gcloud artifacts repositories describe $Repository --location $Region --project $ProjectId *> $null
$repositoryExists = $LASTEXITCODE -eq 0

if (-not $repositoryExists) {
    Invoke-Checked "gcloud" @(
        "artifacts",
        "repositories",
        "create",
        $Repository,
        "--repository-format=docker",
        "--location=$Region",
        "--description=AuthFoundation container images",
        "--project=$ProjectId"
    )
}

Invoke-Checked "gcloud" @(
    "builds",
    "submit",
    $contextPath,
    "--tag",
    $imageUri,
    "--project",
    $ProjectId
)

Write-Output $imageUri
