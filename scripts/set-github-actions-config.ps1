[CmdletBinding()]
param(
    [string] $Repo = "Takeru-k7a/Auth",

    [string] $VariablesFile = "",

    [string] $SecretsFile = "",

    [string] $GhPath = "",

    [switch] $SkipSecrets,

    [switch] $DryRun
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path $Path
}

function Read-JsonObject {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "JSON file not found: $Path"
    }

    $json = Get-Content -Raw -Encoding UTF8 -LiteralPath $Path | ConvertFrom-Json
    if ($null -eq $json) {
        throw "JSON file is empty: $Path"
    }

    return $json
}

function Invoke-Gh {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    if ($DryRun) {
        Write-Output ("$GhPath " + ($Arguments -join " "))
        return
    }

    & $GhPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$GhPath failed with exit code $LASTEXITCODE"
    }
}

if ([string]::IsNullOrWhiteSpace($VariablesFile)) {
    $VariablesFile = "deploy/github-actions.variables.json"
}

if ([string]::IsNullOrWhiteSpace($SecretsFile)) {
    $SecretsFile = "deploy/github-actions.secrets.json"
}

$variablesPath = Resolve-RepoPath $VariablesFile
$secretsPath = Resolve-RepoPath $SecretsFile

if ([string]::IsNullOrWhiteSpace($GhPath)) {
    $ghCommand = Get-Command gh -ErrorAction SilentlyContinue
    if ($ghCommand) {
        $GhPath = $ghCommand.Source
    }
    elseif (Test-Path -LiteralPath "${env:ProgramFiles}\GitHub CLI\gh.exe") {
        $GhPath = "${env:ProgramFiles}\GitHub CLI\gh.exe"
    }
    elseif (Test-Path -LiteralPath "${env:LOCALAPPDATA}\Programs\GitHub CLI\gh.exe") {
        $GhPath = "${env:LOCALAPPDATA}\Programs\GitHub CLI\gh.exe"
    }
    else {
        $GhPath = "gh"
    }
}

if (-not $DryRun -and -not (Test-Path -LiteralPath $GhPath) -and -not (Get-Command $GhPath -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI is not available. Install gh, restart PowerShell, or pass -GhPath."
}

$variables = Read-JsonObject $variablesPath
foreach ($property in $variables.PSObject.Properties) {
    $name = $property.Name
    $value = [string] $property.Value

    if ([string]::IsNullOrWhiteSpace($value)) {
        Write-Warning "Skip empty variable: $name"
        continue
    }

    Write-Output "Set GitHub variable: $name"
    Invoke-Gh @("variable", "set", $name, "--repo", $Repo, "--body", $value)
}

if ($SkipSecrets) {
    Write-Output "Skip GitHub secrets."
    exit 0
}

if (-not (Test-Path -LiteralPath $secretsPath)) {
    Write-Warning "Secrets file not found, skipped: $secretsPath"
    Write-Warning "Create it from deploy/github-actions.secrets.example.json when you want to set secrets."
    exit 0
}

$secrets = Read-JsonObject $secretsPath
foreach ($property in $secrets.PSObject.Properties) {
    $name = $property.Name
    $value = [string] $property.Value

    if ([string]::IsNullOrWhiteSpace($value)) {
        Write-Warning "Skip empty secret: $name"
        continue
    }

    Write-Output "Set GitHub secret: $name"
    Invoke-Gh @("secret", "set", $name, "--repo", $Repo, "--app", "actions", "--body", $value)
}
