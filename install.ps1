#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipSkill,
    [switch]$AddToPath
)

$ErrorActionPreference = 'Stop'
$repoDir = $PSScriptRoot
$vaultScript = Join-Path $repoDir 'bin\vault.ps1'
$vaultShim = Join-Path $repoDir 'bin\vault.cmd'
$userProfileDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$skillParent = Join-Path $userProfileDir '.claude\skills'
$skillDir = Join-Path $skillParent 'vault'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'blind-vault Windows installer must run in native Windows PowerShell, not WSL/Linux.'
}
if (-not (Test-Path -LiteralPath $vaultScript) -or -not (Test-Path -LiteralPath $vaultShim)) {
    throw 'bin\vault.ps1 or bin\vault.cmd is missing.'
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $vaultScript init

if (-not $SkipSkill) {
    New-Item -ItemType Directory -Path $skillParent -Force | Out-Null
    if (Test-Path -LiteralPath $skillDir) {
        $existing = Get-Item -LiteralPath $skillDir -Force
        $rawTarget = [string]$existing.Target
        if ([string]::IsNullOrWhiteSpace($rawTarget)) {
            throw "$skillDir already exists and is not a link. Move it aside or rerun with -SkipSkill."
        }
        $targetPath = if ([IO.Path]::IsPathRooted($rawTarget)) {
            [IO.Path]::GetFullPath($rawTarget)
        } else {
            [IO.Path]::GetFullPath((Join-Path $existing.Parent.FullName $rawTarget))
        }
        if (-not $targetPath.Equals([IO.Path]::GetFullPath($repoDir), [StringComparison]::OrdinalIgnoreCase)) {
            throw "$skillDir points to '$targetPath', not this repository. Move it aside or rerun with -SkipSkill."
        }
    } else {
        New-Item -ItemType Junction -Path $skillDir -Target $repoDir | Out-Null
    }
}

if ($AddToPath) {
    $binDir = [IO.Path]::GetFullPath((Join-Path $repoDir 'bin'))
    $userPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User)
    $pathEntries = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $alreadyPresent = @($pathEntries | Where-Object {
        try {
            [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($_)).TrimEnd('\') -eq
                $binDir.TrimEnd('\')
        } catch {
            $false
        }
    }).Count -gt 0
    if (-not $alreadyPresent) {
        $updatedPath = [string]::Join(';', @($pathEntries + $binDir))
        [Environment]::SetEnvironmentVariable('Path', $updatedPath, [EnvironmentVariableTarget]::User)
    }
}

Write-Output ''
Write-Output 'Windows backend installed.'
Write-Output "  CLI: $vaultShim"
if (-not $SkipSkill) {
    Write-Output "  Skill: $skillDir -> $repoDir"
}
Write-Output ''
if ($AddToPath) {
    Write-Output 'The repository bin directory was added to your user PATH. Open a new terminal.'
} else {
    Write-Output 'Optional: rerun with -AddToPath, or add this directory to your user PATH:'
    Write-Output "  $repoDir\bin"
}
Write-Output ''
Write-Output 'Try: vault.cmd add openai-api-key --env OPENAI_API_KEY --allow api.openai.com'
