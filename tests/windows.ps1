#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$vaultPath = Join-Path $repoRoot 'bin\vault.ps1'
$testDir = Join-Path ([IO.Path]::GetTempPath()) ('blind-vault-test-' + [Guid]::NewGuid().ToString('N'))
$oldVaultDir = $env:BLINDVAULT_DIR
$env:BLINDVAULT_DIR = $testDir

$testId = [Guid]::NewGuid().ToString('N')
$basicName = 'codex-basic-' + $testId
$caseName = 'Codex-Case-' + $testId
$scopeName = 'codex-scope-' + $testId
$largeName = 'codex-large-' + $testId
$tooLargeName = 'codex-too-large-' + $testId
$cleanupNames = @($basicName, $caseName, $scopeName, $largeName, $tooLargeName)
$assertions = 0

function Invoke-VaultProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Arguments,
        [string]$StandardInput = ''
    )

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = 'powershell.exe'
    $startInfo.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $vaultPath + '" ' + $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $true

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()
    if ($StandardInput) {
        $process.StandardInput.WriteLine($StandardInput)
    }
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{ Code = $process.ExitCode; Out = $stdout; Err = $stderr }
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "assertion failed: $Message"
    }
    $script:assertions++
}

New-Item -ItemType Directory -Path $testDir -Force | Out-Null

try {
    $init = Invoke-VaultProcess 'init'
    Assert-True ($init.Code -eq 0) 'init succeeds'

    $secret = 'blindvault-test-' + [Guid]::NewGuid().ToString('N')
    $add = Invoke-VaultProcess (
        'add ' + $basicName +
        ' --from-stdin --service Test --env BV_TEST_SECRET --allow powershell.exe'
    ) $secret
    Assert-True ($add.Code -eq 0) 'add succeeds'

    $manifestPath = Join-Path $testDir 'manifest.json'
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    Assert-True ($manifestText.Contains($basicName)) 'manifest contains pointer'
    Assert-True (-not $manifestText.Contains($secret)) 'manifest does not contain value'
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $hasBom = $manifestBytes.Length -ge 3 -and $manifestBytes[0] -eq 0xEF -and
        $manifestBytes[1] -eq 0xBB -and $manifestBytes[2] -eq 0xBF
    Assert-True (-not $hasBom) 'manifest is UTF-8 without BOM'

    $emitScript = '[Console]::Out.Write($env:BV_TEST_SECRET); exit 0'
    $emitEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($emitScript))
    $use = Invoke-VaultProcess (
        'use ' + $basicName +
        ' -- powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + $emitEncoded
    )
    Assert-True ($use.Code -eq 0) 'use preserves success exit code'
    Assert-True ($use.Out.Contains("[REDACTED:$basicName]")) 'exact value is redacted'
    Assert-True (-not $use.Out.Contains($secret)) 'use output does not leak value'

    $blocked = Invoke-VaultProcess ('use ' + $basicName + ' -- cmd.exe /d /c exit 0')
    Assert-True ($blocked.Code -ne 0) 'scope mismatch fails'
    Assert-True (($blocked.Out + $blocked.Err).Contains('SCOPE BLOCK')) 'scope mismatch is explicit'

    $exitScript = 'exit 23'
    $exitEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($exitScript))
    $exitResult = Invoke-VaultProcess (
        'use ' + $basicName +
        ' -- powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + $exitEncoded
    )
    Assert-True ($exitResult.Code -eq 23) 'child exit code is preserved'

    $list = Invoke-VaultProcess 'ls'
    Assert-True ($list.Code -eq 0) 'list succeeds'
    Assert-True ($list.Out.Contains($basicName)) 'list contains pointer'
    Assert-True (-not $list.Out.Contains($secret)) 'list does not leak value'

    $badDelay = Invoke-VaultProcess ('type ' + $basicName + ' --delay -1')
    Assert-True ($badDelay.Code -ne 0) 'type rejects a negative delay'
    Assert-True (($badDelay.Out + $badDelay.Err).Contains('--delay')) 'type delay error is explicit'

    $oldTypeApps = $env:BLINDVAULT_TYPE_APPS
    try {
        $env:BLINDVAULT_TYPE_APPS = 'blindvault-impossible-browser-' + $testId
        $guardedType = Invoke-VaultProcess ('type ' + $basicName + ' --delay 0')
        Assert-True ($guardedType.Code -ne 0) 'type refuses a non-browser foreground process'
        Assert-True (($guardedType.Out + $guardedType.Err).Contains('nothing was typed')) 'type guard is explicit'
        Assert-True (-not ($guardedType.Out + $guardedType.Err).Contains($secret)) 'type guard output does not leak value'
    } finally {
        $env:BLINDVAULT_TYPE_APPS = $oldTypeApps
    }

    $caseSecret = 'case-' + [Guid]::NewGuid().ToString('N')
    $caseAdd = Invoke-VaultProcess (
        'add ' + $caseName + ' --from-stdin --env BV_CASE --allow cmd.exe'
    ) $caseSecret
    Assert-True ($caseAdd.Code -eq 0) 'mixed-case name can be added'
    $caseCollision = Invoke-VaultProcess (
        'add ' + $caseName.ToLowerInvariant() + ' --from-stdin --env BV_CASE --allow cmd.exe'
    ) 'unused-test-value'
    Assert-True ($caseCollision.Code -ne 0) 'case-insensitive target collision is rejected'

    $scopeAdd = Invoke-VaultProcess (
        'add ' + $scopeName + ' --from-stdin --env BV_SCOPE --allow openai.com'
    ) ('scope-' + [Guid]::NewGuid().ToString('N'))
    Assert-True ($scopeAdd.Code -eq 0) 'domain-scoped credential can be added'
    $subdomain = Invoke-VaultProcess (
        'use ' + $scopeName + ' -- cmd.exe /d /c rem api.openai.com'
    )
    Assert-True ($subdomain.Code -eq 0) 'scope permits a subdomain'
    $port = Invoke-VaultProcess (
        'use ' + $scopeName + ' -- cmd.exe /d /c rem openai.com:443'
    )
    Assert-True ($port.Code -eq 0) 'scope permits a port boundary'
    $suffixAttack = Invoke-VaultProcess (
        'use ' + $scopeName + ' -- cmd.exe /d /c rem openai.com.evil.io'
    )
    Assert-True ($suffixAttack.Code -ne 0) 'scope blocks a malicious domain suffix'
    $prefixAttack = Invoke-VaultProcess (
        'use ' + $scopeName + ' -- cmd.exe /d /c rem notopenai.com'
    )
    Assert-True ($prefixAttack.Code -ne 0) 'scope blocks a malicious domain prefix'

    $oldForce = $env:BLINDVAULT_FORCE
    try {
        $env:BLINDVAULT_FORCE = '0'
        $zeroForce = Invoke-VaultProcess ('use ' + $scopeName + ' -- cmd.exe /d /c exit 0')
        Assert-True ($zeroForce.Code -ne 0) 'BLINDVAULT_FORCE=0 does not bypass scope'
        $env:BLINDVAULT_FORCE = '1'
        $humanForce = Invoke-VaultProcess ('use ' + $scopeName + ' -- cmd.exe /d /c exit 0')
        Assert-True ($humanForce.Code -eq 0) 'BLINDVAULT_FORCE=1 bypasses scope'
    } finally {
        $env:BLINDVAULT_FORCE = $oldForce
    }

    $largeSecret = 'x' * 2560
    $largeAdd = Invoke-VaultProcess (
        'add ' + $largeName + ' --from-stdin --env BV_LARGE --allow cmd.exe'
    ) $largeSecret
    Assert-True ($largeAdd.Code -eq 0) '2560-byte credential is accepted'

    $tooLargeSecret = 'x' * 2561
    $tooLargeAdd = Invoke-VaultProcess (
        'add ' + $tooLargeName + ' --from-stdin --env BV_TOO_LARGE --allow cmd.exe'
    ) $tooLargeSecret
    Assert-True ($tooLargeAdd.Code -ne 0) '2561-byte credential is rejected'
    $postLimitManifest = [IO.File]::ReadAllText($manifestPath)
    Assert-True (-not $postLimitManifest.Contains($tooLargeName)) 'oversize failure creates no pointer'

    Write-Output "PASS: $assertions Windows backend assertions"
} finally {
    foreach ($name in $cleanupNames) {
        [void](Invoke-VaultProcess ('rm ' + $name))
    }
    $env:BLINDVAULT_DIR = $oldVaultDir
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedTestDir = [IO.Path]::GetFullPath($testDir)
    if ($resolvedTestDir.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTestDir)) {
        [IO.Directory]::Delete($resolvedTestDir, $true)
    }
}
