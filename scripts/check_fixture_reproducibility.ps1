$ErrorActionPreference = "Stop"

$repository = Split-Path -Parent $PSScriptRoot
$committed = [System.IO.Path]::GetFullPath(
    (Join-Path $repository "tests/fixtures/bin/SHA256SUMS")
)
$temporaryRootValue = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
if (-not $temporaryRootValue) {
    throw "复现检查需要 RUNNER_TEMP 或 TEMP"
}
$temporaryRoot = [System.IO.Path]::GetFullPath($temporaryRootValue)
$nonce = [Guid]::NewGuid().ToString("N")
$reproRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $temporaryRoot "ida-re-mcp-fixtures-$nonce")
)
$first = [System.IO.Path]::GetFullPath((Join-Path $reproRoot "a"))
$second = [System.IO.Path]::GetFullPath((Join-Path $reproRoot "b"))

if (
    $reproRoot -eq $temporaryRoot -or
    -not $reproRoot.StartsWith($temporaryRoot + [System.IO.Path]::DirectorySeparatorChar)
) {
    throw "复现检查目录必须严格位于临时目录内"
}

try {
    & (Join-Path $PSScriptRoot "build_fixtures.ps1") `
        -OutputDirectory $first -ExternalOutput
    & (Join-Path $PSScriptRoot "build_fixtures.ps1") `
        -OutputDirectory $second -ExternalOutput

    $firstManifest = Get-Content -LiteralPath (Join-Path $first "SHA256SUMS")
    $secondManifest = Get-Content -LiteralPath (Join-Path $second "SHA256SUMS")
    $committedManifest = Get-Content -LiteralPath $committed
    foreach ($comparison in @(
        @{
            Name = "两个独立目录"
            Difference = Compare-Object $firstManifest $secondManifest
        },
        @{
            Name = "新构建与提交清单"
            Difference = Compare-Object $firstManifest $committedManifest
        }
    )) {
        if ($comparison.Difference) {
            $comparison.Difference | Out-String | Write-Error
            throw "fixture $($comparison.Name) 的摘要不一致"
        }
    }
}
finally {
    $resolved = [System.IO.Path]::GetFullPath($reproRoot)
    if (
        (Test-Path -LiteralPath $resolved) -and
        $resolved -ne $temporaryRoot -and
        $resolved.StartsWith($temporaryRoot + [System.IO.Path]::DirectorySeparatorChar)
    ) {
        Remove-Item -Recurse -Force -LiteralPath $resolved
    }
}
