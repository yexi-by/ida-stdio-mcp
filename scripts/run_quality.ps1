$ErrorActionPreference = "Stop"

function Invoke-CheckedNativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    & $Executable @ArgumentList
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $command = "$Executable $($ArgumentList -join ' ')"
        throw "命令执行失败，退出码为 ${exitCode}: $command"
    }
}

function Invoke-CheckedPowerShellScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [hashtable]$Parameters = @{}
    )

    & $ScriptPath @Parameters
    $scriptSucceeded = $?
    $exitCode = $LASTEXITCODE
    if (-not $scriptSucceeded -or ($null -ne $exitCode -and $exitCode -ne 0)) {
        throw "PowerShell 子脚本执行失败，退出码为 ${exitCode}: $ScriptPath"
    }
}

$repository = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$qualityRoot = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("ida-re-mcp-quality-" + [Guid]::NewGuid().ToString("N"))
$qualityRoot = [System.IO.Path]::GetFullPath($qualityRoot)
$temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
if (-not $qualityRoot.StartsWith(
    $temporaryRoot,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "质量检查的临时目录必须位于系统临时目录"
}

$hadProjectEnvironment = Test-Path Env:UV_PROJECT_ENVIRONMENT
$originalProjectEnvironment = $env:UV_PROJECT_ENVIRONMENT
if (-not $env:UV_PROJECT_ENVIRONMENT) {
    $env:UV_PROJECT_ENVIRONMENT = Join-Path $qualityRoot "project-venv"
}
$projectEnvironment = [System.IO.Path]::GetFullPath($env:UV_PROJECT_ENVIRONMENT)
$repositoryPrefix = $repository + [System.IO.Path]::DirectorySeparatorChar
if (
    $projectEnvironment.Equals(
        $repository,
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or
    $projectEnvironment.StartsWith(
        $repositoryPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )
) {
    throw "UV_PROJECT_ENVIRONMENT 不能是项目目录或项目中的子目录"
}

try {
    $distribution = Join-Path $qualityRoot "dist"
    $smokeEnvironment = Join-Path $qualityRoot "smoke-venv"
    $runtimeData = Join-Path $qualityRoot "runtime"
    $pytestCache = Join-Path $qualityRoot "pytest-cache"
    $env:RUFF_CACHE_DIR = Join-Path $qualityRoot "ruff-cache"
    $env:HYPOTHESIS_STORAGE_DIRECTORY = Join-Path $qualityRoot "hypothesis"
    $env:PYTHONPYCACHEPREFIX = Join-Path $qualityRoot "pycache"
    New-Item -ItemType Directory -Force -Path $distribution, $runtimeData | Out-Null

    Invoke-CheckedNativeCommand "uv" @("python", "install", "3.13")
    Invoke-CheckedNativeCommand "uv" @("lock", "--check")
    Invoke-CheckedNativeCommand "uv" @("sync", "--locked")
    Invoke-CheckedNativeCommand "uv" @(
        "run",
        "--locked",
        "python",
        "-c",
        "import sys; assert sys.version_info[:2] == (3, 13)"
    )
    Invoke-CheckedNativeCommand "uv" @("run", "--locked", "ruff", "format", "--check", ".")
    Invoke-CheckedNativeCommand "uv" @("run", "--locked", "ruff", "check", ".")
    Invoke-CheckedNativeCommand "uv" @("run", "--locked", "basedpyright")
    Invoke-CheckedNativeCommand "uv" @(
        "run",
        "--locked",
        "pytest",
        "-q",
        "tests/unit",
        "tests/integration",
        "-o",
        "cache_dir=$pytestCache"
    )
    Invoke-CheckedPowerShellScript (Join-Path $PSScriptRoot "check_fixture_reproducibility.ps1")
    Invoke-CheckedNativeCommand "uv" @(
        "build",
        "--no-sources",
        "--out-dir",
        $distribution
    )

    $wheel = @(Get-ChildItem -LiteralPath $distribution -Filter "*.whl")
    if ($wheel.Count -ne 1) {
        throw "wheel 构建必须且只能产生一个 .whl"
    }
    Invoke-CheckedNativeCommand "uv" @(
        "venv",
        "--python",
        "3.13",
        $smokeEnvironment
    )
    $smokePython = Join-Path $smokeEnvironment "Scripts/python.exe"
    $smokeExecutable = Join-Path $smokeEnvironment "Scripts/ida-re-mcp.exe"
    Invoke-CheckedNativeCommand "uv" @(
        "pip",
        "install",
        "--python",
        $smokePython,
        $wheel[0].FullName
    )

    $originalLocalAppData = $env:LOCALAPPDATA
    try {
        $env:LOCALAPPDATA = $runtimeData
        Invoke-CheckedPowerShellScript `
            (Join-Path $PSScriptRoot "stdio_smoke.ps1") `
            @{ Executable = $smokeExecutable }
    }
    finally {
        $env:LOCALAPPDATA = $originalLocalAppData
    }
}
finally {
    if ($hadProjectEnvironment) {
        $env:UV_PROJECT_ENVIRONMENT = $originalProjectEnvironment
    }
    else {
        Remove-Item Env:UV_PROJECT_ENVIRONMENT -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $qualityRoot) {
        Remove-Item -Recurse -Force -LiteralPath $qualityRoot
    }
}
