$ErrorActionPreference = "Stop"

$repository = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if (-not $env:UV_PROJECT_ENVIRONMENT) {
    $env:UV_PROJECT_ENVIRONMENT = Join-Path $env:LOCALAPPDATA "ida-re-mcp/dev-venv"
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
    throw "UV_PROJECT_ENVIRONMENT 必须位于工作树外"
}

$qualityRoot = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("ida-re-mcp-quality-" + [Guid]::NewGuid().ToString("N"))
$qualityRoot = [System.IO.Path]::GetFullPath($qualityRoot)
$temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
if (-not $qualityRoot.StartsWith(
    $temporaryRoot,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "质量门禁临时目录必须位于平台临时目录"
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

    uv python install 3.13
    uv lock --check
    uv sync --locked
    uv run --locked python -c "import sys; assert sys.version_info[:2] == (3, 13)"
    uv run --locked ruff format --check .
    uv run --locked ruff check .
    uv run --locked basedpyright
    uv run --locked pytest -q tests/unit tests/integration -o "cache_dir=$pytestCache"
    & (Join-Path $PSScriptRoot "check_fixture_reproducibility.ps1")
    uv build --no-sources --out-dir $distribution

    $wheel = @(Get-ChildItem -LiteralPath $distribution -Filter "*.whl")
    if ($wheel.Count -ne 1) {
        throw "wheel 构建必须且只能产生一个 .whl"
    }
    uv venv --python 3.13 $smokeEnvironment
    $smokePython = Join-Path $smokeEnvironment "Scripts/python.exe"
    $smokeExecutable = Join-Path $smokeEnvironment "Scripts/ida-re-mcp.exe"
    uv pip install --python $smokePython $wheel[0].FullName

    $originalLocalAppData = $env:LOCALAPPDATA
    try {
        $env:LOCALAPPDATA = $runtimeData
        & (Join-Path $PSScriptRoot "stdio_smoke.ps1") -Executable $smokeExecutable
    }
    finally {
        $env:LOCALAPPDATA = $originalLocalAppData
    }
}
finally {
    if (Test-Path -LiteralPath $qualityRoot) {
        Remove-Item -Recurse -Force -LiteralPath $qualityRoot
    }
}
