param(
    [Parameter(Mandatory = $true)]
    [string]$Executable
)

$ErrorActionPreference = "Stop"

$executablePath = [System.IO.Path]::GetFullPath($Executable)
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
    throw "找不到 ida-re-mcp 可执行文件: $executablePath"
}

$pythonPath = Join-Path (Split-Path -Parent $executablePath) "python.exe"
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw "找不到安装环境的 Python: $pythonPath"
}

& $pythonPath (Join-Path $PSScriptRoot "stdio_smoke.py") $executablePath
if ($LASTEXITCODE -ne 0) {
    throw "ida-re-mcp stdio smoke 失败，退出码为 $LASTEXITCODE"
}
