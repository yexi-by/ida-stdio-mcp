param(
    [Parameter(Mandatory = $true)]
    [string]$Executable
)

$ErrorActionPreference = "Stop"

$executablePath = [System.IO.Path]::GetFullPath($Executable)
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
    throw "找不到 ida-re-mcp 可执行文件: $executablePath"
}

$request = @{
    jsonrpc = "2.0"
    id = "discover-smoke"
    method = "server/discover"
    params = @{
        _meta = @{
            "io.modelcontextprotocol/protocolVersion" = "2026-07-28"
            "io.modelcontextprotocol/clientCapabilities" = @{}
            "io.modelcontextprotocol/clientInfo" = @{
                name = "ida-re-mcp-stdio-smoke"
                version = "1.0.0"
            }
        }
    }
} | ConvertTo-Json -Compress -Depth 8

$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $executablePath
$startInfo.ArgumentList.Add("serve")
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
$started = $false
try {
    if (-not $process.Start()) {
        throw "无法启动 ida-re-mcp stdio smoke"
    }
    $started = $true
    $process.StandardInput.WriteLine($request)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    if (-not $process.WaitForExit(30000)) {
        $process.Kill($true)
        throw "ida-re-mcp stdio smoke 在 30 秒内未退出"
    }
    if ($process.ExitCode -ne 0) {
        throw ("ida-re-mcp stdio smoke 退出码为 {0}: {1}" -f $process.ExitCode, $stderr)
    }
}
finally {
    if ($started -and -not $process.HasExited) {
        $process.Kill($true)
        $process.WaitForExit()
    }
    $process.Dispose()
}

$lines = @($stdout -split "\r?\n" | Where-Object { $_.Length -gt 0 })
if ($lines.Count -ne 1) {
    throw "stdout 必须且只能包含一条 JSON-RPC 响应，实际为 $($lines.Count) 条"
}

$response = $lines[0] | ConvertFrom-Json
if ($response.jsonrpc -ne "2.0" -or $response.id -ne "discover-smoke") {
    throw "stdio smoke 返回了无效 JSON-RPC 信封"
}
if ($response.result.resultType -ne "complete") {
    throw "server/discover 未返回 complete"
}
$versions = @($response.result.supportedVersions)
if ($versions.Count -ne 1 -or $versions[0] -ne "2026-07-28") {
    throw "server/discover 未严格声明 2026-07-28"
}
$capabilities = @($response.result.capabilities.PSObject.Properties.Name | Sort-Object)
if (($capabilities -join ",") -ne "resources,tools") {
    throw "server/discover 广告了 tools/resources 之外的能力"
}
$serverInfoProperty = $response.result._meta.PSObject.Properties[
    "io.modelcontextprotocol/serverInfo"
]
if ($null -eq $serverInfoProperty -or $serverInfoProperty.Value.name -ne "ida-re-mcp") {
    throw "server/discover 返回了错误的产品身份"
}
