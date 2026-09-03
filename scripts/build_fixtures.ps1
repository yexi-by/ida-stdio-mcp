param(
    [string]$OutputDirectory = "tests/fixtures/bin",
    [switch]$ExternalOutput
)

$ErrorActionPreference = "Stop"

$repository = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repository "tests/fixtures/src"
$expectedRoot = [System.IO.Path]::GetFullPath((Join-Path $repository "tests/fixtures"))
if ($ExternalOutput) {
    if (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
        throw "外部 fixture 输出目录必须是绝对路径"
    }
    $output = [System.IO.Path]::GetFullPath($OutputDirectory)
    $temporaryRootValue = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
    if (-not $temporaryRootValue) {
        throw "外部 fixture 构建需要 RUNNER_TEMP 或 TEMP"
    }
    $temporaryRoot = [System.IO.Path]::GetFullPath($temporaryRootValue)
    if (
        $output -eq $temporaryRoot -or
        -not $output.StartsWith($temporaryRoot + [System.IO.Path]::DirectorySeparatorChar)
    ) {
        throw "外部 fixture 输出目录必须严格位于临时目录内"
    }
}
else {
    $output = [System.IO.Path]::GetFullPath((Join-Path $repository $OutputDirectory))
    if (-not $output.StartsWith($expectedRoot + [System.IO.Path]::DirectorySeparatorChar)) {
        throw "提交用 fixture 输出目录必须位于 tests/fixtures 内"
    }
}

$llvmBin = if ($env:LLVM_BIN) {
    [System.IO.Path]::GetFullPath($env:LLVM_BIN)
}
else {
    $null
}
if ($llvmBin) {
    if (-not (Test-Path -LiteralPath $llvmBin -PathType Container)) {
        throw "LLVM_BIN 不是可访问目录"
    }
    $env:PATH = "$llvmBin;$env:PATH"
}

function Resolve-FirstApplication([string]$Name) {
    $command = Get-Command $Name -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    return $command.Source
}

$clang = if ($llvmBin) {
    Join-Path $llvmBin "clang.exe"
}
else {
    Resolve-FirstApplication "clang"
}
$clangCpp = if ($llvmBin) {
    Join-Path $llvmBin "clang++.exe"
}
else {
    Resolve-FirstApplication "clang++"
}
$lldLink = if ($llvmBin) {
    Join-Path $llvmBin "lld-link.exe"
}
else {
    Resolve-FirstApplication "lld-link"
}
foreach ($tool in @($clang, $clangCpp, $lldLink)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "LLVM 工具不存在: $tool"
    }
}

$clangOutput = @(& $clang --version)
$clangExitCode = $LASTEXITCODE
if ($clangExitCode -ne 0) {
    throw "无法执行 clang，退出码 $clangExitCode"
}
$lldOutput = @(& $lldLink --version)
$lldExitCode = $LASTEXITCODE
if ($lldExitCode -ne 0) {
    throw "无法执行 lld-link，退出码 $lldExitCode"
}
$clangVersion = $clangOutput | Select-Object -First 1
$lldVersion = $lldOutput | Select-Object -First 1
if ($clangVersion -notmatch "22\.1\.8" -or $lldVersion -notmatch "22\.1\.8") {
    throw "fixture 构建要求 LLVM/LLD 22.1.8"
}

New-Item -ItemType Directory -Force -Path $output | Out-Null

$nativePeObject = Join-Path $output "native_pe_x64.obj"
$nativePeBinary = Join-Path $output "native_pe_x64.dll"
$nativePeImport = Join-Path $output "native_pe_x64.lib"
$nativePeX86Object = Join-Path $output "native_pe_x86.obj"
$nativePeX86Binary = Join-Path $output "native_pe_x86.dll"
$nativePeX86Import = Join-Path $output "native_pe_x86.lib"
$nativeElfX64 = Join-Path $output "native_elf_x64.so"
$nativeElfArm64 = Join-Path $output "native_elf_arm64.so"
$nativeElfX86 = Join-Path $output "native_elf_x86.so"
$nativeElfArmv7 = Join-Path $output "native_elf_armv7.so"
$debugObject = Join-Path $output "debug_target_x64.obj"
$debugBinary = Join-Path $output "debug_target_x64.exe"
$debugImport = Join-Path $output "debug_target_x64.lib"
$debugX86Object = Join-Path $output "debug_target_x86.obj"
$debugX86Binary = Join-Path $output "debug_target_x86.exe"
$debugX86Import = Join-Path $output "debug_target_x86.lib"
$il2cppPeObject = Join-Path $output "il2cpp_pe_x64.obj"
$il2cppPeBinary = Join-Path $output "il2cpp_pe_x64.dll"
$il2cppPeImport = Join-Path $output "il2cpp_pe_x64.lib"
$il2cppPeX86Object = Join-Path $output "il2cpp_pe_x86.obj"
$il2cppPeX86Binary = Join-Path $output "il2cpp_pe_x86.dll"
$il2cppPeX86Import = Join-Path $output "il2cpp_pe_x86.lib"
$il2cppElfBinary = Join-Path $output "il2cpp_elf_x64.so"
$il2cppElfX86Binary = Join-Path $output "il2cpp_elf_x86.so"
$il2cppElfArmv7Binary = Join-Path $output "il2cpp_elf_armv7.so"
$il2cppMetadata = Join-Path $output "il2cpp_metadata_fingerprint.bin"

$commonC = @(
    "-O1",
    "-ffreestanding",
    "-fno-stack-protector",
    "-funwind-tables",
    "-fno-ident",
    "-ffile-prefix-map=$repository=.",
    "-fdebug-prefix-map=$repository=."
)

& $clang @commonC --target=x86_64-pc-windows-msvc -c `
    (Join-Path $source "native_static.c") -o $nativePeObject
if ($LASTEXITCODE -ne 0) { throw "编译 native PE fixture 失败" }
& $lldLink "/dll" "/noentry" "/nodefaultlib" "/brepro" "/dynamicbase" "/nxcompat" `
    "/implib:$nativePeImport" "/out:$nativePeBinary" $nativePeObject
if ($LASTEXITCODE -ne 0) { throw "链接 native PE fixture 失败" }

& $clang @commonC --target=i686-pc-windows-msvc -c `
    (Join-Path $source "native_static.c") -o $nativePeX86Object
if ($LASTEXITCODE -ne 0) { throw "编译 native PE x86 fixture 失败" }
& $lldLink "/dll" "/noentry" "/nodefaultlib" "/machine:x86" "/brepro" "/dynamicbase" `
    "/nxcompat" "/implib:$nativePeX86Import" "/out:$nativePeX86Binary" $nativePeX86Object
if ($LASTEXITCODE -ne 0) { throw "链接 native PE x86 fixture 失败" }

& $clang @commonC --target=x86_64-unknown-linux-gnu -fPIC -fuse-ld=lld -nostdlib -shared `
    "-Wl,--build-id=none" "-Wl,-z,noexecstack" `
    (Join-Path $source "native_static.c") -o $nativeElfX64
if ($LASTEXITCODE -ne 0) { throw "构建 native ELF x64 fixture 失败" }

& $clang @commonC --target=aarch64-unknown-linux-gnu -fPIC -fuse-ld=lld -nostdlib -shared `
    "-Wl,--build-id=none" "-Wl,-z,noexecstack" `
    (Join-Path $source "native_static.c") -o $nativeElfArm64
if ($LASTEXITCODE -ne 0) { throw "构建 native ELF AArch64 fixture 失败" }

& $clang @commonC --target=i386-unknown-linux-gnu -fPIC -fuse-ld=lld -nostdlib -shared `
    "-Wl,--build-id=none" "-Wl,-z,noexecstack" `
    (Join-Path $source "native_static.c") -o $nativeElfX86
if ($LASTEXITCODE -ne 0) { throw "构建 native ELF x86 fixture 失败" }

& $clang @commonC --target=armv7a-linux-gnueabihf -march=armv7-a -mfloat-abi=softfp `
    -fPIC -fuse-ld=lld -nostdlib -shared "-Wl,--build-id=none" "-Wl,-z,noexecstack" `
    (Join-Path $source "native_static.c") -o $nativeElfArmv7
if ($LASTEXITCODE -ne 0) { throw "构建 native ELF ARMv7 fixture 失败" }

& $clang @commonC --target=x86_64-pc-windows-msvc -c `
    (Join-Path $source "debug_target.c") -o $debugObject
if ($LASTEXITCODE -ne 0) { throw "编译 debugger fixture 失败" }
& $lldLink "/entry:mainCRTStartup" "/subsystem:console" "/nodefaultlib" "/brepro" "/dynamicbase" `
    "/nxcompat" "/implib:$debugImport" "/out:$debugBinary" $debugObject "kernel32.lib"
if ($LASTEXITCODE -ne 0) { throw "链接 debugger fixture 失败" }

& $clang @commonC --target=i686-pc-windows-msvc -c `
    (Join-Path $source "debug_target.c") -o $debugX86Object
if ($LASTEXITCODE -ne 0) { throw "编译 debugger x86 fixture 失败" }
& $lldLink "/entry:mainCRTStartup" "/subsystem:console" "/nodefaultlib" "/machine:x86" `
    "/brepro" "/dynamicbase" "/nxcompat" "/implib:$debugX86Import" `
    "/out:$debugX86Binary" $debugX86Object "kernel32.lib"
if ($LASTEXITCODE -ne 0) { throw "链接 debugger x86 fixture 失败" }

& $clangCpp @commonC --target=x86_64-pc-windows-msvc -fno-exceptions -fno-rtti -c `
    (Join-Path $source "il2cpp_shaped.cpp") -o $il2cppPeObject
if ($LASTEXITCODE -ne 0) { throw "编译 IL2CPP PE fixture 失败" }
& $lldLink "/dll" "/noentry" "/nodefaultlib" "/brepro" "/dynamicbase" "/nxcompat" `
    "/implib:$il2cppPeImport" "/out:$il2cppPeBinary" $il2cppPeObject
if ($LASTEXITCODE -ne 0) { throw "链接 IL2CPP PE fixture 失败" }

& $clangCpp @commonC --target=i686-pc-windows-msvc -fno-exceptions -fno-rtti -c `
    (Join-Path $source "il2cpp_shaped.cpp") -o $il2cppPeX86Object
if ($LASTEXITCODE -ne 0) { throw "编译 IL2CPP PE x86 fixture 失败" }
& $lldLink "/dll" "/noentry" "/nodefaultlib" "/machine:x86" "/brepro" "/dynamicbase" `
    "/nxcompat" "/implib:$il2cppPeX86Import" "/out:$il2cppPeX86Binary" $il2cppPeX86Object
if ($LASTEXITCODE -ne 0) { throw "链接 IL2CPP PE x86 fixture 失败" }

& $clangCpp @commonC --target=x86_64-unknown-linux-gnu -fPIC -fuse-ld=lld -nostdlib -shared `
    -fno-exceptions -fno-rtti "-Wl,--build-id=none" "-Wl,-z,noexecstack" `
    (Join-Path $source "il2cpp_shaped.cpp") -o $il2cppElfBinary
if ($LASTEXITCODE -ne 0) { throw "构建 IL2CPP ELF fixture 失败" }

& $clangCpp @commonC --target=i386-unknown-linux-gnu -fPIC -fuse-ld=lld -nostdlib -shared `
    -fno-exceptions -fno-rtti "-Wl,--build-id=none" "-Wl,-z,noexecstack" `
    (Join-Path $source "il2cpp_shaped.cpp") -o $il2cppElfX86Binary
if ($LASTEXITCODE -ne 0) { throw "构建 IL2CPP ELF x86 fixture 失败" }

& $clangCpp @commonC --target=armv7a-linux-gnueabihf -march=armv7-a -mfloat-abi=softfp `
    -mthumb -fPIC -fuse-ld=lld -nostdlib -shared -fno-exceptions -fno-rtti `
    "-Wl,--build-id=none" "-Wl,-z,noexecstack" `
    (Join-Path $source "il2cpp_shaped.cpp") -o $il2cppElfArmv7Binary
if ($LASTEXITCODE -ne 0) { throw "构建 IL2CPP ELF ARMv7 fixture 失败" }

$metadataSource = Join-Path $source "il2cpp_metadata_fingerprint.json"
$metadataBytes = [System.IO.File]::ReadAllBytes($metadataSource)
$metadataDigest = [System.Security.Cryptography.SHA256]::HashData($metadataBytes)
$metadataLength = [System.BitConverter]::GetBytes([uint32]$metadataBytes.Length)
if (-not [System.BitConverter]::IsLittleEndian) {
    [Array]::Reverse($metadataLength)
}
$metadataMagic = [System.Text.Encoding]::ASCII.GetBytes("IDA-RE-IL2CPP-METADATA`0")
$metadataStream = [System.IO.MemoryStream]::new()
try {
    $metadataStream.Write($metadataMagic, 0, $metadataMagic.Length)
    $metadataStream.Write($metadataLength, 0, $metadataLength.Length)
    $metadataStream.Write($metadataDigest, 0, $metadataDigest.Length)
    $metadataStream.Write($metadataBytes, 0, $metadataBytes.Length)
    [System.IO.File]::WriteAllBytes($il2cppMetadata, $metadataStream.ToArray())
}
finally {
    $metadataStream.Dispose()
}

Remove-Item -Force -LiteralPath $nativePeImport
Remove-Item -Force -LiteralPath $nativePeX86Import
Remove-Item -Force -LiteralPath $debugImport
Remove-Item -Force -LiteralPath $debugX86Import
Remove-Item -Force -LiteralPath $il2cppPeImport
Remove-Item -Force -LiteralPath $il2cppPeX86Import

Get-ChildItem -LiteralPath $output -File |
    Where-Object { $_.Extension -ne ".obj" -and $_.Name -ne "SHA256SUMS" } |
    Sort-Object Name |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object {
        "{0}  {1}" -f $_.Hash.ToLowerInvariant(), (Split-Path -Leaf $_.Path)
    } |
    Set-Content -Encoding utf8NoBOM -LiteralPath (Join-Path $output "SHA256SUMS")

Remove-Item -Force -LiteralPath $nativePeObject
Remove-Item -Force -LiteralPath $nativePeX86Object
Remove-Item -Force -LiteralPath $debugObject
Remove-Item -Force -LiteralPath $debugX86Object
Remove-Item -Force -LiteralPath $il2cppPeObject
Remove-Item -Force -LiteralPath $il2cppPeX86Object
