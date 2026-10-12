# SPDX-License-Identifier: MIT
# Builds Warmor's eBPF-for-Windows programs into native images (.sys).
#
#   1. clang compiles each program to BPF bytecode (.o).
#   2. eBPF-for-Windows' Convert-BpfToNative.ps1 verifies it with PREVAIL and
#      generates a kernel driver (bpf2c), which must then be signed.
#
# Run from a Visual Studio Developer PowerShell with the WDK installed:
#
#   .\build.ps1 -EbpfIncludeDir C:\ebpf\build\native\include `
#               -NtosIncludeDir C:\ntosebpfext\include `
#               -ConvertScript  C:\ebpf\build\native\bin\Convert-BpfToNative.ps1
#
# Output: warmor_net.sys and warmor_proc.sys in -OutDir. Install them in a
# "bpf" directory next to warmor-daemon.exe.
#
# Signing: test-signed images load only with `bcdedit /set testsigning on`.
# Production machines (HVCI on) need images signed through Microsoft's
# attestation signing; see docs/PLATFORM_WINDOWS.md.

param(
    [Parameter(Mandatory = $true)] [string] $EbpfIncludeDir,
    [string] $NtosIncludeDir = "",
    [Parameter(Mandatory = $true)] [string] $ConvertScript,
    [string] $Clang = "clang",
    [string] $OutDir = (Join-Path $PSScriptRoot "out")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$programs = @(
    @{ Name = "warmor_net";  Includes = @($EbpfIncludeDir) },
    # The process hook header (ebpf_ntos_hooks.h) ships with ntosebpfext.
    @{ Name = "warmor_proc"; Includes = @($EbpfIncludeDir, $NtosIncludeDir) }
)

foreach ($p in $programs) {
    if ($p.Name -eq "warmor_proc" -and -not $NtosIncludeDir) {
        Write-Warning "Skipping warmor_proc: -NtosIncludeDir not given (process enforcement will use ETW)"
        continue
    }

    $src = Join-Path $PSScriptRoot "$($p.Name).c"
    $obj = Join-Path $OutDir "$($p.Name).o"
    $incArgs = @("-I", $PSScriptRoot)
    foreach ($inc in $p.Includes) { $incArgs += @("-I", $inc) }

    Write-Host "clang: $src -> $obj"
    & $Clang -target bpf -O2 -g -Werror @incArgs -c $src -o $obj
    if ($LASTEXITCODE -ne 0) { throw "clang failed for $($p.Name)" }

    Write-Host "bpf2c: $obj -> $($p.Name).sys"
    Push-Location $OutDir
    try {
        & $ConvertScript -FileName $p.Name
        if ($LASTEXITCODE -ne 0) { throw "Convert-BpfToNative failed for $($p.Name)" }
    } finally {
        Pop-Location
    }
}

Write-Host "Done. Sign the .sys files, then copy them to <install dir>\bpf\."
