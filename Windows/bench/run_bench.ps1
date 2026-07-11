param(
    [ValidateSet('direct','iocp','compare')]
    [string]$Mode = 'compare',
    [long]$Bytes = 67108864,
    [int]$Conns = 16,
    [int]$Latency = 200
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $PSScriptRoot 'bench_relay.c'))) {
    $PSScriptRoot = Join-Path $Root 'bench'
}
Set-Location $PSScriptRoot

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "Visual Studio C++ tools not found" }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"

$src = @(
    "bench_relay.c",
    "..\src\netbridge\nb_iocp_relay.c"
) -join ' '

$cmd = "`"$vcvars`" x64 >nul && cl.exe /nologo /O2 /std:c11 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /I`"..\src`" $src /Fe:bench_relay.exe /link ws2_32.lib"
Write-Host "Building bench_relay.exe..." -ForegroundColor Cyan
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "bench build failed" }

Write-Host "Running benchmark..." -ForegroundColor Cyan
& .\bench_relay.exe $Mode --bytes $Bytes --conns $Conns --latency $Latency
