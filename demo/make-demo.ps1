# Construit l'archive du projet de démonstration : demo\build\azuget-demo-<version>-windows-x64.zip
# Usage : powershell -ExecutionPolicy Bypass -File demo\make-demo.ps1 -Version 0.1.0
param([Parameter(Mandatory = $true)][string]$Version, [int]$PaddingMB = 0)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'azuget-demo'
$build = Join-Path $PSScriptRoot 'build'
$stage = Join-Path $build ("stage-" + $Version)
New-Item -ItemType Directory -Force $build | Out-Null
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item (Join-Path $src '*') $stage -Recurse
$hello = "Bonjour ! Ceci est azuget-demo version $Version, construit le $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').`r`n" + ('Lest ' * 2000) + "`r`n"
[IO.File]::WriteAllText((Join-Path $stage 'hello.txt'), $hello, (New-Object Text.UTF8Encoding $false))
if ($PaddingMB -gt 0) {
    # lest aléatoire (incompressible) pour tester un vrai transfert
    $bytes = New-Object byte[] ($PaddingMB * 1MB)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    [IO.File]::WriteAllBytes((Join-Path $stage 'lest.bin'), $bytes)
}
$zip = Join-Path $build ("azuget-demo-" + $Version + "-windows-x64.zip")
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
Remove-Item -Recurse -Force $stage
Write-Output $zip
