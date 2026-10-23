# AzuGet - installe l'outil en ligne de commande sur le PC de publication (Windows).
# Crée un environnement Python dans C:\Users\<toi>\Tools\azuget\.venv, y installe cryptography,
# et pose les raccourcis azuget.cmd / azuget dans Tools\bin (déjà dans le PATH).
# Relançable sans risque. Usage : powershell -ExecutionPolicy Bypass -File deploy\windows\install-cli.ps1 [-FeedDir F:\AzuGet]
param(
    [string]$FeedDir = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$Tools = (Join-Path $env:USERPROFILE 'Tools')
)
$ErrorActionPreference = 'Stop'
$venv = Join-Path $Tools 'azuget\.venv'
$py = Join-Path $venv 'Scripts\python.exe'
$bin = Join-Path $Tools 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null

if (-not (Test-Path $py)) {
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) {
        & $uv.Source venv --python 3.12 $venv
    } else {
        & py -3 -m venv $venv
    }
}
$uv = Get-Command uv -ErrorAction SilentlyContinue
if ($uv) { & $uv.Source pip install --python $py cryptography } else { & $py -m pip install --upgrade cryptography }

$script = Join-Path $FeedDir 'tools\azuget.py'
if (-not (Test-Path $script)) { throw "tools\azuget.py introuvable sous $FeedDir" }
$cmd = "@echo off`r`n`"$py`" `"$script`" %*`r`n"
[IO.File]::WriteAllText((Join-Path $bin 'azuget.cmd'), $cmd, [Text.Encoding]::ASCII)
$pyBash = '/' + ($py -replace ':', '' -replace '\\', '/'); $pyBash = $pyBash.Substring(0,1) + $pyBash.Substring(1,1).ToLower() + $pyBash.Substring(2)
$scriptFwd = $script -replace '\\', '/'
$sh = "#!/bin/sh`nexec `"$pyBash`" `"$scriptFwd`" `"`$@`"`n"
[IO.File]::WriteAllText((Join-Path $bin 'azuget'), $sh, (New-Object Text.UTF8Encoding $false))

& $py $script --version
Write-Output "installé. Étapes suivantes : azuget keygen (une seule fois), puis config dans $env:USERPROFILE\.azuget\config.json (voir README)."
