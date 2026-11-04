$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
py -3 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ with venv is required.' }
& .\.venv\Scripts\python.exe -m pip install --no-index --find-links dist any2ipa==1.0.0
if ($LASTEXITCODE -ne 0) { throw 'Local installation failed.' }
& .\.venv\Scripts\any2ipa.exe doctor
Write-Output 'Ready. Run .\.venv\Scripts\any2ipa.exe --help'
