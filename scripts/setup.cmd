@echo off
setlocal
cd /d "%~dp0.."
py -3 -m venv .venv
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" -m pip install --no-index --find-links dist any2ipa==1.0.0
if errorlevel 1 exit /b 1
".venv\Scripts\any2ipa.exe" doctor
echo Ready. Run .venv\Scripts\any2ipa.exe --help
