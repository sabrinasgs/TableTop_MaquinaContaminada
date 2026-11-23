@echo off
REM TableTop SITALKS
cd /d "%~dp0"
fltmc >nul 2>&1
if %errorlevel% neq 0 (
  echo Pedindo permissao de administrador...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Recurse -File | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Simulacao.ps1"
pause
