@echo off
setlocal

:: Verifica se ja esta rodando como admin
net session >nul 2>&1
if %errorLevel% == 0 goto :run

:: Relanca como administrador (abre UAC)
powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs -Wait"
exit /b

:run
cd /d "%~dp0"
echo.
echo ============================================================
echo   SecurityAudit.ps1 - Executando como Administrador
echo ============================================================
echo.

:: Prefere pwsh (PowerShell 7+) se disponivel, senao usa o powershell (5.1)
where pwsh >nul 2>&1
if %errorLevel% == 0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecurityAudit.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecurityAudit.ps1"
)

echo.
echo Relatorio salvo em: %~dp0reports\
pause
