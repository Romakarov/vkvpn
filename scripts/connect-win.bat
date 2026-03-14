@echo off
REM VKVPN Client — Windows launcher
REM Usage: double-click or run from cmd

setlocal enabledelayedexpansion

set CONFIG=%USERPROFILE%\.vkvpn.conf

if exist "%CONFIG%" (
    for /f "tokens=1,2 delims==" %%a in (%CONFIG%) do set %%a=%%b
)

if "%PEER%"=="" (
    echo === VKVPN Setup ===
    set /p PEER="VPS address (host:port, e.g. 144.124.247.27:56000): "
    set /p LINK="VK link OR Yandex link: "
    set /p CONNS="Connections (16 for VK, 1 for Yandex, default 16): "
    if "!CONNS!"=="" set CONNS=16

    echo !LINK! | findstr /i "vk join" >nul
    if !errorlevel!==0 (
        set PROVIDER=vk
        set LINK_FLAG=-vk-link
    ) else (
        set PROVIDER=yandex
        set LINK_FLAG=-yandex-link
    )

    (
        echo PEER=!PEER!
        echo LINK=!LINK!
        echo LINK_FLAG=!LINK_FLAG!
        echo PROVIDER=!PROVIDER!
        echo CONNS=!CONNS!
    ) > "%CONFIG%"
    echo Config saved to %CONFIG%
    echo.
)

echo === VKVPN ===
echo Provider: %PROVIDER%
echo Peer:     %PEER%
echo Listen:   127.0.0.1:9000
echo.
echo Configure WireGuard:
echo   Endpoint = 127.0.0.1:9000
echo   MTU = 1280
echo.
echo Starting tunnel... (Ctrl+C to stop)
echo.

set SCRIPT_DIR=%~dp0
set CLIENT=%SCRIPT_DIR%..\client-bin.exe

if not exist "%CLIENT%" (
    echo ERROR: Client binary not found at %CLIENT%
    echo Build it: go build -ldflags "-s -w" -trimpath -o client-bin.exe ./client/
    pause
    exit /b 1
)

"%CLIENT%" %LINK_FLAG% "%LINK%" -peer "%PEER%" -n %CONNS% -listen 127.0.0.1:9000
pause
