@echo off
:: EPT Hook Test — load Ophion + TestEptHook
:: Run as Administrator on test-signed enabled system
:: (bcdedit /set testsigning on)

set BINDIR=%~dp0..\build\bin\Debug

echo [*] Copying drivers...
copy /Y "%BINDIR%\Ophion.sys"      "%SystemRoot%\System32\drivers\" >nul
copy /Y "%BINDIR%\TestEptHook.sys" "%SystemRoot%\System32\drivers\" >nul

echo [*] Creating services...
sc create Ophion      type= kernel binPath= "%SystemRoot%\System32\drivers\Ophion.sys"      >nul 2>&1
sc create TestEptHook type= kernel binPath= "%SystemRoot%\System32\drivers\TestEptHook.sys" >nul 2>&1

echo [*] Starting Ophion hypervisor...
sc start Ophion
if errorlevel 1 (
    echo [!] Failed to start Ophion
    pause
    exit /b 1
)
timeout /t 1 >nul

echo [*] Starting TestEptHook (hooking NtCreateFile)...
sc start TestEptHook
if errorlevel 1 (
    echo [!] Failed to start TestEptHook
    pause
    exit /b 1
)

echo.
echo [+] NtCreateFile is now hooked!
echo     Open DbgView or WinDbg to see "[EPT-TEST] NtCreateFile: ..." messages
echo.
echo     To unload:  test_unload.bat
pause
