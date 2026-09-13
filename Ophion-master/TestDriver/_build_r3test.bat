@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d %~dp0
cl.exe /nologo /W3 /O2 /EHsc /MT test_hook_r3.cpp /Fe:test_hook_r3.exe /link /SUBSYSTEM:CONSOLE user32.lib
if errorlevel 1 (
    echo [ERROR] Compile failed
    exit /b 1
)
echo [OK] test_hook_r3.exe compiled
