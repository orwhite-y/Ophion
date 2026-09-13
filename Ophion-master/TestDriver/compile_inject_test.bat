@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d %~dp0
cl.exe /nologo /W3 /Od /Zi /EHsc /MT inject_test.cpp /Fe:inject_test.exe /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo [ERROR] Compile failed
    exit /b 1
)
echo [OK] inject_test.exe compiled
