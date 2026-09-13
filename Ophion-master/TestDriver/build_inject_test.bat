@echo off
setlocal enabledelayedexpansion

REM Quick compile for inject_test.exe
cd /d "%~dp0"

REM Setup environment
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [ERROR] vcvars64.bat not found
    exit /b 1
)

call "%VCVARS%" >nul 2>&1

REM Compile
cl.exe /nologo /W3 /O2 /EHsc /MT inject_test.cpp /Fe:inject_test.exe /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)

echo [OK] inject_test.exe compiled successfully
dir inject_test.exe
