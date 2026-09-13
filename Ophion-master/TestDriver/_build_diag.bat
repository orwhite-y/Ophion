@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d %~dp0
cl.exe /nologo /O2 /EHsc diag_dev.cpp /Fe:diag_dev.exe /link /SUBSYSTEM:CONSOLE > diag_build.log 2>&1
echo EXIT_CODE=%ERRORLEVEL%
type diag_build.log
