@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /W4 /O2 ept_target.c /Fe:ept_target.exe
echo EPT_TARGET_EXIT=%ERRORLEVEL%
