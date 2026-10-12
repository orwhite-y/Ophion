@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /W4 /O2 ept_probe_all.c /Fe:ept_probe_all.exe
echo EPT_PROBE_EXIT=%ERRORLEVEL%
