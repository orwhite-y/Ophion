@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
pushd "%~dp0"
cl /nologo /W4 vbox_probe.c /Fe:vbox_probe.exe
set "build_result=%ERRORLEVEL%"
popd
exit /b %build_result%
