@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
pushd "%~dp0"
cl /nologo /std:c++17 /EHsc /W4 /O2 remote_call_cli.cpp /Fe:remote_call_cli.exe
set "build_result=%ERRORLEVEL%"
popd
exit /b %build_result%
