@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b %errorlevel%
cl /nologo /std:c++17 /EHsc /W4 /O2 trace_cli.cpp /Fe:trace_cli.exe
exit /b %errorlevel%
