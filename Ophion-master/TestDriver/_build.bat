@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl.exe /nologo /W3 /O2 /EHsc /MT %1.cpp /Fe:%1.exe /link /SUBSYSTEM:CONSOLE user32.lib > build_%1.log 2>&1
echo COMPILE_EXIT=%errorlevel%
type build_%1.log
