@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /W3 /O2 /EHsc /MT test_hook_r3.cpp /Fe:test_hook_r3.exe /link /SUBSYSTEM:CONSOLE user32.lib
echo EXIT_CODE=%ERRORLEVEL%
