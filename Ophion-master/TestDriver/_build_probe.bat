@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /O2 _probe_dev.cpp /Fe:_probe_dev.exe /link /SUBSYSTEM:CONSOLE
