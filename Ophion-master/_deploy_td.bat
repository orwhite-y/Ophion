@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
echo STOP RMCoreTst...
sc stop RMCoreTst >nul 2>&1
timeout /t 2 /nobreak >nul
echo COPY TestEptHook.sys...
copy /Y build\bin\Debug\TestEptHook.sys "C:\Windows\System32\drivers\TestEptHook.sys" >nul
echo START RMCoreTst...
sc start RMCoreTst >nul 2>&1
timeout /t 2 /nobreak >nul
sc query RMCoreTst | findstr STATE
echo DONE
