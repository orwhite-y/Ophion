@echo off
:: sign_deploy_drv.bat - Sign and deploy patched drivers
:: Run as Administrator!

set "SRCDIR=F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug"
set "DSTDIR=C:\Windows\System32\drivers"
set "CSIGN=F:\soft\DSignTool\CSignTool.exe"

echo ============================================
echo  Sign + Deploy Drivers (RMCore/RMCoreTst)
echo ============================================

:: Save current date
for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value') do set "ldt=%%a"
set "CURYYYY=%ldt:~0,4%"
set "CURMM=%ldt:~4,2%"
set "CURDD=%ldt:~6,2%"

echo Saving current date: %CURYYYY%/%CURMM%/%CURDD%

:: Set date to 2015/1/15 for cert validity
echo Setting date to 2015/1/15 for signing...
date 2015/1/15

:: Sign TestEptHook.sys
echo.
echo Signing TestEptHook.sys...
"%CSIGN%" sign /r 13 /f "%SRCDIR%\TestEptHook.sys" /ac

:: Sign Ophion.sys
echo.
echo Signing Ophion.sys...
"%CSIGN%" sign /r 13 /f "%SRCDIR%\Ophion.sys" /ac

:: Restore date
echo.
echo Restoring date to %CURYYYY%/%CURMM%/%CURDD%
date %CURYYYY%/%CURMM%/%CURDD%

:: Deploy
echo.
echo Deploying to %DSTDIR%...
copy /Y "%SRCDIR%\TestEptHook.sys" "%DSTDIR%\TestEptHook.sys"
copy /Y "%SRCDIR%\Ophion.sys" "%DSTDIR%\Ophion.sys"

:: Restart services
echo.
echo Stopping services...
sc stop RMCore 2>nul
sc stop RMCoreTst 2>nul
timeout /t 2 /nobreak >nul

echo Starting services...
sc start RMCore
sc start RMCoreTst

echo.
echo ============================================
echo  Done! Check sc query RMCore and RMCoreTst
echo ============================================
pause