@echo off
cd /d F:\te\Ophion-master\Ophion-master

:: Try various VS dev environment paths
set "VSCMD="
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
if not defined VSCMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if not defined VSCMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
if not defined VSCMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

if defined VSCMD (
    echo Found VS dev environment: %VSCMD%
    call "%VSCMD%" -arch=x64 -host_arch=x64
) else (
    echo No VS dev environment found. Trying direct msbuild paths.
    :: Direct path for BuildTools
    set "PATH=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64;C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin;%PATH%"
    :: Also try Community
    set "PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64;C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin;%PATH%"
)

echo Looking for msbuild...
where msbuild 2>&1

echo.
echo Building TestDriver Debug x64...
msbuild TestDriver\TestDriver.vcxproj /p:Configuration=Debug /p:Platform=x64 /v:n /t:Build 2>&1
echo EXIT_CODE=%errorlevel%
