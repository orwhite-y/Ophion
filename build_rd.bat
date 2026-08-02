@echo off
set "VSCMD="
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
if not defined VSCMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if not defined VSCMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
if not defined VSCMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

if defined VSCMD (
    echo Found VS dev environment: %VSCMD%
    call "%VSCMD%" -arch=x64 -host_arch=x64
) else (
    echo No VS dev environment found.
)

echo Building renderdoc Release x64...
msbuild "F:\te\Ophion-master\renderdoc-1.36\renderdoc\renderdoc.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:n /m /t:Build 2>&1
echo EXIT_CODE=%errorlevel%
