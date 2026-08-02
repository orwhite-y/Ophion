@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul 2>&1
cd /d F:\te\Ophion-master\renderdoc-1.36
MSBuild.exe renderdoc\renderdoc.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /verbosity:minimal
echo RD_EXIT=%ERRORLEVEL%
