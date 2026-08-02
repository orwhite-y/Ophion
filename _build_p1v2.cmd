@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul 2>&1

echo === BUILD Ophion Debug x64 ===
cd /d F:\te\Ophion-master\Ophion-master
MSBuild.exe Ophion.vcxproj /p:Configuration=Debug /p:Platform=x64 /t:Build /verbosity=minimal
echo OPHION_EXIT=%ERRORLEVEL%

echo === BUILD TestDriver Debug x64 ===
MSBuild.exe TestDriver\TestDriver.vcxproj /p:Configuration=Debug /p:Platform=x64 /t:Build /verbosity:minimal
echo TESTDRIVER_EXIT=%ERRORLEVEL%
