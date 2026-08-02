@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
echo ===== BUILD TestDriver =====
cd /d "F:\winDriver\te\Ophion-master\Ophion-master\TestDriver"
msbuild TestDriver.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /m /v:minimal 2>&1
if errorlevel 1 (echo TESTDRIVER_BUILD_FAILED & exit /b 1)
echo ===== BUILD Ophion =====
cd /d "F:\winDriver\te\Ophion-master\Ophion-master"
msbuild Ophion.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /m /v:minimal 2>&1
if errorlevel 1 (echo OPHION_BUILD_FAILED & exit /b 1)
echo ===== BUILD COMPLETE =====
