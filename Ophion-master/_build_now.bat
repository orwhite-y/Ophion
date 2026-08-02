@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d "%~dp0"
echo ===== BUILD Ophion (ept_stealth.cpp) =====
msbuild Ophion.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /m
echo ===== BUILD TestDriver (test_driver.cpp) =====
cd /d "%~dp0TestDriver"
msbuild TestDriver.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /m
exit /b 0
