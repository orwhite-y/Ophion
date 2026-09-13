@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" TestDriver\TestDriver.vcxproj -t:Build -p:Configuration=Debug -p:Platform=x64 -v:m -nologo
echo EXIT=%ERRORLEVEL%
