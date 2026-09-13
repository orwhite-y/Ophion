@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\winDriver\te\Ophion-master\Ophion-master\TestDriver
"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" TestDriver.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /m /nologo /v:minimal > _build_dbg.log 2>&1
echo BUILD_EXIT=%ERRORLEVEL%
