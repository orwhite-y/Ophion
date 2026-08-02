@echo off
cd /d F:\te\Ophion-master\Ophion-master
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
MSBuild.exe TestDriver\TestDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Clean,Build
