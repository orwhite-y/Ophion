@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
msbuild Ophion.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64 /m
exit /b %ERRORLEVEL%
