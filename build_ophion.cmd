@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
msbuild Ophion-master.sln /p:Configuration=Debug /p:Platform=x64 /t:Ophion /p:CL_MP=8 /verbosity:minimal
echo EXIT CODE: %ERRORLEVEL%