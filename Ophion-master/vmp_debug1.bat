set "projectpath=%cd%"
@REM cd ../../
set "preProjectpath=%cd%"
cd /d %projectpath%
set "SignFullPath=%preProjectpath%/build/bin/Debug/Ophion.sys"
set "SignFullPath1=%preProjectpath%/x64/Debug/testHookDriver.sys"
@REM set "VMPath=%preProjectpath%/x64/Release/YJ.sys.vmp"

set "d=%date:~0,10%"
set "path=%path%;D:/VMProtect Ultimate/;E:/tools/DSignTool/"

@rem VMProtect_Con.exe %VMPath%

date 2015/1/15
CSignTool.exe  sign /r 13 /f %SignFullPath% /ac
date %d%



date 2015/1/15
CSignTool.exe  sign /r 13 /f %SignFullPath1% /ac
date %d%