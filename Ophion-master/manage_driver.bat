@echo off
:: manage_driver.bat - 一键管理驱动：编译、签名、部署、启动/停止/卸载
:: 必须以管理员权限运行

setlocal enabledelayedexpansion

:: ======================== 配置区 ========================
set "PROJDIR=F:\winDriver\te\Ophion-master\Ophion-master"
set "SOLUTION=%PROJDIR%\Ophion.sln"
set "DRVOUT=%PROJDIR%\build\bin\Debug"
set "DRVDEST=C:\Windows\System32\drivers"
set "CSIGN=F:\soft\DSignTool\CSignTool.exe"
set "PY=C:\Python314\python.exe"
set "PATCH=F:\work\xg\Cheat Engine\bin\patch_driver.py"
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
set "DRV1=Ophion.sys"
set "DRV2=TestEptHook.sys"
set "SVC1=RMCore"
set "SVC2=RMCoreTst"
:: =======================================================

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] 必须以管理员权限运行
    pause
    exit /b 1
)

:: 解析参数
set "ACTION=%~1"
if "%ACTION%"=="" goto :ShowHelp
if /i "%ACTION%"=="all" goto :DoAll
if /i "%ACTION%"=="clean" goto :DoClean
if /i "%ACTION%"=="build" goto :DoBuild
if /i "%ACTION%"=="sign" goto :DoSign
if /i "%ACTION%"=="deploy" goto :DoDeploy
if /i "%ACTION%"=="start" goto :DoStart
if /i "%ACTION%"=="stop" goto :DoStop
if /i "%ACTION%"=="uninstall" goto :DoUninstall
goto :ShowHelp

:ShowHelp
echo.
echo 用法:
echo   manage_driver.bat all        # 完整流程：编译+签名+部署+启动
echo   manage_driver.bat clean      # 清理：停止+卸载服务
echo   manage_driver.bat build      # 仅编译项目
echo   manage_driver.bat sign       # 仅签名驱动
echo   manage_driver.bat deploy     # 部署+创建服务
echo   manage_driver.bat start      # 启动服务
echo   manage_driver.bat stop       # 停止服务
echo   manage_driver.bat uninstall  # 卸载服务
echo.
pause
exit /b 0

:: ======================== 功能函数 ========================

:DoAll
echo.
echo ========================================
echo   完整流程：编译+签名+部署+启动
echo ========================================
call :DoBuild
if %errorlevel% neq 0 exit /b 1
call :DoSign
if %errorlevel% neq 0 exit /b 1
call :DoDeploy
if %errorlevel% neq 0 exit /b 1
call :DoStart
goto :Done

:DoClean
echo.
echo ========================================
echo   清理：停止+卸载服务
echo ========================================
call :DoStop
call :DoUninstall
goto :Done

:DoBuild
echo.
echo [BUILD] 编译项目
if not exist "%SOLUTION%" (
    echo [X] 解决方案不存在: %SOLUTION%
    exit /b 1
)
if not exist "%MSBUILD%" (
    echo [X] MSBuild 未找到: %MSBUILD%
    exit /b 1
)

echo   清理旧输出...
"%MSBUILD%" "%SOLUTION%" /t:Clean /p:Configuration=Debug /p:Platform=x64 /v:m /nologo

echo   开始编译 Debug x64...
"%MSBUILD%" "%SOLUTION%" /t:Build /p:Configuration=Debug /p:Platform=x64 /v:m /nologo /m
if %errorlevel% neq 0 (
    echo [X] 编译失败
    exit /b 1
)

if not exist "%DRVOUT%\%DRV1%" (
    echo [X] 编译产物未找到: %DRVOUT%\%DRV1%
    exit /b 1
)
if not exist "%DRVOUT%\%DRV2%" (
    echo [X] 编译产物未找到: %DRVOUT%\%DRV2%
    exit /b 1
)

echo [OK] 编译完成
exit /b 0

:DoSign
echo.
echo [SIGN] 签名驱动（回退时间到 2015-01-15）

:: 1. 修补字符串
echo   修补驱动字符串...
if exist "%PATCH%" (
    "%PY%" "%PATCH%" "%DRVOUT%\%DRV1%"
    "%PY%" "%PATCH%" "%DRVOUT%\%DRV2%"
    echo [OK] 字符串修补完成
) else (
    echo [!] patch_driver.py 未找到，跳过字符串修补
)

:: 2. 保存当前日期
for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value') do set "ldt=%%a"
set "CURYYYY=!ldt:~0,4!"
set "CURMM=!ldt:~4,2!"
set "CURDD=!ldt:~6,2!"
echo   保存当前日期: !CURYYYY!/!CURMM!/!CURDD!

:: 3. 回退时间签名
echo   设置系统时间为 2015/1/15...
date 2015/1/15 >nul

echo   签名 %DRV1%...
"%CSIGN%" sign /r 13 /f "%DRVOUT%\%DRV1%" /ac
if %errorlevel% neq 0 (
    echo [X] 签名 %DRV1% 失败
    date !CURYYYY!/!CURMM!/!CURDD! >nul
    exit /b 1
)
echo [OK] %DRV1% 已签名

echo   签名 %DRV2%...
"%CSIGN%" sign /r 13 /f "%DRVOUT%\%DRV2%" /ac
if %errorlevel% neq 0 (
    echo [X] 签名 %DRV2% 失败
    date !CURYYYY!/!CURMM!/!CURDD! >nul
    exit /b 1
)
echo [OK] %DRV2% 已签名

:: 4. 恢复时间
echo   恢复系统时间为 !CURYYYY!/!CURMM!/!CURDD!...
date !CURYYYY!/!CURMM!/!CURDD! >nul

exit /b 0

:DoDeploy
echo.
echo [DEPLOY] 部署驱动 + 创建服务

:: 先卸载旧服务
call :DoUninstall

:: 复制文件
echo.
echo   复制驱动到 %DRVDEST%...
if not exist "%DRVOUT%\%DRV1%" (
    echo [X] %DRV1% 源文件不存在: %DRVOUT%\%DRV1%
    exit /b 1
)
if not exist "%DRVOUT%\%DRV2%" (
    echo [X] %DRV2% 源文件不存在: %DRVOUT%\%DRV2%
    exit /b 1
)

copy /Y "%DRVOUT%\%DRV1%" "%DRVDEST%\%DRV1%" >nul
echo [OK] %DRV1% -^> %DRVDEST%

copy /Y "%DRVOUT%\%DRV2%" "%DRVDEST%\%DRV2%" >nul
echo [OK] %DRV2% -^> %DRVDEST%

:: 创建服务
echo.
echo   创建服务...
sc create %SVC1% binPath= "%DRVDEST%\%DRV1%" type= kernel start= demand >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] 服务 %SVC1% 已注册
) else (
    echo [!] 服务 %SVC1% 创建失败
)

sc create %SVC2% binPath= "%DRVDEST%\%DRV2%" type= kernel start= demand >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] 服务 %SVC2% 已注册
) else (
    echo [!] 服务 %SVC2% 创建失败
)

exit /b 0

:DoStart
echo.
echo [START] 启动服务

echo   启动 %SVC1%...
sc start %SVC1% >nul 2>&1
timeout /t 2 /nobreak >nul
sc query %SVC1% | findstr /i "RUNNING" >nul
if %errorlevel% equ 0 (
    echo [OK] %SVC1% 运行中
) else (
    echo [!] %SVC1% 未能启动（检查日志）
)

echo   启动 %SVC2%...
sc start %SVC2% >nul 2>&1
timeout /t 2 /nobreak >nul
sc query %SVC2% | findstr /i "RUNNING" >nul
if %errorlevel% equ 0 (
    echo [OK] %SVC2% 运行中
) else (
    echo [!] %SVC2% 未能启动（检查日志）
)

exit /b 0

:DoStop
echo.
echo [STOP] 停止服务

:: 按反序停止（TestDriver先，Ophion后）
echo   停止 %SVC2%...
sc query %SVC2% 2>nul | findstr /i "RUNNING" >nul
if %errorlevel% equ 0 (
    sc stop %SVC2% >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo [OK] %SVC2% 已停止
) else (
    echo   %SVC2% 未运行，跳过
)

echo   停止 %SVC1%...
sc query %SVC1% 2>nul | findstr /i "RUNNING" >nul
if %errorlevel% equ 0 (
    sc stop %SVC1% >nul 2>&1
    timeout /t 3 /nobreak >nul
    echo [OK] %SVC1% 已停止
) else (
    echo   %SVC1% 未运行，跳过
)

exit /b 0

:DoUninstall
echo.
echo [UNINSTALL] 卸载服务

:: 先停止
call :DoStop
timeout /t 1 /nobreak >nul

:: 按反序删除
echo.
echo   删除 %SVC2%...
sc query %SVC2% >nul 2>&1
if %errorlevel% equ 0 (
    sc delete %SVC2% >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo [OK] %SVC2% 已卸载
) else (
    echo   %SVC2% 不存在，跳过
)

echo   删除 %SVC1%...
sc query %SVC1% >nul 2>&1
if %errorlevel% equ 0 (
    sc delete %SVC1% >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo [OK] %SVC1% 已卸载
) else (
    echo   %SVC1% 不存在，跳过
)

timeout /t 2 /nobreak >nul
exit /b 0

:Done
echo.
echo ========================================
echo   完成！
echo ========================================
echo.
pause
exit /b 0
