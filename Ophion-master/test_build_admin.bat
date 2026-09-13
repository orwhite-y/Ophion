@echo off
:: test_build_admin.bat - 自动提权测试编译

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 需要管理员权限，正在提权...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

setlocal

set "SOLUTION=F:\winDriver\te\Ophion-master\Ophion-master\Ophion.sln"
set "DRVOUT=F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug"
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
set "DRV1=Ophion.sys"
set "DRV2=TestEptHook.sys"

title 测试编译功能

echo ========================================
echo   测试编译功能 (已提权)
echo ========================================
echo.

if not exist "%SOLUTION%" (
    echo [X] 解决方案不存在: %SOLUTION%
    pause
    exit /b 1
)

if not exist "%MSBUILD%" (
    echo [X] MSBuild 未找到: %MSBUILD%
    pause
    exit /b 1
)

echo [1/3] 清理旧输出...
"%MSBUILD%" "%SOLUTION%" /t:Clean /p:Configuration=Debug /p:Platform=x64 /v:m /nologo
echo.

echo [2/3] 编译 Debug x64...
"%MSBUILD%" "%SOLUTION%" /t:Build /p:Configuration=Debug /p:Platform=x64 /v:minimal /nologo /m
if %errorlevel% neq 0 (
    echo.
    echo [X] 编译失败 (错误码: %errorlevel%)
    pause
    exit /b 1
)
echo.

echo [3/3] 检查输出文件...
if exist "%DRVOUT%\%DRV1%" (
    echo [OK] 找到 %DRV1%
    dir "%DRVOUT%\%DRV1%" | findstr /i ".sys"
) else (
    echo [X] 编译产物未找到: %DRVOUT%\%DRV1%
    pause
    exit /b 1
)

if exist "%DRVOUT%\%DRV2%" (
    echo [OK] 找到 %DRV2%
    dir "%DRVOUT%\%DRV2%" | findstr /i ".sys"
) else (
    echo [X] 编译产物未找到: %DRVOUT%\%DRV2%
    pause
    exit /b 1
)

echo.
echo ========================================
echo   编译成功！
echo ========================================
echo   输出目录: %DRVOUT%
echo.
dir "%DRVOUT%\*.sys" 2>nul
echo ========================================
echo.
pause
