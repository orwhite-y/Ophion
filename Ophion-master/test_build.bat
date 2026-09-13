@echo off
:: test_build.bat - 测试编译功能（不需要管理员权限）

setlocal

set "SOLUTION=F:\winDriver\te\Ophion-master\Ophion-master\Ophion.sln"
set "DRVOUT=F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug"
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
set "DRV1=Ophion.sys"
set "DRV2=TestEptHook.sys"

echo ========================================
echo   测试编译功能
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
"%MSBUILD%" "%SOLUTION%" /t:Build /p:Configuration=Debug /p:Platform=x64 /v:m /nologo /m
if %errorlevel% neq 0 (
    echo.
    echo [X] 编译失败
    pause
    exit /b 1
)
echo.

echo [3/3] 检查输出文件...
if not exist "%DRVOUT%\%DRV1%" (
    echo [X] 编译产物未找到: %DRVOUT%\%DRV1%
    pause
    exit /b 1
)
echo [OK] 找到 %DRV1%

if not exist "%DRVOUT%\%DRV2%" (
    echo [X] 编译产物未找到: %DRVOUT%\%DRV2%
    pause
    exit /b 1
)
echo [OK] 找到 %DRV2%

echo.
echo ========================================
echo   编译成功！
echo ========================================
echo   输出目录: %DRVOUT%
echo   %DRV1%
echo   %DRV2%
echo ========================================
echo.
pause
