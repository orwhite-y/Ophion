@echo off
REM Build the injector with MSVC static CRT (run from x64 Native Tools Command Prompt)
REM /MT = static link CRT (no vcruntime140.dll dependency)
cl /EHsc /W4 /O2 /MT injector.cpp /link /out:injector.exe user32.lib
echo.
if exist injector.exe (
    echo Build successful: injector.exe ^(static linked^)
) else (
    echo Build failed!
)
