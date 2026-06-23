@echo off
REM Build the injector with MSVC (run from x64 Native Tools Command Prompt)
cl /EHsc /W4 /O2 injector.cpp /link /out:injector.exe user32.lib
echo.
if exist injector.exe (
    echo Build successful: injector.exe
) else (
    echo Build failed!
)
