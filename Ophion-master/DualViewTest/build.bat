@echo off
echo Building test DLL...
cl /LD /Fe:test_dll.dll test_dll.cpp user32.lib /link /DLL
echo.
echo Building test program...
cl /Fe:test_dualview.exe test_dualview.cpp user32.lib
echo.
echo Done. Files:
echo   test_dll.dll       - DLL with ShowMessage() export
echo   test_dualview.exe  - test program
echo.
echo Usage:
echo   test_dualview.exe
echo   test_dualview.exe "\SystemRoot\System32\dbghelp.dll"
