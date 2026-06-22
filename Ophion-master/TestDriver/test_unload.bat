@echo off
:: EPT Hook Test — unload TestEptHook + Ophion
:: Run as Administrator

echo [*] Stopping TestEptHook (unhooking NtCreateFile)...
sc stop TestEptHook >nul 2>&1

timeout /t 1 >nul

echo [*] Stopping Ophion hypervisor...
sc stop Ophion >nul 2>&1

echo [*] Deleting services...
sc delete TestEptHook >nul 2>&1
sc delete Ophion      >nul 2>&1

echo [+] Done.
pause
