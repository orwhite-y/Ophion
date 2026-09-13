# deploy_drivers.ps1 - sign (backdated) + deploy Ophion/TestDriver + create services
# MUST run as Administrator
param([switch]$Start)   # -Start to also start services after deploy

$CSIGN    = 'F:\soft\DSignTool\CSignTool.exe'
$DRVDEST  = 'C:\Windows\System32\drivers'
$DRVOUT   = 'F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug'
$DRVFILES = @('Ophion.sys','TestEptHook.sys')
$PY       = 'C:\Python314\python.exe'
$PATCH    = 'F:\work\xg\Cheat Engine\bin\patch_driver.py'

function Die($m){ Write-Host ("  [X]  " + $m) -ForegroundColor Red; exit 1 }
function OK($m){   Write-Host ("  [OK] " + $m) -ForegroundColor Green }
function Step($n,$msg){ Write-Host ("`n[" + $n + "] " + $msg) -ForegroundColor Cyan }

# --- admin check ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $admin){ Die 'Must run as Administrator' }

# --- 0. uninstall existing services (TestDriver first, then Ophion) ---
Step 0 'uninstall existing services (RMCoreTst -> delay -> RMCore -> 3s)'

# 0a. stop + delete RMCoreTst (TestDriver) first
$svcTst = Get-Service -Name 'RMCoreTst' -ErrorAction SilentlyContinue
if($svcTst -and $svcTst.Status -eq 'Running'){
  Write-Host "  stopping RMCoreTst ..."
  Stop-Service 'RMCoreTst' -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}
$svcTst = Get-Service -Name 'RMCoreTst' -ErrorAction SilentlyContinue
if($svcTst){
  Write-Host "  deleting RMCoreTst ..."
  sc.exe delete 'RMCoreTst' | Out-Null
  Start-Sleep -Seconds 2
  OK "RMCoreTst uninstalled"
} else {
  Write-Host "  RMCoreTst not found, skip"
}

# 0b. stop + delete RMCore (Ophion) second, with 3s delay after
$svcCore = Get-Service -Name 'RMCore' -ErrorAction SilentlyContinue
if($svcCore -and $svcCore.Status -eq 'Running'){
  Write-Host "  stopping RMCore ..."
  Stop-Service 'RMCore' -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 5  # extra delay: DriverUnload has 2s internal wait for notify race
}
$svcCore = Get-Service -Name 'RMCore' -ErrorAction SilentlyContinue
if($svcCore){
  Write-Host "  deleting RMCore ..."
  sc.exe delete 'RMCore' | Out-Null
  Start-Sleep -Seconds 3
  OK "RMCore uninstalled"
} else {
  Write-Host "  RMCore not found, skip"
}

# --- 1. re-patch strings (in case build overwrote) ---
Step 1 'patch driver strings (Ophion -> RMCore)'
foreach($f in $DRVFILES){
  $p = Join-Path $DRVOUT $f
  if(Test-Path $p){ & $PY $PATCH $p }
}
OK 'strings patched'

# --- 2. sign with backdated clock ---
Step 2 'sign drivers (backdated to 2015-01-15)'
$origDate = Get-Date
try {
  Write-Host "  setting clock to 2015-01-15 ..."
  Set-Date -Date ([datetime]'2015-01-15 12:00:00')
  foreach($f in $DRVFILES){
    $p = Join-Path $DRVOUT $f
    if(-not (Test-Path $p)){ Die "$f not found at $p" }
    Write-Host "  signing $f ..."
    & $CSIGN sign /r 13 /f $p /ac
    if($LASTEXITCODE -ne 0){ Die "signing $f failed (exit $LASTEXITCODE)" }
    OK "$f signed"
  }
} finally {
  Write-Host "  restoring clock to $origDate ..."
  Set-Date -Date $origDate
}

# --- 3. deploy ---
Step 3 'deploy to System32\drivers'
foreach($f in $DRVFILES){
  $src = Join-Path $DRVOUT $f
  $dst = Join-Path $DRVDEST $f
  Copy-Item $src $dst -Force
  OK "$f -> $dst"
}

# --- 4. (re)create services ---
Step 4 'register services'
$svc = @{
  'RMCore'    = (Join-Path $DRVDEST 'Ophion.sys')
  'RMCoreTst' = (Join-Path $DRVDEST 'TestEptHook.sys')
}
foreach($name in $svc.Keys){
  $svcBin = $svc[$name]
  # services already deleted in Step 0, just create fresh
  $existing = Get-Service -Name $name -ErrorAction SilentlyContinue
  if($existing){
    sc.exe delete $name | Out-Null
    Start-Sleep -Milliseconds 500
  }
  sc.exe create $name binPath= $svcBin type= kernel start= demand | Out-Null
  OK "service $name registered (binPath=$svcBin)"
}

# --- 5. start services (optional) ---
if($Start){
  Step 5 'start services'
  Write-Host "  starting RMCore (Ophion hypervisor) ..."
  Start-Service RMCore -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 3
  $rc = Get-Service RMCore -ErrorAction SilentlyContinue
  if($rc -and $rc.Status -eq 'Running'){ OK "RMCore running" }
  else { Write-Host "  [!] RMCore not running (check O.log)" -ForegroundColor Yellow }

  Write-Host "  starting RMCoreTst (TestDriver) ..."
  Start-Service RMCoreTst -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
  $rt = Get-Service RMCoreTst -ErrorAction SilentlyContinue
  if($rt -and $rt.Status -eq 'Running'){ OK "RMCoreTst running" }
  else { Write-Host "  [!] RMCoreTst not running (check T.log)" -ForegroundColor Yellow }
} else {
  Write-Host "`n  (use -Start to also start services)" -ForegroundColor DarkGray
}

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "new drivers deployed."