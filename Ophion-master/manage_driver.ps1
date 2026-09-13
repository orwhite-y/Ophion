# manage_driver.ps1 - 一键管理驱动：编译、签名、部署、启动/停止/卸载
# 必须以管理员权限运行
param(
  [switch]$Build,      # 编译项目
  [switch]$Sign,       # 签名（自动回退时间）
  [switch]$Deploy,     # 部署到 System32\drivers
  [switch]$Start,      # 启动服务
  [switch]$Stop,       # 停止服务
  [switch]$Uninstall,  # 卸载服务
  [switch]$All,        # 完整流程：编译+签名+部署+启动
  [switch]$Clean       # 清理：停止+卸载
)

# ======================== 配置区 ========================
$PROJDIR  = 'F:\winDriver\te\Ophion-master\Ophion-master'
$SOLUTION = Join-Path $PROJDIR 'Ophion.sln'
$DRVOUT   = Join-Path $PROJDIR 'build\bin\Debug'
$DRVDEST  = 'C:\Windows\System32\drivers'
$DRVFILES = @('Ophion.sys','TestEptHook.sys')
$CSIGN    = 'F:\soft\DSignTool\CSignTool.exe'
$PY       = 'C:\Python314\python.exe'
$PATCH    = 'F:\work\xg\Cheat Engine\bin\patch_driver.py'
$MSBUILD  = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
$SERVICES = @{
  'RMCore'    = @{ File='Ophion.sys';      Order=1 }
  'RMCoreTst' = @{ File='TestEptHook.sys'; Order=2 }
}
# =======================================================

function Die($m){ Write-Host "  [X]  $m" -ForegroundColor Red; exit 1 }
function OK($m){  Write-Host "  [OK] $m" -ForegroundColor Green }
function Step($n,$msg){ Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Warn($m){ Write-Host "  [!] $m" -ForegroundColor Yellow }

# 检查管理员权限
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $admin){ Die '必须以管理员权限运行' }

# 无参数时显示帮助
if(-not ($Build -or $Sign -or $Deploy -or $Start -or $Stop -or $Uninstall -or $All -or $Clean)){
  Write-Host @"

用法:
  .\manage_driver.ps1 -All           # 完整流程：编译+签名+部署+启动
  .\manage_driver.ps1 -Clean         # 清理：停止+卸载服务
  .\manage_driver.ps1 -Build -Sign   # 仅编译和签名
  .\manage_driver.ps1 -Stop          # 停止服务
  .\manage_driver.ps1 -Start         # 启动服务
  .\manage_driver.ps1 -Uninstall     # 卸载服务（自动停止）

单独开关:
  -Build      编译项目
  -Sign       签名驱动（自动回退时间到2015-01-15）
  -Deploy     部署到System32\drivers并创建服务
  -Start      启动服务
  -Stop       停止服务
  -Uninstall  卸载服务
  -All        = Build + Sign + Deploy + Start
  -Clean      = Stop + Uninstall

"@ -ForegroundColor Gray
  exit 0
}

# -All 展开
if($All){ $Build=$true; $Sign=$true; $Deploy=$true; $Start=$true }
# -Clean 展开
if($Clean){ $Stop=$true; $Uninstall=$true }

# ======================== 功能函数 ========================

function Do-Stop {
  Step 'STOP' '停止服务'
  # 按相反顺序停止（TestDriver先，Ophion后）
  $sorted = $SERVICES.GetEnumerator() | Sort-Object {$_.Value.Order} -Descending
  foreach($kv in $sorted){
    $name = $kv.Key
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if($svc -and $svc.Status -eq 'Running'){
      Write-Host "  停止 $name ..."
      Stop-Service $name -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
      OK "$name 已停止"
    } else {
      Write-Host "  $name 未运行，跳过"
    }
  }
}

function Do-Uninstall {
  Step 'UNINSTALL' '卸载服务'
  # 先停止
  Do-Stop
  Start-Sleep -Seconds 1

  # 按相反顺序删除
  $sorted = $SERVICES.GetEnumerator() | Sort-Object {$_.Value.Order} -Descending
  foreach($kv in $sorted){
    $name = $kv.Key
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if($svc){
      Write-Host "  删除 $name ..."
      sc.exe delete $name | Out-Null
      Start-Sleep -Seconds 1
      OK "$name 已卸载"
    } else {
      Write-Host "  $name 不存在，跳过"
    }
  }
  Start-Sleep -Seconds 2
}

function Do-Build {
  Step 'BUILD' "编译项目 ($SOLUTION)"
  if(-not (Test-Path $SOLUTION)){ Die "解决方案不存在: $SOLUTION" }
  if(-not (Test-Path $MSBUILD)){ Die "MSBuild 未找到: $MSBUILD" }

  Write-Host "  清理旧输出 ..."
  & $MSBUILD $SOLUTION /t:Clean /p:Configuration=Debug /p:Platform=x64 /v:m /nologo

  Write-Host "  开始编译 Debug x64 ..."
  & $MSBUILD $SOLUTION /t:Build /p:Configuration=Debug /p:Platform=x64 /v:m /nologo /m
  if($LASTEXITCODE -ne 0){ Die "编译失败 (exit $LASTEXITCODE)" }

  # 检查输出
  foreach($f in $DRVFILES){
    $p = Join-Path $DRVOUT $f
    if(-not (Test-Path $p)){ Die "编译产物未找到: $p" }
  }
  OK '编译完成'
}

function Do-Sign {
  Step 'SIGN' '签名驱动（回退时间到 2015-01-15）'

  # 1. 先 patch 字符串
  Write-Host "  修补驱动字符串 ..."
  foreach($f in $DRVFILES){
    $p = Join-Path $DRVOUT $f
    if(-not (Test-Path $p)){ Die "$f 不存在: $p" }
    if(Test-Path $PATCH){
      & $PY $PATCH $p
    } else {
      Warn "patch_driver.py 未找到，跳过字符串修补"
    }
  }
  OK '字符串修补完成'

  # 2. 回退时间签名
  $origDate = Get-Date
  try {
    Write-Host "  设置系统时间为 2015-01-15 12:00:00 ..."
    Set-Date -Date ([datetime]'2015-01-15 12:00:00')
    Start-Sleep -Milliseconds 500

    foreach($f in $DRVFILES){
      $p = Join-Path $DRVOUT $f
      Write-Host "  签名 $f ..."
      & $CSIGN sign /r 13 /f $p /ac
      if($LASTEXITCODE -ne 0){ Die "签名 $f 失败 (exit $LASTEXITCODE)" }
      OK "$f 已签名"
    }
  } finally {
    Write-Host "  恢复系统时间为 $origDate ..."
    Set-Date -Date $origDate
  }
}

function Do-Deploy {
  Step 'DEPLOY' '部署驱动 + 创建服务'

  # 先卸载旧服务
  Do-Uninstall

  # 复制文件
  Write-Host "`n  复制驱动到 $DRVDEST ..."
  foreach($f in $DRVFILES){
    $src = Join-Path $DRVOUT $f
    $dst = Join-Path $DRVDEST $f
    if(-not (Test-Path $src)){ Die "$f 源文件不存在: $src" }
    Copy-Item $src $dst -Force
    OK "$f -> $dst"
  }

  # 创建服务
  Write-Host "`n  创建服务 ..."
  $sorted = $SERVICES.GetEnumerator() | Sort-Object {$_.Value.Order}
  foreach($kv in $sorted){
    $name = $kv.Key
    $file = $kv.Value.File
    $binPath = Join-Path $DRVDEST $file

    sc.exe create $name binPath= $binPath type= kernel start= demand | Out-Null
    if($LASTEXITCODE -eq 0){
      OK "服务 $name 已注册 (binPath=$binPath)"
    } else {
      Warn "服务 $name 创建失败 (exit $LASTEXITCODE)"
    }
  }
}

function Do-Start {
  Step 'START' '启动服务'
  $sorted = $SERVICES.GetEnumerator() | Sort-Object {$_.Value.Order}
  foreach($kv in $sorted){
    $name = $kv.Key
    Write-Host "  启动 $name ..."
    Start-Service $name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $svc = Get-Service $name -ErrorAction SilentlyContinue
    if($svc -and $svc.Status -eq 'Running'){
      OK "$name 运行中"
    } else {
      Warn "$name 未能启动（检查日志）"
    }
  }
}

# ======================== 主流程 ========================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  驱动管理脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if($Stop){      Do-Stop }
if($Uninstall){ Do-Uninstall }
if($Build){     Do-Build }
if($Sign){      Do-Sign }
if($Deploy){    Do-Deploy }
if($Start){     Do-Start }

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
