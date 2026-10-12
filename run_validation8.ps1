Get-Process qrenderdoc,cdb -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -LiteralPath 'F:\winDriver\te\Ophion-master\qrenderdoc_validation8.txt' -ErrorAction SilentlyContinue
$env:OPHION_FORCE_D3D12_API_VALIDATION='1'
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe' -lines -y 'srv*f:\symbols*https://msdl.microsoft.com/download/symbols;F:\winDriver\te\Ophion-master\renderdoc-1.36\x64\Release' -i 'F:\winDriver\te\Ophion-master\renderdoc-1.36\x64\Release' -c 'sxe AV; g; k 80; r; .dump /ma /o F:\winDriver\te\Ophion-master\qrenderdoc_next.dmp; qd' 'F:\winDriver\te\Ophion-master\renderdoc-1.36\x64\Release\qrenderdoc.exe' 'C:\ProgramData\WinComp\captures\frame_capture_2.rdc' *> 'F:\winDriver\te\Ophion-master\qrenderdoc_validation8.txt'
$code = $LASTEXITCODE
Get-Process qrenderdoc -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Output "cdb exit=$code"
Select-String -Path 'F:\winDriver\te\Ophion-master\qrenderdoc_validation8.txt' -Pattern 'minimal capture-only|D3D12DebugManager|CopyBuffer replay|CopyResource replay|D3D12 CORRUPTION|Device Removed|Removing Device|GPU device lost|Fatal error|Failed to open|Access violation|CORRUPTED_PARAMETER|Close failed|refusing to submit|RenderCheckerboard|UploadConstants'
