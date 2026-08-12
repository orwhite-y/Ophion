# Pre-test kernel module snapshot - run BEFORE injection test
# Saves to C:\Windows\MOD_SNAPSHOT.txt so it survives reboot
$code = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class KdrvSnap {
    [DllImport("psapi.dll")]
    public static extern bool EnumDeviceDrivers(IntPtr[] lpImageBase, int cb, out int lpcbNeeded);
    [DllImport("psapi.dll")]
    public static extern int GetDeviceDriverBaseName(IntPtr ImageBase, StringBuilder lpBaseName, int nSize);
    [DllImport("psapi.dll")]
    public static extern int GetDeviceDriverFileName(IntPtr ImageBase, StringBuilder lpFileName, int nSize);
}
"@
Add-Type -TypeDefinition $code -Language CSharp -ErrorAction SilentlyContinue

$needed = 0
[KdrvSnap]::EnumDeviceDrivers($null, 0, [ref]$needed) | Out-Null
$count = [int]($needed / [IntPtr]::Size)
$bases = New-Object IntPtr[] $count
[KdrvSnap]::EnumDeviceDrivers($bases, $needed, [ref]$needed) | Out-Null

$sb = New-Object System.Text.StringBuilder
$sb.AppendLine("# Kernel Module Snapshot - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')") | Out-Null
$sb.AppendLine("# Format: base end size name path") | Out-Null
$sb.AppendLine("") | Out-Null

foreach ($base in $bases) {
    $nameb = New-Object System.Text.StringBuilder 512
    $pathb = New-Object System.Text.StringBuilder 1024
    [KdrvSnap]::GetDeviceDriverBaseName($base, $nameb, 512) | Out-Null
    [KdrvSnap]::GetDeviceDriverFileName($base, $pathb, 1024) | Out-Null
    $name = $nameb.ToString()
    $path = $pathb.ToString()
    $baseVal = $base.ToInt64()
    
    # Get SizeOfImage from PE file on disk
    $pePath = $path -replace '\\SystemRoot\\', 'C:\Windows\' -replace '\\System32\\', 'C:\Windows\System32\' -replace '\\??\\', ''
    $sizeOfImage = 0
    if (Test-Path $pePath -PathType Leaf) {
        try {
            $fb = [System.IO.File]::ReadAllBytes($pePath)
            $peOff = [BitConverter]::ToInt32($fb, 0x3C)
            $sizeOfImage = [BitConverter]::ToUInt32($fb, $peOff + 0x18 + 0x38)
        } catch {}
    }
    
    $endAddr = $baseVal + $sizeOfImage
    $sb.AppendLine("0x{0:X16} 0x{1:X16} 0x{2:X8} {3} {4}" -f $baseVal, $endAddr, $sizeOfImage, $name, $path) | Out-Null
}

$out = $sb.ToString()
[System.IO.File]::WriteAllText("C:\Windows\MOD_SNAPSHOT.txt", $out)
Write-Host "Snapshot saved to C:\Windows\MOD_SNAPSHOT.txt"
Write-Host "$count modules recorded"

# Also print key modules for quick reference
$lines = $out -split "`n" | Where-Object { $_ -match 'ntoskrnl|Ophion|TestEptHook|win32k|dxg|nvlddmkm|hal\.|FLTMGR|Ntfs|CI\.|tcpip' }
Write-Host ""
Write-Host "=== Key Modules ==="
$lines | ForEach-Object { Write-Host $_ }