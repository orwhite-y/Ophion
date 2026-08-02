@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul 2>&1
cd /d F:\te\Ophion-master\renderdoc-1.36
MSBuild.exe renderdoc\renderdoc.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /verbosity:minimal > F:\te\Ophion-master\_rd_build.log 2>&1
echo RD_EXIT=%ERRORLEVEL% >> F:\te\Ophion-master\_rd_build.log
python -c "import struct;d=open(r'F:/te/Ophion-master/renderdoc-1.36/x64/Release/renderdoc.dll','rb').read();pe=struct.unpack_from('<I',d,0x3C)[0];dd=pe+24+112;tls_rva=struct.unpack_from('<I',d,dd+9*8)[0];tls_sz=struct.unpack_from('<I',d,dd+9*8+4)[0];print(f'TLS rva=0x{tls_rva:X} size=0x{tls_sz:X}'+(' GONE!' if tls_rva==0 and tls_sz==0 else ' still present'))" >> F:\te\Ophion-master\_rd_build.log 2>&1
