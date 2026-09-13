import subprocess
import sys

# Compile inject_test.cpp
cmd = [
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.42.34433\bin\Hostx64\x64\cl.exe",
    "/nologo", "/W3", "/O2", "/EHsc", "/MT",
    "inject_test.cpp",
    "/Fe:inject_test.exe",
    "/link", "/SUBSYSTEM:CONSOLE",
    "/LIBPATH:C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0\\um\\x64",
    "/LIBPATH:C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\MSVC\\14.42.34433\\lib\\x64"
]

result = subprocess.run(cmd, capture_output=True, text=True, cwd=r"F:\winDriver\te\Ophion-master\Ophion-master\TestDriver")
print(result.stdout)
print(result.stderr)
sys.exit(result.returncode)
