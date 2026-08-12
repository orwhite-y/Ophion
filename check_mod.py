import ctypes
from ctypes import wintypes

k = ctypes.windll.kernel32
p = ctypes.windll.psapi
h = k.GetCurrentProcess()

mods = (ctypes.c_void_p * 1024)()
cb = wintypes.DWORD()
p.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(cb))
cnt = cb.value // ctypes.sizeof(ctypes.c_void_p)

for i in range(cnt):
    mn = ctypes.create_unicode_buffer(260)
    p.GetModuleBaseNameW(h, mods[i], mn, 260)
    name = mn.value.lower()
    if name in ('ntdll.dll', 'kernelbase.dll', 'kernel32.dll', 'win32u.dll'):
        base = mods[i]
        addr = base + 0x1ad0
        try:
            buf = (ctypes.c_ubyte * 32)()
            ctypes.memmove(buf, addr, 32)
            hexstr = " ".join("{:02x}".format(b) for b in buf)
            print("{} base=0x{:x} +0x1ad0=0x{:x} bytes={}".format(name, base, addr, hexstr))
        except:
            print("{} base=0x{:x} +0x1ad0=READ_FAIL".format(name, base))
