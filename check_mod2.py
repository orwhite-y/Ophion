import ctypes
from ctypes import wintypes

k = ctypes.windll.kernel32
p = ctypes.windll.psapi
h = k.GetCurrentProcess()

mods = (ctypes.c_void_p * 2048)()
cb = wintypes.DWORD()
p.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(cb))
cnt = cb.value // ctypes.sizeof(ctypes.c_void_p)

for i in range(min(cnt, 50)):
    mn = ctypes.create_unicode_buffer(260)
    p.GetModuleBaseNameW(h, mods[i], mn, 260)
    name = mn.value
    base = mods[i]
    print("{:3d} {:20s} base=0x{:016x}".format(i, name, base))
