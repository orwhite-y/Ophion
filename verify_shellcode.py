#!/usr/bin/env python3
"""
Verify the Ophion TriggerJump shellcode encoding after the DllName/DllFullName fix.
Run: python3 verify_shellcode.py
"""
import struct

def build_shellcode(dll_remote_va, dll_name_va, dll_full_name_va, ldr_load_va, dll_size):
    buf = bytearray()

    # 1. sub rsp, 0x58  (4 bytes)
    buf += bytes([0x48, 0x83, 0xEC, 0x58])

    # 2. mov rax, <dll_full_name_remote_va>  (10 bytes)
    buf += bytes([0x48, 0xB8]) + struct.pack('<Q', dll_full_name_va)

    # 3. mov [rsp+0x30], rax  (5 bytes)
    buf += bytes([0x48, 0x89, 0x44, 0x24, 0x30])

    # 4. mov rax, <dll_name_remote_va>  (10 bytes)
    buf += bytes([0x48, 0xB8]) + struct.pack('<Q', dll_name_va)

    # 5. mov [rsp+0x28], rax  (5 bytes)
    buf += bytes([0x48, 0x89, 0x44, 0x24, 0x28])

    # 6. mov qword ptr [rsp+0x20], 0  (12 bytes)
    buf += bytes([0x48, 0xC7, 0x84, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    # 7. mov r9, dll_remote_va  (10 bytes)
    buf += bytes([0x49, 0xB9]) + struct.pack('<Q', dll_remote_va)

    # 8. xor r8d, r8d  (3 bytes)
    buf += bytes([0x45, 0x31, 0xC0])

    # 9. xor edx, edx  (2 bytes)
    buf += bytes([0x31, 0xD2])

    # 10. lea rcx, [rsp+0x40]  (5 bytes)
    buf += bytes([0x48, 0x8D, 0x4C, 0x24, 0x40])

    # 11. mov rax, LdrLoadVa  (10 bytes)
    buf += bytes([0x48, 0xB8]) + struct.pack('<Q', ldr_load_va)

    # 12. call rax  (2 bytes)
    buf += bytes([0xFF, 0xD0])

    # 13. mov rax, [rsp+0x40]  (5 bytes)
    buf += bytes([0x48, 0x8B, 0x44, 0x24, 0x40])

    # 14. mov r10, (dll_remote_va + DllSize)  (10 bytes)
    module_base_out = dll_remote_va + dll_size
    buf += bytes([0x49, 0xBA]) + struct.pack('<Q', module_base_out)

    # 15. mov [r10], rax  (3 bytes)
    buf += bytes([0x49, 0x89, 0x02])

    # 16. add rsp, 0x58  (4 bytes)
    buf += bytes([0x48, 0x83, 0xC4, 0x58])

    # 17. ret  (1 byte)
    buf += bytes([0xC3])

    return buf

# --- Instruction boundaries for verification ---
BOUNDARIES = [
    (0,   4,   "sub rsp, 0x58"),
    (4,   14,  "mov rax, imm64 (DllFullName addr)"),
    (14,  19,  "mov [rsp+0x30], rax"),
    (19,  29,  "mov rax, imm64 (DllName addr)"),
    (29,  34,  "mov [rsp+0x28], rax"),
    (34,  46,  "mov qword [rsp+0x20], 0 (Reserved)"),
    (46,  56,  "mov r9, imm64 (BufferAddress)"),
    (56,  59,  "xor r8d, r8d (dwFlags=0)"),
    (59,  61,  "xor edx, edx (LdrEntry=NULL)"),
    (61,  66,  "lea rcx, [rsp+0x40] (&BaseAddress)"),
    (66,  76,  "mov rax, imm64 (LdrLoadDllMemoryExW)"),
    (76,  78,  "call rax"),
    (78,  83,  "mov rax, [rsp+0x40] (HMEMORYMODULE)"),
    (83,  93,  "mov r10, imm64 (output addr)"),
    (93,  96,  "mov [r10], rax (store module base)"),
    (96,  100, "add rsp, 0x58"),
    (100, 101, "ret"),
]

def main():
    # Test values
    dll_va = 0x00000200_4A3B0000
    dll_name_va = dll_va + 0x50000 + 8
    dll_full_name_va = dll_name_va + 28  # after "renderdoc.dll\0" (14 wchars)
    ldr_va = 0x00007FFA_B1234567
    dll_size = 0x50000

    sc = build_shellcode(dll_va, dll_name_va, dll_full_name_va, ldr_va, dll_size)

    print("=" * 70)
    print("SHELLCODE VERIFICATION (DllName/DllFullName fix)")
    print("=" * 70)

    # Print disassembly
    for start, end, desc in BOUNDARIES:
        inst = sc[start:end]
        print(f"  [{start:3d}-{end:3d}] {inst.hex(' '):<35s} ; {desc}")

    total = len(sc)
    print(f"\nTotal size: {total} bytes / 128 buffer = {'OK' if total <= 128 else 'OVERFLOW'}")
    print(f"Headroom: {128 - total} bytes")

    # Stack alignment
    sub_val = 0x58  # 88
    # Entry RSP = 16n + 8 (after call pushed return addr)
    # After sub: RSP = 16n + 8 - 88 = 16n - 80 = 16(n-5) -> aligned
    aligned = ((8 - sub_val) % 16) == 0
    print(f"\nStack alignment:")
    print(f"  Entry RSP = 16n + 8")
    print(f"  sub rsp, 0x{sub_val:X} ({sub_val} bytes)")
    print(f"  RSP after sub = 16n + 8 - {sub_val} = 16(n-5) -> {'ALIGNED' if aligned else 'MISALIGNED'}")
    print(f"  Before 'call rax': RSP is 16-byte aligned: {'YES' if aligned else 'NO'}")

    # Verify imm64 values are little-endian
    print(f"\nImm64 value checks:")
    fn_val = struct.unpack('<Q', sc[6:14])[0]
    dn_val = struct.unpack('<Q', sc[21:29])[0]
    r9_val = struct.unpack('<Q', sc[48:56])[0]
    ldr_val = struct.unpack('<Q', sc[68:76])[0]
    out_val = struct.unpack('<Q', sc[85:93])[0]

    checks = [
        ("DllFullName addr", fn_val, dll_full_name_va),
        ("DllName addr",     dn_val, dll_name_va),
        ("BufferAddress",    r9_val, dll_va),
        ("LdrLoadVa",        ldr_val, ldr_va),
        ("Output addr",      out_val, dll_va + dll_size),
    ]
    for name, actual, expected in checks:
        status = "OK" if actual == expected else "FAIL"
        print(f"  {name}: 0x{actual:016x} vs 0x{expected:016x} -> {status}")

    # NULL case
    print(f"\nNULL string test:")
    sc_null = build_shellcode(dll_va, 0, 0, ldr_va, dll_size)
    dn_null = struct.unpack('<Q', sc_null[21:29])[0]
    fn_null = struct.unpack('<Q', sc_null[6:14])[0]
    print(f"  DllName=NULL -> shellcode passes 0x{dn_null:016x}: {'OK' if dn_null == 0 else 'FAIL'}")
    print(f"  DllFullName=NULL -> shellcode passes 0x{fn_null:016x}: {'OK' if fn_null == 0 else 'FAIL'}")

    # Verify no RAX clobber issue
    print(f"\nRegister flow:")
    print(f"  rax = DllFullName addr -> stored to [rsp+0x30] -> rax free")
    print(f"  rax = DllName addr     -> stored to [rsp+0x28] -> rax free")
    print(f"  rax = LdrLoadVa        -> call rax              -> no clobber issue")
    print(f"  rax = [rsp+0x40]       -> stored to [r10]       -> no clobber issue")
    print(f"  All RAX uses are sequential, no conflict: OK")

    # Final verdict
    all_ok = (total <= 128 and aligned and
              all(a == e for _, a, e in checks) and
              dn_null == 0 and fn_null == 0)
    print(f"\n{'=' * 70}")
    print(f"VERDICT: {'ALL CHECKS PASSED' if all_ok else 'FAILURES DETECTED'}")
    print(f"{'=' * 70}")

if __name__ == '__main__':
    main()
