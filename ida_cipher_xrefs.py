import json
from pathlib import Path

import ida_funcs
import ida_kernwin
import ida_lines
import ida_name
import idaapi
import idautils
import idc


TARGETS = [
    0x181D2D2C0,
    0x181D311F0,
    0x181D33600,
    0x181D35740,
    0x181D37A70,
    0x181D41940,
    0x181D424E0,
    0x181D2E230,
    0x181D2EB20,
    0x181D2ED80,
    0x181D2F2C0,
    0x181D2FCD0,
    0x181D307D0,
    0x181D39B60,
    0x181D3A590,
    0x181D3D7D0,
    0x181D43070,
    0x181D444B0,
    0x181D44970,
    0x181D45E20,
    0x181D47F90,
    0x181D58800,
]
OUT = Path(r"F:\winDriver\te\Ophion-master\ida_blob_headless_out\cipher_xrefs.json")


def line(ea):
    return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")


def window(ea, before=20, after=30):
    start = ea
    for _ in range(before):
        prev = idc.prev_head(start)
        if prev == idaapi.BADADDR:
            break
        start = prev
    rows = []
    cur = start
    for _ in range(before + after + 1):
        if cur == idaapi.BADADDR:
            break
        rows.append({"ea": hex(cur), "text": line(cur)})
        cur = idc.next_head(cur)
    return rows


report = {
    "targets": {},
    "mx_names": [
        {"ea": hex(ea), "name": name}
        for ea, name in idautils.Names()
        if name.startswith("MX_")
    ],
}
for target in TARGETS:
    refs = []
    for xr in idautils.XrefsTo(target, 0):
        fn = ida_funcs.get_func(xr.frm)
        refs.append(
            {
                "from": hex(xr.frm),
                "type": xr.type,
                "iscode": bool(xr.iscode),
                "function": hex(fn.start_ea) if fn else None,
                "function_name": ida_name.get_name(fn.start_ea) if fn else None,
                "window": window(xr.frm),
            }
        )
    fn = ida_funcs.get_func(target)
    report["targets"][hex(target)] = {
        "name": ida_name.get_name(target),
        "function_end": hex(fn.end_ea) if fn else None,
        "assembly": [
            {"ea": hex(ea), "text": line(ea)}
            for ea in idautils.FuncItems(target)
        ] if fn else [],
        "xrefs": refs,
    }

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"[cipher-xrefs] wrote {OUT}")
idc.qexit(0)
