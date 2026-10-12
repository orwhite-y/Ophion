"""Headless IDA analysis for the packet string writer and its callers.

Usage (IDA 9.x):
  idat.exe -A -S"<absolute-path-to-this-script>" GameAssembly_clean.dll.i64

The LLVM deobfuscator's proved patches are applied only long enough to capture
the improved pseudocode, then rolled back before the database exits.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_nalt
import ida_pro
import idautils
import idc


TARGET_EA = 0x181D59FE0
RELATED_EAS = (TARGET_EA, 0x181D593B0, 0x181D51650)
OUT_DIR = Path(r"F:\winDriver\te\Ophion-master\ida_blob_headless_out")
PLUGIN_DIR = Path(
    r"C:\Users\Administrator\AppData\Roaming\Hex-Rays\IDA Pro\plugins"
)
RUNTIME_DIR = PLUGIN_DIR / "llvm_deobf_runtime"


def decompile_text(ea: int) -> str:
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return "<decompile returned None>"
        return "\n".join(
            ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
        )
    except Exception as exc:
        return f"<decompile failed: {type(exc).__name__}: {exc}>"


def disasm_window(call_ea: int, before: int = 30, after: int = 8) -> list[dict]:
    fn = ida_funcs.get_func(call_ea)
    if fn is None:
        return []
    eas = []
    ea = call_ea
    for _ in range(before):
        prev = idc.prev_head(ea, fn.start_ea)
        if prev == idc.BADADDR or prev >= ea:
            break
        eas.append(prev)
        ea = prev
    eas.reverse()
    eas.append(call_ea)
    ea = call_ea
    for _ in range(after):
        nxt = idc.next_head(ea, fn.end_ea)
        if nxt == idc.BADADDR or nxt <= ea:
            break
        eas.append(nxt)
        ea = nxt
    return [
        {
            "ea": x,
            "ea_hex": hex(x),
            "text": ida_lines.tag_remove(idc.generate_disasm_line(x, 0) or ""),
        }
        for x in eas
    ]


def pseudocode_call_context(text: str, names: tuple[str, ...], radius: int = 10) -> list[str]:
    lines = text.splitlines()
    indexes = [
        i for i, line in enumerate(lines)
        if any(name in line for name in names)
    ]
    if not indexes:
        return []
    keep = set()
    for i in indexes:
        keep.update(range(max(0, i - radius), min(len(lines), i + radius + 1)))
    return [f"{i + 1:04d}: {lines[i]}" for i in sorted(keep)]


def analyze_callers() -> dict:
    target_name = idc.get_func_name(TARGET_EA)
    aliases = tuple(x for x in (target_name, "sub_181D59FE0", "181D59FE0") if x)
    xrefs = list(idautils.XrefsTo(TARGET_EA, 0))
    records = []
    cache: dict[int, str] = {}
    for xr in xrefs:
        fn = ida_funcs.get_func(xr.frm)
        fn_start = fn.start_ea if fn else idc.BADADDR
        if fn_start not in cache:
            cache[fn_start] = decompile_text(fn_start) if fn else "<no function>"
        pseudo = cache[fn_start]
        lower = pseudo.lower()
        records.append(
            {
                "call_ea": xr.frm,
                "call_ea_hex": hex(xr.frm),
                "xref_type": xr.type,
                "function_ea": None if not fn else fn.start_ea,
                "function_ea_hex": None if not fn else hex(fn.start_ea),
                "function_name": idc.get_func_name(xr.frm),
                "mentions_blob": "blob" in lower,
                "mentions_base64": "base64" in lower,
                "mentions_crypto": any(
                    key in lower
                    for key in (
                        "aes", "chacha", "salsa", "sha", "md5", "crc",
                        "encrypt", "decrypt", "compress", "zlib", "lz4",
                    )
                ),
                "pseudocode_context": pseudocode_call_context(pseudo, aliases),
                "blob_lines": [
                    f"{i + 1:04d}: {line}"
                    for i, line in enumerate(pseudo.splitlines())
                    if "blob" in line.lower()
                ],
                "assembly_window": disasm_window(xr.frm),
            }
        )
    return {
        "target_name": target_name,
        "xref_count": len(xrefs),
        "unique_caller_count": len(cache),
        "records": records,
        "caller_pseudocode": {
            hex(ea) if ea != idc.BADADDR else "BADADDR": text
            for ea, text in cache.items()
        },
    }


def run_proved_pipeline(ea: int) -> dict:
    for path in (str(PLUGIN_DIR), str(RUNTIME_DIR)):
        if path not in sys.path:
            sys.path.insert(0, path)
    from llvm_deobf_proved import ProvedPipeline

    pipeline = ProvedPipeline(str(PLUGIN_DIR))
    before = decompile_text(ea)
    bundle = pipeline.analyze(ea)
    result = {
        "function_ea": ea,
        "function_ea_hex": hex(ea),
        "function_name": idc.get_func_name(ea),
        "before": before,
        "bundle": bundle,
        "mode": "preview-only",
    }
    return result


def save_report(report: dict) -> None:
    report_path = OUT_DIR / "blob_headless_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def main() -> int:
    started = time.time()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ida_auto.auto_wait()

    report: dict = {
        "input_file": ida_nalt.get_input_file_path(),
        "idb_path": idc.get_idb_path(),
        "image_base": ida_nalt.get_imagebase(),
        "target_ea": TARGET_EA,
        "target_ea_hex": hex(TARGET_EA),
        "started_unix": started,
        "proved": {},
        "callers": None,
        "errors": [],
    }

    # Persist the expensive caller/decompiler pass first.  The proved bridge is
    # then previewed separately so a third-party resolver failure cannot discard
    # already-collected call-site evidence.
    try:
        report["callers"] = analyze_callers()
    except Exception as exc:
        report["errors"].append(
            {
                "stage": "callers",
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            }
        )
    save_report(report)

    for ea in RELATED_EAS:
        try:
            report["proved"][hex(ea)] = run_proved_pipeline(ea)
        except Exception as exc:
            report["errors"].append(
                {
                    "stage": f"proved:{hex(ea)}",
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc(),
                }
            )
        save_report(report)

    report["elapsed_seconds"] = time.time() - started
    report_path = OUT_DIR / "blob_headless_report.json"
    save_report(report)

    summary = [
        f"input={report['input_file']}",
        f"idb={report['idb_path']}",
        f"target={hex(TARGET_EA)} {idc.get_func_name(TARGET_EA)}",
        f"xrefs={(report.get('callers') or {}).get('xref_count')}",
        f"unique_callers={(report.get('callers') or {}).get('unique_caller_count')}",
        f"errors={len(report['errors'])}",
        f"elapsed={report['elapsed_seconds']:.3f}s",
        f"report={report_path}",
    ]
    (OUT_DIR / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("[blob-headless] " + " | ".join(summary))
    return 0 if not report["errors"] else 2


try:
    _exit_code = main()
except Exception:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "fatal.txt").write_text(traceback.format_exc(), encoding="utf-8")
    _exit_code = 3

ida_pro.qexit(_exit_code)
