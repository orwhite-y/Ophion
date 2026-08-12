# -*- coding: utf-8 -*-
import re

# Read clean version
with open(r'F:\winDriver\te\Ophion-master\_process_clean.md', 'r', encoding='utf-8-sig') as f:
    content = f.read()

# --- Update current status section ---
old_status = """## \u5f53\u524d\u72b6\u6001
- **\u9879\u76ee\u8def\u5f84**\uff1aF:\\winDriver\\te\\Ophion-master (\u9a71\u52a8) + F:\\winDriver\\te\\Ophion-master\\renderdoc-1.36 (renderdoc)
- **\u6700\u8fd1\u66f4\u65b0**\uff1a2026-08-11 15:18
- **\u6700\u8fd1\u4f1a\u8bdd**\uff1asession-28-mode-h-fix-success
- **\u57fa\u7ebf**\uff1aHEAD = beeb4a5 + \u5de5\u4f5c\u6811\u6539\u52a8 stealth.h (MODE_G->MODE_H\uff0c\u672a\u63d0\u4ea4)
- **\u8fdb\u884c\u4e2d**\uff1a\u65e0\u3002\u6ce8\u5165\u6d4b\u8bd5\u6210\u529f\uff0c\u7b49 He \u786e\u8ba4 F12 \u622a\u5e27\u3002
- **\u4e0b\u4e00\u6b65**\uff1aHe \u9a8c\u8bc1 F12 overlay/\u622a\u5e27\uff1b\u5982\u6210\u529f\u53ef\u63d0\u4ea4 stealth.h \u6539\u52a8\u3002"""

new_status = """## \u5f53\u524d\u72b6\u6001
- **\u9879\u76ee\u8def\u5f84**\uff1aF:\\winDriver\\te\\Ophion-master (\u9a71\u52a8) + F:\\winDriver\\te\\Ophion-master\\renderdoc-1.36 (renderdoc)
- **\u6700\u8fd1\u66f4\u65b0**\uff1a2026-08-12 10:15
- **\u6700\u8fd1\u4f1a\u8bdd**\uff1asession-32-process-commit
- **\u57fa\u7ebf**\uff1aHEAD = b5c2e07 (session 29-31 \u5168\u90e8\u4fee\u590d\u5df2\u63d0\u4ea4)
- **\u5de5\u4f5c\u6811**\uff1a\u5e72\u51c0\uff08\u4ec5 untracked \u4e34\u65f6\u6587\u4ef6\uff09
- **\u8fdb\u884c\u4e2d**\uff1a\u65e0\u3002\u9a71\u52a8\u6e90\u7801\u5df2\u5168\u90e8\u63d0\u4ea4\uff0c\u6ce8\u5165\u7a33\u5b9a\u3002
- **\u4e0b\u4e00\u6b65**\uff1aHe \u51b3\u5b9a\u662f\u5426\u91cd\u65b0\u542f\u52a8\u6e38\u620f\u6d4b\u8bd5\u622a\u5e27\uff08\u7528 flag file \u89e6\u53d1\uff0c\u4e0d\u8981\u7528 F12\uff09\u3002"""

content = content.replace(old_status, new_status)

# --- Insert new changelog entries after session 28 ---
session31 = """### 2026-08-12 10:15  [session 32]
- \u52a8\u4f5c\uff1a\u63a5\u7ba1 + \u68c0\u67e5 git \u72b6\u6001 + \u4fee\u590d PROCESS.md \u7f16\u7801\u635f\u574f + \u63d0\u4ea4
- \u53d1\u73b0\uff1ab5c2e07 \u63d0\u4ea4\u65f6 PROCESS.md \u88ab GBK \u53cc\u91cd\u7f16\u7801\u635f\u574f\uff08UTF-8 BOM + GBK \u5b57\u8282\uff09\uff0c\u4ece 8f7be9c \u6062\u590d\u5e72\u51c0\u7248\u672c
- \u6587\u4ef6\uff1aPROCESS.md\uff08\u91cd\u5199\u4e3a\u6b63\u786e UTF-8 BOM + CRLF\uff09
- \u7ed3\u8bba\uff1a\u9a71\u52a8\u6e90\u7801\u5df2\u5728 b5c2e07 \u63d0\u4ea4\uff0c\u5de5\u4f5c\u6811\u5e72\u51c0\u3002PROCESS.md \u7f16\u7801\u4fee\u590d\u540e\u5f85\u63d0\u4ea4\u3002

### 2026-08-12 09:51  [session 31]
- \u52a8\u4f5c\uff1a\u63a5\u7ba1 + \u5206\u6790\u84dd\u5c4f dump + \u4fee\u590d SEH + \u7f16\u8bd1\u90e8\u7f72\u6d4b\u8bd5
- \u84dd\u5c4f\u5206\u6790\uff1a081226-10703-01.dmp (09:30:58)
  - BUGCHECK: KMODE_EXCEPTION_NOT_HANDLED (0x1E)
  - Arg1: 0xC0000005 (STATUS_ACCESS_VIOLATION)
  - Arg2: fffff8024d3e4957 (Ntfs.sys)
  - \u6808\uff1abc_worker_thread -> hv_breadcrumb_write_log+0x41f -> NtWriteFile -> Ntfs -> AV
  - \u6839\u56e0\uff1aBC.log \u540e\u53f0\u7ebf\u7a0b\u5199 ZwWriteFile \u65f6 Ntfs \u5185\u90e8 AV\u3002BC.log \u53ea\u662f\u8c03\u8bd5\u65e5\u5fd7\uff0c\u5931\u8d25\u4e0d\u5e94\u62d6\u57ae OS
- \u4fee\u590d\uff1abreadcrumb.cpp
  - hv_breadcrumb_write_log: __try/__except(EXCEPTION_EXECUTE_HANDLER) \u5305\u88f9 ZwWriteFile
  - ZwClose \u4e5f\u5305\u4e86 SEH
  - bc_worker_thread \u548c hv_breadcrumb_flush_now \u7684\u8c03\u7528\u4e5f\u5305\u4e86 SEH (\u9632\u5fa1)
  - \u6587\u4ef6\u7528 UTF-8 BOM + LF\uff0c\u4f7f\u7528 UTF-8 \u7f16\u7801\u7f16\u8f91
- VMCALL \u8bef\u62a5\u4fee\u590d\uff1aTdStealthFreePageSafe \u6bcf\u9875\u5bf9\u5168\u90e8 CPU \u53d1 VMCALL\uff0crenderdoc.dll=2094 \u9875 -> 2094 VMCALLs/CPU\u3002safety-net streak \u8ba1\u6570\u6392\u9664 VMCALL\u3002
- \u91cd\u91cf\u7ea7\u8bb0\u5f55\uff1a
  - Ophion.sys@FFFFF8024A700000, TestEptHook.sys@FFFFF8024AC0000
  - ntoskrnl@FFFFF8057D800000
  - GoWR PID=12248 WS=1786MB Threads=79
  - BC.log: 2024 EPT violation, 22 EPT misconfig, 1 VMCALL, 1 MOV_CR breaker, 0 panic
  - \u7cfb\u7edf\u7a33\u5b9a 15+ \u5206\u949f\uff0c\u65e0\u65b0 dump
- \u7f16\u8bd1\uff1a_build2.bat \u6210\u529f\uff0c\u7b7e\u540d\u901a\u8fc7
- \u6d4b\u8bd5\u7ed3\u679c\uff1a\u6ce8\u5165\u6210\u529f\uff0c\u7cfb\u7edf\u7a33\u5b9a 15+ \u5206\u949f\uff0c\u65e0 BSOD
- \u63d0\u4ea4\uff1ab5c2e07\uff08\u6e90\u7801 + PROCESS.md \u4e00\u8d77\u63d0\u4ea4\uff0c\u4f46 PROCESS.md \u7f16\u7801\u635f\u574f\uff09

### 2026-08-11 17:01  [session 30]
- \u52a8\u4f5c\uff1a\u63a5\u7ba1 + MTF handler \u65b9\u5411\u53cd\u8f6c\u4fee\u590d + \u7f16\u8bd1\u901a\u8fc7
- \u4fee\u590d\uff1aept_hook.cpp ~L1109 MTF handler \u7528 sp->pt_page_va (shadow->shadow) \u800c\u975e sp->real_pt_page_va (real->shadow)\u3002\u65e7\u4ee3\u7801\u5bfc\u81f4\u65e0\u9650 EPT W=0 \u91cd\u89e6\u53d1 -> \u7cfb\u7edf\u5361\u6b7b\u3002
- \u5176\u4ed6\u4fee\u590d\uff08\u5747\u5728 b5c2e07\uff09\uff1a
  - #PF TRUE-path liveloop breaker (vmexit.cpp ~L2530)
  - MOV_CR liveloop breaker (vmexit.cpp ~L2117)\uff1a\u8fde\u7eed 1024 \u6b21 MOV_CR \u540e\u4e2d\u6b62
  - Safety-net bugcheck (vmexit.cpp ~L2130)\uff1aws>=4096(\u975eVMCALL) \u6216 wrs>=65536 -> hv_panic
  - TdShadowFreePageList SEH (td_shadow.cpp ~L42)\uff1astale VA \u6e05\u7406 -> BSOD 0x3B
  - TdShadowUnmapRealPage SEH (td_shadow.cpp ~L121)
  - ept_stealth_abort_shadow_window \u516c\u5f00\u63a5\u53e3 (ept_stealth.cpp ~L505)

"""

# Insert before session 28 entry
session28_marker = "### 2026-08-11 15:18  [session 28]"
content = content.replace(session28_marker, session31 + session28_marker)

# --- Add new key findings before existing ones ---
new_findings = """- **\u3010session 31\u3011BC.log \u540e\u53f0\u7ebf\u7a0b Ntfs AV**\uff1abc_worker_thread \u5199 BC.log \u65f6 ZwWriteFile -> Ntfs \u5185\u90e8 AV\u3002SEH \u5305\u88f9\u89e3\u51b3\u3002\u786e\u5207\u6839\u56e0\u672a\u5b9a\u3002
- **\u3010session 31\u3011AutoReboot=1**\uff1a\u84dd\u5c4f\u4e00\u5206\u949f\u81ea\u52a8\u91cd\u542f\uff0cHe \u770b\u5230\u7684\u662f\u76f4\u63a5\u91cd\u542f\u3002Dump \u4ecd\u7136\u751f\u6210\u5728 C:\\Windows\\Minidump\\\u3002
- **\u3010session 31\u3011breadcrumb.cpp \u662f UTF-8 BOM + LF**\uff1a\u4e0d\u662f CRLF+GBK\u3002\u7f16\u8f91\u7528 UTF-8\u3002
- **\u3010session 31\u3011VMCALL streak**\uff1aTdStealthFreePageSafe \u7528 KeGenericCallDpc -> hv_vmcall_simple \u5bf9\u5168\u90e8 CPU \u6bcf\u9875\u53d1 VMCALL\u3002renderdoc.dll=2094 \u9875 -> 2094 VMCALLs/CPU\u3002safety-net \u5fc5\u987b\u6392\u9664 VMCALL\u3002
- **\u3010session 31\u3011renderdoc \u622a\u5e27\u89e6\u53d1**\uff1a\u4e0d\u8981\u7528 F12\uff01F12 \u542f\u7528 overlay -> late-wrap \u6a21\u5f0f\u4e0b GPU device removal\u3002\u6b63\u786e\u65b9\u5f0f\uff1a\u521b\u5efa flag file C:\\ProgramData\\WinComp\\capture.flag\u3002CheckCaptureTrigger() \u6bcf\u6b21 Present \u68c0\u67e5\u6b64\u6587\u4ef6\uff0c\u5220\u9664\u540e\u8bbe g_captureStarted=true\uff0c\u4e0b\u4e00\u5e27 EndFrameCapture \u5199 C:\\ProgramData\\WinComp\\captures\\frame_XXXXXX.bmp\u3002
- **\u3010session 30\u3011MTF handler \u65b9\u5411\u53cd\u8f6c = \u5361\u6b7b\u6839\u56e0**\uff1aMODE_H \u4e0b MTF handler \u5fc5\u987b shadow->shadow\uff08\u7528 sp->pt_page_va\uff09\uff0c\u4e0d\u80fd\u7528 sp->real_pt_page_va\uff08real->shadow \u8986\u76d6 OS \u5199\u5165 -> \u65e0\u9650\u5faa\u73af\u5361\u6b7b\uff09\u3002
"""

old_findings_marker = "- **\u4e0d\u5f97\u56de\u9000\uff08\u5168\u5c40\u89c4\u5219\uff09**"
content = content.replace(old_findings_marker, new_findings + old_findings_marker)

# --- Update todo section ---
old_todo = """## \u5f85\u529e / \u4e0b\u4e00\u6b65
1. He \u9a8c\u8bc1 F12 overlay / renderdoc \u622a\u5e27\u662f\u5426\u6b63\u5e38
2. \u5982\u622a\u5e27\u6210\u529f -> \u63d0\u4ea4 stealth.h (MODE_G->MODE_H) \u6539\u52a8
3. \u5982\u622a\u5e27\u6709\u95ee\u9898 -> \u5206\u6790 renderdoc hook \u72b6\u6001
4. \uff08\u53ef\u9009\uff09\u63d0\u4ea4\u540e\u6e05\u7406\u5de5\u4f5c\u6811\u7684 .bak/.rej \u4e34\u65f6\u6587\u4ef6"""

new_todo = """## \u5f85\u529e / \u4e0b\u4e00\u6b65
1. He \u51b3\u5b9a\u662f\u5426\u91cd\u65b0\u542f\u52a8\u6e38\u620f\u6d4b\u8bd5\u622a\u5e27
2. \u5982\u6d4b\u622a\u5e27\uff1a\u7528 flag file \u89e6\u53d1\uff08\u4e0d\u8981\u7528 F12\uff09
3. \u5982\u622a\u5e27\u6210\u529f -> \u786e\u8ba4\u6d41\u7a0b\u5b8c\u6574
4. \u5982\u622a\u5e27\u6709\u95ee\u9898 -> \u5206\u6790 renderdoc RDCLOG \u8f93\u51fa
5. \uff08\u53ef\u9009\uff09\u63d0\u4ea4\u540e\u6e05\u7406\u5de5\u4f5c\u6811 .bak/.rej \u4e34\u65f6\u6587\u4ef6"""

content = content.replace(old_todo, new_todo)

# Write with UTF-8 BOM + CRLF
lines = content.replace('\r\n', '\n').split('\n')
crlf = '\r\n'.join(lines)
bom = b'\xef\xbb\xbf'
data = bom + crlf.encode('utf-8')
with open(r'F:\winDriver\te\Ophion-master\PROCESS.md', 'wb') as f:
    f.write(data)
print(f'Written {len(data)} bytes')
