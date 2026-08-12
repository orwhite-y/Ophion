# Codex 宸ヤ綔娴佺▼璁板綍 (Ophion/renderdoc 娉ㄥ叆椤圭洰)

> 璁板綍宸插畬鎴愩€佽繘琛屼腑銆佸緟鍔炵殑宸ヤ綔銆備笂涓嬫枃鍘嬬缉鍚庡繀璇汇€?

## 褰撳墠鐘舵€?
- **椤圭洰璺緞**锛欶:\winDriver\te\Ophion-master (椹卞姩) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **鏈€杩戞洿鏂?*锛?2026-08-12 09:48
- **鏈€杩戜細璇?*锛歴ession-31-bc-log-seh-fix
- **鍩虹嚎**锛欻EAD = 8f7be9c (session 28) + 宸ヤ綔鏍戞敼鍔?10鏂囦欢)
- **杩涜涓?*锛歎BC.log SEH 淇澶嶇紪璇戦儴缃叉祴璇曢€氳繃 (GoWR + renderdoc 娉娉ㄥ叆鍚庣ǔ瀹?30s+)
- **涓嬩竴姝?*锛欻e 楠岃瘉 F12 overlay / renderdoc 鎴hower

## 鍙樻洿鏃ュ織
### 2026-08-12 09:48  [session 31]
- 鍔ㄤ綔锛氭帴绠?+ 鍒嗘瀽钃濆睆 dump + 淇嶄慨 SEH + 缂栬瘧閮ㄧ讲娴嬭瘯
- 钃濆睆鍒嗘瀽锛?081226-10703-01.dmp (09:30:58)
  - BUGCHECK: KMODE_EXCEPTION_NOT_HANDLED (0x1E)
  - Arg1: 0xC0000005 (STATUS_ACCESS_VIOLATION)
  - Arg2: fffff8024d3e4957 (Ntfs.sys)
  - 鏍堬細bc_worker_thread -> hv_breadcrumb_write_log+0x41f -> NtWriteFile -> Ntfs -> AV
  - 鏍瑰洜锛欰C.log 鍚庡彴绾跨▼鍐?ZwWriteFile 鏃?Ntfs 鍐呴儴 AV銆俿BC.log 鍙槸璋冭瘯鏃ュ織锛屽け璐ヤ笉搴斿綋ㄤ簩 OS
- 淇嶄慨锛歰readcrumb.cpp
  - hv_breadcrumb_write_log: __try/__except(EXCEPTION_EXECUTE_HANDLER) 鍖呰 mrWriteFile + 寮︽敼 entry 瀵煎嚭
  - ZwClose 涔熷寘浜嗗惂 SEH
  - bc_worker_thread 鍙?hv_breadcrumb_flush_now 鐨勮皟鐢ㄤ篃鍖呬簡 SEH (闃插尽)
  - 鏂囦欢鐢?UTF-8 BOM + LF锛屼笉鏄?CRLF+GBK锛屼娇鐢?UTF-8 缂栫爜缂栬緫
- 绠楀垎绂婚噸閲忕敓姝夛細
  - Ophion.sys@FFFFF8024A700000, TestEptHook.sys@FFFFF8024AC0000
  - ntoskrnl@FFFFF8057D800000
  - GoWR PID=12248 WS=1786MB Threads=79
  - BC.log: 2024 EPT violation, 22 EPT misconfig, 1 VMCALL, 1 MOV_CR breaker, 鏃?panic
  - 绯荤粺鎬荤ǔ瀹?15鍒嗛挓+锛屾棤鏂?dump
- 缂栬瘧锛歘build2.bat 鎴愬姛锛岀鏄悕閫氳繃
- 缁撹锛欰BC.log SEH 淇嶅嶄慨瑙ｅ喅浜嗚摑灞忛棶棰樸€傛硹bench 鐙虫櫤姝e父锛屾敞鍏ュ悗绯荤粺鎬ㄧǔ瀹?

### 2026-08-11 17:01  [session 30]
- 鍔ㄤ綔锛氭帴绠?+ MTF handler 鏂瑰悜鍙嶈浆淇嶄慨 + 缂栬瘧閫氳繃
- 缁撴锛氬緟閮ㄧ讲娴嬭瘯锛堟湰浼氳窡宸插畬鎴愶級

## 鍏抽敭鍙戠幇
- **銆恠ession 31銆怓C.log 鍚庡彴绾跨▼鍙戠敓 Ntfs AV**锛歋bc_worker_thread 鍐?BC.log 鏃?ZwWriteFile -> NtWriteFile -> Ntfs 鍐呴儴 AV銆俿SEH 淇嶅嶄慨瑙ｅ喅銆傚彲鑳芥槸 hypervisor 鐨?EPT/shadow 鏈哄埗褰卞搷鍒?Ntfs 鍐呴儴缁撴瀯锛屼絾纭垏鍘熷洜鏈熷洜鏈畾銆?
- **銆恠ession 31銆怉utoReboot=1**锛氱矗灞忎竴鍒嗛挓灏辫嚜鍔ㄩ噸鍚紝鐢紝鐢ㄦ埛鐪嬪埌鐨勬槸钃濆睆(闈?BSOD)銆俈ump 浠嶇劧浼氱敓鎴愩€?
- **銆恠ession 31銆怉readcrumb.cpp 鏄?UTF-8 BOM + LF**锛氫笉鏄?CRLF+GBK銆傜敤 UTF-8 缂栫爜缂栬緫锛屼笉鐢?GBK銆?
- **銆恠ession 30銆慚TF handler 鏂瑰悜鍙嶈浆 = 鍗℃鏍瑰洜**锛歁ODE_H 涓嬶紝MTF handler 蹇呴』 shadow->shadow锛堢敤 sp->pt_page_va锛夛紝涓嶈兘鐢?sp->real_pt_page_va锛堝崕->shadow 瑕嗙洊 OS 鍐欏叆 -> 鏃犻檺寰幆鍗℃锛夈€?
- **涓嶅緱鍥為€€锛堝叏灞€瑙勫垯锛?*锛欻E 鏄庣‘瑕佹眰鏈缁忓厑璁笉瑕佸洖閫€浠ｇ爜銆?
- **Python 缂栬緫 CRLF 鏂囦欢浼氭妲夋崲琛岀 erotic->LF**锛氬繀椤讳娇鐢?binary 妯″紡銆?
- **VMX-root 绾绾︽潫**锛氭棤 API 璋冪敤銆佹棤鏂囦欢 I/O銆傚彧鑳界敤浜掗攣 + 鍐呭瓨鍐?+ VMX 鎸囧安保 + 绔彛 I/O + __invlpg + __writecr4銆?
- **CFG 涓嶇敤纰?*锛欻E 鐢ㄧ壒璁艰繃 CFG銆?
- **USE_PRIVATE_HOST_CR3 = 1**锛歏MX-root 璺戝湪绉佹湁 host CR3 涓娿€?
- **BSOD 鏈哄埗**锛欱ugcheck=0xDEADC0DE銆傚弬鏁?=0xFF01(#PF)/0xFF02(鍏跺畠)锛屽弬鏁?=cr2/鍚戦噺锛屽弬鏁?=RIP锛屽弬鏁?=err銆?
- **dual-EPT 涓嶈兘鏇夸唬 shadow CR3**锛欻E 璁捐鏄犵'z鐢ㄦ硾鍒囦唤銆?
- **TdNeuterCFG / trigger 涓嶈绂?*锛欻E 鏄庣‘鎷掔粷銆?

## 寰呭姙 / 涓嬩竴姝?
1. He 楠岃瘉 F12 overlay / renderdoc 鎴hower 鏄惁姝e父
2. 濡傛埅甯ф垚鍔?-> 鎻愪氦宸ヤ綔鏍戞敼鍔?
3. 濡傛埅甯ф湁闂 -> 鍒嗘瀽 renderdoc hook 鐘舵€?
4. 鍒嗘瀽 Ntfs AV 鐨勬牴鏍瑰洜锛堝彲鑳芥槸 hypervisor 鍐呭瓨绠绠＄悊闂锛夛紝浣嗗紭鍏堢骇绾ф祴璇?