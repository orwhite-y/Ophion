<<<<<<< HEAD
ï»¿# Codex å®¸ãƒ¤ç¶”å¨´ä½ºâ–¼ç’æ¿ç¶ (Ophion/renderdoc å¨‰ã„¥å†æ¤¤åœ­æ´°)

> ç’æ¿ç¶å®¸æ’ç•¬éŽ´æ„©â‚¬ä½½ç¹˜ç›å±¼è…‘éŠ†ä½¸ç·Ÿé”ç‚µæ®‘å®¸ãƒ¤ç¶”éŠ†å‚™ç¬‚æ¶“å¬«æžƒé˜å¬¬ç¼‰éšåº¡ç¹€ç’‡æ±‡â‚¬?

## è¤°æ’³å¢ é˜èˆµâ‚¬?
- **æ¤¤åœ­æ´°ç’ºç·ž**é”›æ¬¶:\winDriver\te\Ophion-master (æ¤¹åžå§©) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **éˆâ‚¬æ©æˆžæ´¿é‚?*é”›?2026-08-12 09:48
- **éˆâ‚¬æ©æˆœç´°ç’‡?*é”›æ­´ession-31-bc-log-seh-fix
- **é©è™¹åšŽ**é”›æ¬»EAD = 8f7be9c (session 28) + å®¸ãƒ¤ç¶”éæˆžæ•¼é”?10é‚å›¦æ¬¢)
- **æ©æ¶œæ¶“?*é”›æ­ŽBC.log SEH æ·‡æ¾¶å¶‡ç´ªç’‡æˆ¦å„´ç¼ƒå‰ç¥´ç’‡æ›¢â‚¬æ°³ç¹ƒ (GoWR + renderdoc å¨‰å¨‰ã„¥å†éšåº£Ç”ç€¹?30s+)
- **æ¶“å¬©ç«´å§?*é”›æ¬»e æ¥ å²ƒç˜‰ F12 overlay / renderdoc éŽ´hower

## é™æ¨»æ´¿éƒãƒ¥ç¹”
### 2026-08-12 09:48  [session 31]
- é”ã„¤ç¶”é”›æ°­å¸´ç» ?+ é’å—˜ç€½é’ƒæ¿†ç† dump + æ·‡å¶„æ…¨ SEH + ç¼‚æ ¬ç˜§é–®ã„§è®²å¨´å¬­ç˜¯
- é’ƒæ¿†ç†é’å—˜ç€½é”›?081226-10703-01.dmp (09:30:58)
  - BUGCHECK: KMODE_EXCEPTION_NOT_HANDLED (0x1E)
  - Arg1: 0xC0000005 (STATUS_ACCESS_VIOLATION)
  - Arg2: fffff8024d3e4957 (Ntfs.sys)
  - éå ¬ç´°bc_worker_thread -> hv_breadcrumb_write_log+0x41f -> NtWriteFile -> Ntfs -> AV
  - éç‘°æ´œé”›æ¬°C.log éšåº¡å½´ç»¾è·¨â–¼é?ZwWriteFile éƒ?Ntfs éå‘´å„´ AVéŠ†ä¿¿BC.log é™æ§¸ç’‹å†­ç˜¯éƒãƒ¥ç¹”é”›å±½ã‘ç’ãƒ¤ç¬‰æ´æ–¿ç¶‹ã„¤ç°© OS
- æ·‡å¶„æ…¨é”›æ­°readcrumb.cpp
  - hv_breadcrumb_write_log: __try/__except(EXCEPTION_EXECUTE_HANDLER) é–å‘° mrWriteFile + å¯®ï¸½æ•¼ entry ç€µç…Žåš­
  - ZwClose æ¶”ç†·å¯˜æµœå——æƒ‚ SEH
  - bc_worker_thread é™?hv_breadcrumb_flush_now é¨å‹®çšŸé¢ã„¤ç¯ƒé–å‘¬ç°¡ SEH (é—ƒæ’å°½)
  - é‚å›¦æ¬¢é¢?UTF-8 BOM + LFé”›å±¼ç¬‰é„?CRLF+GBKé”›å±¼å¨‡é¢?UTF-8 ç¼‚æ «çˆœç¼‚æ ¬ç·«
- ç» æ¥€åžŽç»‚å©šå™¸é–²å¿•æ•“å§å¤›ç´°
  - Ophion.sys@FFFFF8024A700000, TestEptHook.sys@FFFFF8024AC0000
  - ntoskrnl@FFFFF8057D800000
  - GoWR PID=12248 WS=1786MB Threads=79
  - BC.log: 2024 EPT violation, 22 EPT misconfig, 1 VMCALL, 1 MOV_CR breaker, éƒ?panic
  - ç»¯è¤ç²ºéŽ¬è¤Ç”ç€¹?15é’å—›æŒ“+é”›å±¾æ£¤é‚?dump
- ç¼‚æ ¬ç˜§é”›æ­˜build2.bat éŽ´æ„¬å§›é”›å²€é„æ‚•é–«æ°³ç¹ƒ
- ç¼æ’¹é”›æ¬°BC.log SEH æ·‡å¶…å¶„æ…¨ç‘™ï½…å–…æµœå—šæ‘‘çžå¿›æ£¶æ£°æ¨¸â‚¬å‚›ç¡¹bench é™è™«æ«¤å§eçˆ¶é”›å±¾æ•žéãƒ¥æ‚—ç»¯è¤ç²ºéŽ¬ã„§Ç”ç€¹?

### 2026-08-11 17:01  [session 30]
- é”ã„¤ç¶”é”›æ°­å¸´ç» ?+ MTF handler é‚ç‘°æ‚œé™å¶ˆæµ†æ·‡å¶„æ…¨ + ç¼‚æ ¬ç˜§é–«æ°³ç¹ƒ
- ç¼æ’´é”›æ°¬ç·Ÿé–®ã„§è®²å¨´å¬­ç˜¯é”›å Ÿæ¹°æµ¼æ°³çª¡å®¸æ’ç•¬éŽ´æ„¶ç´š

## éæŠ½æ•­é™æˆ å¹‡
- **éŠ†æ ession 31éŠ†æ€“C.log éšåº¡å½´ç»¾è·¨â–¼é™æˆ æ•“ Ntfs AV**é”›æ­‹bc_worker_thread é?BC.log éƒ?ZwWriteFile -> NtWriteFile -> Ntfs éå‘´å„´ AVéŠ†ä¿¿SEH æ·‡å¶…å¶„æ…¨ç‘™ï½…å–…éŠ†å‚šå½²é‘³èŠ¥æ§¸ hypervisor é¨?EPT/shadow éˆå“„åŸ—è¤°åžæ·é’?Ntfs éå‘´å„´ç¼æ’´ç€¯é”›å±¼çµ¾çº­î†¼åžé˜ç†·æ´œéˆç†·æ´œéˆî„ç•¾éŠ†?
- **éŠ†æ ession 31éŠ†æ€‰utoReboot=1**é”›æ°±çŸ—çžå¿Žç«´é’å—›æŒ“çè¾«åšœé”ã„©å™¸éšç´é¢ç´é¢ã„¦åŸ›éªå¬ªåŸŒé¨å‹¬æ§¸é’ƒæ¿†ç†(é—ˆ?BSOD)éŠ†ä¿ˆump æµ å¶‡åŠ§æµ¼æ°±æ•“éŽ´æ„©â‚¬?
- **éŠ†æ ession 31éŠ†æ€‰readcrumb.cpp é„?UTF-8 BOM + LF**é”›æ°«ç¬‰é„?CRLF+GBKéŠ†å‚œæ•¤ UTF-8 ç¼‚æ «çˆœç¼‚æ ¬ç·«é”›å±¼ç¬‰é¢?GBKéŠ†?
- **éŠ†æ ession 30éŠ†æ…šTF handler é‚ç‘°æ‚œé™å¶ˆæµ† = é—â„ƒî„´éç‘°æ´œ**é”›æ­ODE_H æ¶“å¬¶ç´MTF handler è¹‡å‘´ã€ shadow->shadowé”›å ¢æ•¤ sp->pt_page_vaé”›å¤›ç´æ¶“å¶ˆå…˜é¢?sp->real_pt_page_vaé”›å å´•->shadow ç‘•å—™æ´Š OS éæ¬å† -> éƒçŠ»æªºå¯°å¹†é—â„ƒî„´é”›å¤ˆâ‚¬?
- **æ¶“å¶…ç·±é¥ç‚ºâ‚¬â‚¬é”›å åçžâ‚¬ç‘™å‹«åž¯é”›?*é”›æ¬»E é„åº£â€˜ç‘•ä½¹çœ°éˆç¼å¿“åŽ‘ç’ç¬‰ç‘•ä½¸æ´–é–«â‚¬æµ ï½‡çˆœéŠ†?
- **Python ç¼‚æ ¬ç·« CRLF é‚å›¦æ¬¢æµ¼æ°­å¦²å¤‹å´²ç›å²€ erotic->LF**é”›æ°¬ç¹€æ¤¤è®³å¨‡é¢?binary å¦¯â€³ç´¡éŠ†?
- **VMX-root ç»¾ç»¾ï¸½æ½«**é”›æ°­æ£¤ API ç’‹å†ªæ•¤éŠ†ä½¹æ£¤é‚å›¦æ¬¢ I/OéŠ†å‚šå½§é‘³ç•Œæ•¤æµœæŽ—æ”£ + éå‘­ç“¨é?+ VMX éŽ¸å›§å®‰ä¿ + ç»”å½› I/O + __invlpg + __writecr4éŠ†?
- **CFG æ¶“å¶‡æ•¤çº°?*é”›æ¬»E é¢ã„§å£’ç’è‰°ç¹ƒ CFGéŠ†?
- **USE_PRIVATE_HOST_CR3 = 1**é”›æ­MX-root ç’ºæˆæ¹ªç»‰ä½¹æ¹ host CR3 æ¶“å¨¿â‚¬?
- **BSOD éˆå“„åŸ—**é”›æ¬±ugcheck=0xDEADC0DEéŠ†å‚šå¼¬é?=0xFF01(#PF)/0xFF02(éè·ºç• )é”›å±½å¼¬é?=cr2/éšæˆ¦å™ºé”›å±½å¼¬é?=RIPé”›å±½å¼¬é?=erréŠ†?
- **dual-EPT æ¶“å¶ˆå…˜é‡å¤¸å”¬ shadow CR3**é”›æ¬»E ç’æé„çŠµ'zé¢ã„¦ç¡¾é’å›¦å”¤éŠ†?
- **TdNeuterCFG / trigger æ¶“å¶ˆç»‚?*é”›æ¬»E é„åº£â€˜éŽ·æŽ”ç²·éŠ†?

## å¯°å‘­å§™ / æ¶“å¬©ç«´å§?
1. He æ¥ å²ƒç˜‰ F12 overlay / renderdoc éŽ´hower é„æƒå§eçˆ¶
2. æ¿¡å‚›åŸ…ç”¯Ñ„åžšé”?-> éŽ»æ„ªæ°¦å®¸ãƒ¤ç¶”éæˆžæ•¼é”?
3. æ¿¡å‚›åŸ…ç”¯Ñ„æ¹é—‚ -> é’å—˜ç€½ renderdoc hook é˜èˆµâ‚¬?
4. é’å—˜ç€½ Ntfs AV é¨å‹¬ç‰´éç‘°æ´œé”›å å½²é‘³èŠ¥æ§¸ hypervisor éå‘­ç“¨ç» ç» ï¼„æ‚Šé—‚é”›å¤›ç´æµ£å——ç´­éå ¢éª‡ç»¾Ñ„ç¥´ç’‡?
=======
# Codex ¹¤×÷Á÷³Ì¼ÇÂ¼ (Ophion/renderdoc ×¢ÈëÏîÄ¿)

> ¼ÇÂ¼ÒÑÍê³É¡¢½øÐÐÖÐ¡¢´ý°ìµÄ¹¤×÷¡£ÉÏÏÂÎÄÑ¹Ëõºó±Ø¶Á¡£

## µ±Ç°×´Ì¬
- **ÏîÄ¿Â·¾¶**£ºF:\winDriver\te\Ophion-master (Çý¶¯) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **×î½ü¸üÐÂ**£º2026-08-12 12:45
- **×î½ü»á»°**£ºsession-41
- **»ùÏß**£ºHEAD = 020ec66
- **¹¤×÷Ê÷**£ºept_stealth.cpp + vmexit.cpp + ept_hook.cpp + breadcrumb.cpp + PROCESS.md ÓÐÎ´Ìá½»¸Ä¶¯
- **½øÐÐÖÐ**£ºtriple faultÐÞ¸´ÒÑÑéÖ¤³É¹¦£¨ÏµÍ³²»ÔÙÓ²ÖØÆô£©£¬×ªÏòµ÷²éshellcode access violation
- **ÏÂÒ»²½**£ºµ÷²éÎªÊ²Ã´shellcodeÔÚRESIDENT+0x400´¦access violation£¬#PFÃ»VM-exit

## ±ä¸üÈÕÖ¾
### 2026-08-12 14:30  [session 37]
- ¶¯×÷£º½Ó¹Ü + ·ÖÎö stealth #PF handler + ÐÞ¸´4¸ö bug + ±àÒë
- ¸ùÒò·ÖÎö£¨He µÄÎÊÌâ£ºstealth #PF handler ÎªÊ²Ã´²»ÅÐ¶ÏÊÇ²»ÊÇÄ¿±êÒ³£©£º
  - handler È·ÊµÔÚ L1789 ¼ì²é sp->guest_va != fault_page£¬µ«ÓÃµÄÊÇ O(n) Á´±í±éÀú£¨2152+ ÌõÄ¿£©
  - He µÄ½¨Òé£¨ÓÃ shadow CR3 PTE NX Î»×ö O(1) ¿ìËÙÅÐ¶Ï£©ÊÇÓÐÐ§µÄÓÅ»¯·½Ïò£¬µ«²»ÊÇµ±Ç°±ÀÀ£µÄÖ±½ÓÔ­Òò
  - µ±Ç°±ÀÀ£¸ùÒòÊÇ stealth_refresh_shadow_code_pte µÄ CR3 Ð¹Â©
- Bug 1£¨¸ùÒò - CR3 Ð¹Â©£©£ºept_stealth.cpp stealth_refresh_shadow_code_pte L1163
  - mx_enter_cr3(sp->guest_cr3) ÔÚ L1099 ÇÐ»» CR3 + ½ûÖÐ¶Ï + Ë¢ TLB
  - stealth_walk_pte Ê§°Ü£¨real PTE not present£¬renderdoc Ò³±» page out£©Ê±
  - eturn FALSE ÔÚ L1163 Ìø¹ýÁË leave: ±êÇ©µÄ mx_leave_guest_cr3(saved_cr3)
  - ½á¹û£ºÖÐ¶ÏÓÀ¾Ã½ûÓÃ + CR3 Í£ÔÚ guest ½ø³Ì CR3 + TLB È«Ë¢ -> ÏµÍ³¿¨ËÀ
  - ÐÞ¸´£ºÔÚ return FALSE Ç°¼Ó mx_leave_guest_cr3(saved_cr3);
- Bug 2£¨ÓÃ»§Ì¬ livelock breaker È± total ¼ÆÊý£©£ºvmexit.cpp L2653
  - ÄÚºËÌ¬ÓÐ wtotal >= 4 ¶µµ×£¬ÓÃ»§Ì¬Ö»ÓÐ ws >= 32£¨per-address streak£©
  - Á½¸öÓÃ»§Ì¬µØÖ·½»Ìæ #PF -> per-address streak ·´¸´ÖØÖÃ -> ÓÀÔ¶µ½²»ÁË 32
  - ÐÞ¸´£ºif (ws >= 32 || wtotal >= 64) do_reinj_break = TRUE;
- Bug 3£¨breaker ²»Çå shadow window ×´Ì¬£©£ºvmexit.cpp L2666-2685
  - FALSE-path breaker ÖØÖÃ streak/total µ«²»Çå nx_timer_restore/nx_timer_real_cr3
  - MTF handler (session 35 fall-through fix) ´¦Àí nx_timer_restore -> »Ö¸´ shadow CR3
  - -> #PF Á¢¼´¸´·¢ -> breaker ÔÙ´¥·¢ -> Ñ­»· -> streak ÔÚ 0?32 Õñµ´ -> µ½ 128/256 ´¥·¢ CMOS snap
  - ÐÞ¸´£ºbreaker ÖÐ¼Ó if (vcpu->nx_timer_real_cr3) ¿é£º»Ö¸´ real CR3 + Çå×´Ì¬ + ½û CR3-load/store exiting
  - ×¢Òâ£º²»È«µ÷ stealth_pf_abort_shadow_window£¨»á³åÍ» MTF ºÍ #PF interception ÉèÖÃ£©
- Bug 4£¨write-protected reject ²» abort shadow window£©£ºept_stealth.cpp L1836
  - write #PF µ½ W=0 µÄ stealth Ò³ -> reject -> return FALSE ²» abort
  - mid-window Ê± -> shadow PTE W=0 -> write #PF µÝ¹é -> livelock
  - ÐÞ¸´£ºreturn FALSE Ç°¼Ó if (vcpu->nx_timer_real_cr3) stealth_pf_abort_shadow_window(vcpu);
- ÎÄ¼þ£ºOphion-master/src/ept_stealth.cpp, Ophion-master/src/vmexit.cpp
- ±àÒë£º_build2.bat ³É¹¦£¬Ophion.sys + TestEptHook.sys Ç©ÃûÍ¨¹ý
- ½áÂÛ£º4 ¸ö bug ÒÑÐÞ¸´²¢±àÒë£¬µÈ´ý He ¾ö¶¨ÊÇ·ñ²âÊÔ

### 2026-08-12 12:11  [session 38]
- ¶¯×÷£º½Ó¹Ü + ·ÖÎö W.log (7 CPU ¿¨ÔÚ 0x06) + ÐÞ¸´¸ùÒò + ±àÒë
- ¸ùÒò·ÖÎö£¨7 CPU ¿¨ÔÚ marker 0x06£©£º
  - stealth_refresh_shadow_code_pte ºÍ stealth_sync_data_pte_in_window ÖÐ
  - vmx_enter_cr3/vmx_leave_guest_cr3 ´°¿ÚÄÚÓÐ HYPERPLATFORM_LOG_WARN_SAFE µ÷ÓÃ
  - host #PF °²È«·¶Î§Ö»¸²¸Ç stealth_walk_pte + stealth_walk_pt_page
  - ÈÕÖ¾´úÂëµ÷ÓÃ LogpMakePrefix -> PsGetProcessImageFileName µÈ
  - Èç¹ûÕâÐ©º¯ÊýÔÚ guest CR3 + ÖÐ¶Ï½ûÓÃÏÂ´¥·¢ host #PF
  - RIP ²»ÔÚ°²È«·¶Î§ -> pf_panic -> jmp $ (ËÀÑ­»·) -> CPU ¿¨ËÀ
  - 7 ¸ö CPU Í¬Ê±¿¨ËÀ = ÏµÍ³¶³½á
- ÐÞ¸´1£¨¸ùÒò£©£ºÒÆ³ýÁ½¸ö CR3 ´°¿ÚÄÚµÄËùÓÐ HYPERPLATFORM_LOG_WARN_SAFE µ÷ÓÃ
  - stealth_refresh_shadow_code_pte: 5 ´¦ÈÕÖ¾ÒÆ³ý (shadow-pml4 diag, bail-realwalk, BAIL-noshadowpteva, code-sync, MATCH)
  - stealth_sync_data_pte_in_window: 2 ´¦ÈÕÖ¾ÒÆ³ý (cow-fix, data-sync)
  - ±£Áô£ºstealth_walk_pte (°²È«·¶Î§), shadow PTE Ð´ (NonPaged pool), INVVPID (VMXÖ¸Áî), CMOS markers (¶Ë¿ÚI/O), ¼ÆÊýÆ÷×ÔÔö (»¥ËøÄÚ´æÐ´)
  - ÐÂÔö CMOS markers 0x07 (pre-shadow-write) ºÍ 0x08 (post-shadow-write) ÓÃÓÚÕï¶Ï
- ÐÞ¸´2£¨´ÎÒª£©£ºFALSE-path breaker ÖØÖÃ g_wedge_pfloop_streak
  - Ö®Ç° FALSE-path breaker Ö»ÖØÖÃ reinj_streak ºÍ reinj_total£¬²»ÖØÖÃ pfloop_streak
  - µ¼ÖÂ pfloop_streak ³ÖÐøÔö³¤ -> Ã¿ 8 ´Î #PF ´¥·¢Ò»´Î CMOS snap (¶Ë¿Ú I/O)
  - 384 ´Î #PF = 48 ´Î CMOS snap = 576 ´Î¶Ë¿Ú I/O
  - W.log ÖÐ pf_err=0x180=384 Êµ¼ÊÊÇ pfloop_streak£¬²»ÊÇ reinj_streak
- ¹Ø¼ü·¢ÏÖ£ºW.log ÖÐ pf_err ×Ö¶Î´æ´¢µÄÊÇ streak Öµ£¨²»ÊÇ´íÎóÂë£©
  - wedge_cmos_snap_reinj ´æ´¢ pf_va=addr, pf_err=streak
  - pfloop ¼ì²âÆ÷ºÍ reinj ¼ì²âÆ÷¶¼Ð´Í¬Ò» CMOS ×Ö¶Î
  - pf_err=0x180=384 ÊÇ pfloop_streak£¨Î´±» FALSE breaker ÖØÖÃ£©£¬²»ÊÇ reinj_streak
  - reinj_streak ÔÚ 0?32 Ö®¼äÕñµ´£¨breaker Õý³£¹¤×÷£©
- ÎÄ¼þ£ºOphion-master/src/ept_stealth.cpp, Ophion-master/src/vmexit.cpp
- ±àÒë£º_build2.bat ³É¹¦£¬Ophion.sys + TestEptHook.sys Ç©ÃûÍ¨¹ý
- ½áÂÛ£ºCR3 ´°¿ÚÈÕÖ¾ÒÆ³ýÐÞ¸´ÒÑÍê³É£¬µÈ´ý²¿Êð²âÊÔ
### 2026-08-12 13:45  [session 35]
- ¶¯×÷£º·ÖÎö trigger Ê±ÁéÊ±²»Áé¸ùÒò + ÐÞ¸´ + ±àÒë
- ¸ùÒò£ºMTF handler ÓÅÏÈ¼¶·´×ª£¨ept_hook.cpp ept_handle_mtf£©
- ÐÞ¸´£ºpf_passthrough_armed + shadow_ept_wp_pending handler ÒÆ³ý early return£¬fall through µ½ mtf_restore_page
- ÎÄ¼þ£ºOphion-master/src/ept_hook.cpp
- ±àÒë£º_build2.bat ³É¹¦
- ½áÂÛ£ºtrigger flaky ¸ùÒòÒÑÐÞ¸´£¬µÈ´ý He ¾ö¶¨ÊÇ·ñ²âÊÔ

### 2026-08-12 10:26  [session 33]
- ¶¯×÷£º½Ó¹Ü + ·ÖÎö dump 081226-10578-01 + ×¼±¸²âÊÔ
- Dump ·ÖÎö£º0x0A IRQL_NOT_LESS_OR_EQUAL at nt!KeFlushMultipleRangeTb+0x142
- ¸ùÒòÁ´£º#PF@0x12 (shadow PT bug) -> WEDGE C-heal -> ÓÎÏ·±ÀÀ£ -> VAD teardown BSOD -> ÏµÍ³ reset

### 2026-08-12 10:15  [session 32]
- ¶¯×÷£º½Ó¹Ü + ¼ì²é git ×´Ì¬ + ÐÞ¸´ PROCESS.md ±àÂëËð»µ + Ìá½»

### 2026-08-12 09:51  [session 31]
- ¶¯×÷£º½Ó¹Ü + ·ÖÎöÀ¶ÆÁ dump + ÐÞ¸´ SEH + ±àÒë²¿Êð²âÊÔ
- ÐÞ¸´£ºbreadcrumb.cpp SEH °ü¹ü ZwWriteFile
- VMCALL streak ÅÅ³ýÐÞ¸´

## ¹Ø¼ü·¢ÏÖ
- **¡¾session 38¡¿CR3 ´°¿ÚÄÚ½ûÖ¹ HYPERPLATFORM_LOG_WARN_SAFE**£ºvmx_enter_cr3/vmx_leave_guest_cr3 ´°¿ÚÄÚÖ»ÄÜÓÐ stealth_walk_pte£¨°²È«·¶Î§£©¡¢shadow PTE Ð´£¨NonPaged pool£©¡¢INVVPID£¨VMX Ö¸Áî£©¡¢CMOS markers£¨¶Ë¿Ú I/O£©¡¢¼ÆÊýÆ÷×ÔÔö£¨»¥ËøÄÚ´æÐ´£©¡£ÈÎºÎÆäËûº¯Êýµ÷ÓÃ¶¼¿ÉÄÜ´¥·¢²»¿É»Ö¸´µÄ host #PF -> pf_panic -> jmp $ -> CPU ¿¨ËÀ¡£
- **¡¾session 38¡¿W.log pf_err ×Ö¶Î´æ´¢ streak Öµ**£ºwedge_cmos_snap_reinj ´æ´¢ pf_va=addr, pf_err=streak¡£pfloop ¼ì²âÆ÷ºÍ reinj ¼ì²âÆ÷¶¼Ð´Í¬Ò» CMOS ×Ö¶Î¡£pf_err=0x180=384 ÊÇ pfloop_streak¡£
- **¡¾session 38¡¿FALSE-path breaker ±ØÐëÖØÖÃ pfloop_streak**£ºÖ®Ç°Ö»ÖØÖÃ reinj_streak ºÍ reinj_total£¬µ¼ÖÂ pfloop_streak ³ÖÐøÔö³¤£¬Ã¿ 8 ´Î #PF ´¥·¢Ò»´Î CMOS snap¡£
- **¡¾session 37¡¿CR3 Ð¹Â© = ÏµÍ³¿¨ËÀ¸ùÒò**£ºstealth_refresh_shadow_code_pte µÄ eturn FALSE Ìø¹ý mx_leave_guest_cr3¡£renderdoc Ò³ page out ºó´¥·¢¡£ËùÓÐ vmx_enter_cr3/vmx_leave_guest_cr3 ¶ÔÖ®¼äµÄ early return ¶¼±ØÐëÏÈµ÷ leave¡£
- **¡¾session 37¡¿FALSE-path breaker ±ØÐë¶ÀÁ¢Çå shadow window**£º²»ÄÜÈ«µ÷ stealth_pf_abort_shadow_window£¨»á³åÍ» MTF ºÍ #PF interception£©£¬ÐèÒªÊÖ¶¯»Ö¸´ CR3 + Çå×´Ì¬ + ½û CR3-load/store exiting¡£
- **¡¾session 37¡¿write-protected reject Â·¾¶ (L1836) ÊÇ shadow window Ð¹Â©µÄ±ß½ç case**£ºept_stealth_handle_pf ÖÐÎ¨Ò»µÄ return FALSE ²» abort Â·¾¶£¨ÒÑÐÞ£©¡£
- **¡¾session 37¡¿ÓÃ»§Ì¬ livelock breaker È± total ¶µµ×**£ºÄÚºËÌ¬ÓÐ wtotal>=4£¬ÓÃ»§Ì¬Ö»ÓÐ ws>=32¡£½»ÌæµØÖ·ÓÀÔ¶µ½²»ÁË¡£
- **¡¾session 37¡¿stealth #PF handler È·Êµ¼ì²éÄ¿±êÒ³**£ºL1789 sp->guest_va != fault_page¡£µ«ÓÃ O(n) Á´±í±éÀú£¨2152+ ÌõÄ¿£©¡£ÓÃ shadow CR3 PTE NX Î»×ö O(1) ÅÐ¶ÏÊÇÓÐÐ§ÓÅ»¯·½Ïò£¨Éè¼Æ¸Ä½ø£¬·Ç bug£©¡£
- **¡¾session 31¡¿BC.log ºóÌ¨Ïß³Ì Ntfs AV**£ºSEH °ü¹ü½â¾ö¡£
- **¡¾session 31¡¿AutoReboot=1**£ºÀ¶ÆÁÒ»·ÖÖÓ×Ô¶¯ÖØÆô¡£Dump ÈÔÉú³É¡£
- **¡¾session 31¡¿breadcrumb.cpp ÊÇ UTF-8 BOM + LF**¡£
- **¡¾session 31¡¿VMCALL streak**£ºTdStealthFreePageSafe Ã¿Ò³¶ÔÈ«²¿ CPU ·¢ VMCALL¡£
- **¡¾session 31¡¿renderdoc ½ØÖ¡´¥·¢**£ºflag file C:\ProgramData\WinComp\capture.flag£¬²»ÒªÓÃ F12¡£
- **¡¾session 30¡¿MTF handler ·½Ïò·´×ª = ¿¨ËÀ¸ùÒò**£ºMODE_H ÏÂ MTF handler ±ØÐë shadow->shadow¡£
- **¡¾ÒÑÑéÖ¤¡¿MODE_G->MODE_H »Ø¹éÊÇ stale PFN ¸ùÒò**¡£
- **CFG ²»ÓÃÅö**£ºHe ÓÃ trigger ÈÆ CFG¡£
- **VMX-root Ô¼Êø**£ºÎÞ API¡¢ÎÞÎÄ¼þ I/O¡¢ÎÞ DbgPrint¡£Ö»ÄÜ»¥Ëø + ÄÚ´æÐ´ + VMX Ö¸Áî + ¶Ë¿Ú I/O + __invlpg + __writecr4¡£
- **USE_PRIVATE_HOST_CR3 = 1**£ºVMX-root ÅÜÔÚË½ÓÐ host CR3 ÉÏ¡£
- **BSOD »úÖÆ£¨da8fe39£©**£ºBugcheck=0xDEADC0DE¡£CMOS 0x50-0x6F ±ÀÀ£¼ÇÂ¼¡£
- **dual-EPT ²»ÄÜÌæ´ú shadow CR3**£ºguest PTE NX ÔÚ EPT Ö®Ç°±» CPU Ó²¼þ¼ì²é¡£
- **TdNeuterCFG / trigger ²»ÒªÅö**¡£
- **¹¹½¨**£º_build2.bat£¨/t:Rebuild£©£¬Debug ÅäÖÃ¡£
- **Æô¶¯Ë³Ðò**£º±ØÐë Ophion ÏÈ(VMXON) ÔÙ TestEptHook(VMCALL)¡£
- **AsmHostIdt.asm ±ØÐë ÎÞ BOM**¡£
- **¹Ø¼üÂ·¾¶**£º
  - ÏîÄ¿ F:\winDriver\te\Ophion-master
  - ¹¹½¨ Ophion-master\_build2.bat
  - Çý¶¯ build\bin\Debug\Ophion.sys, TestEptHook.sys
  - ×¢ÈëÆ÷ F:\winDriver\te\Ophion-master\Injector\inject_renderdoc.exe
  - renderdoc.dll F:\winDriver\te\renderdoc.dll
  - ÓÎÏ· E:\God of War Ragnarok\GoWR.exe
  - BC.log C:\Windows\BC.log
  - Ä£¿é¿ìÕÕ C:\Windows\MOD_SNAPSHOT2.txt
  - ·ûºÅ srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug

## ´ý°ì / ÏÂÒ»²½
1. ²¿Êð²âÊÔ£¨Í£Çý¶¯ -> killÓÎÏ· -> ²¿ÊðÐÂÇý¶¯ -> Æô¶¯Ophion -> Æô¶¯TestEptHook -> Ä£¿é¿ìÕÕ -> Æô¶¯ÓÎÏ· -> ×¢Èë -> flag file ´¥·¢½ØÖ¡£©
2. ÈçÈÔ¿¨ËÀ£º¼ì²é W.log ÐÂÔö markers 0x07/0x08 È·¶¨¿¨ËÀÎ»ÖÃ
3. Èç×¢Èë³É¹¦£º¼ì²é½ØÖ¡ÊÇ·ñÉú³É .rdc ÎÄ¼þ
4. £¨¿ÉÑ¡£©ÓÃ shadow CR3 PTE NX Î»ÓÅ»¯ stealth_pages Á´±í±éÀú£¨O(n) -> O(1)£©
>>>>>>> 3792be0 (fix(triple-fault): remove passthrough from breakers + stealth_real_va NULL fallback (session 41))
