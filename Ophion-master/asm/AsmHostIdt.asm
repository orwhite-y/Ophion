; AsmHostIdt.asm
; private host IDT handlers for VMX-root mode
;
; Fatal host exceptions (#PF/#DF/#GP/other) route to the C panic
; (hv_host_pf_panic / hv_host_exc_panic) which stamps CMOS NVRAM + KeBugCheckEx.
; This replaces the old "add [rsp+8],1" (landed mid-instruction -> #UD -> freeze)
; and "cli;hlt" (silent freeze, no diagnostic). See hostidt.cpp for the layout.
;
; #PF special case: if the faulting RIP is inside the self-map walk safe range
; [g_pf_safe_start, g_pf_safe_end) AND that range is set (!= 0), the handler
; recovers: RAX=0 (not-present PTE for the caller), advance RIP by 3 (past the
; 3-byte "mov rax,[reg]" that faulted on an unmapped self-map VA). This lets
; stealth_walk_pte / stealth_walk_pt_page tolerate not-present intermediate
; entries without BSODing. If the safe range is unset (0) or RIP is outside it,
; the #PF is unexpected -> BSOD panic with CR2/RIP/err in the bugcheck params.
;
; The C panic never returns, so no register preservation is needed in the panic
; path. The recovery path preserves r10/r11 (pushed/popped) but NOT rax
; (intentionally set to 0 = not-present PTE for the caller).
;
; Stack frames (IST=0, error code present for #PF/#DF/#GP):
;   [rsp+0]  = error code   [rsp+8] = RIP   [rsp+16] = CS   [rsp+24] = RFLAGS
; For vectors without an error code (default handler): [rsp+0] = RIP, [rsp+8] = CS.

PUBLIC asm_host_nmi_handler
PUBLIC asm_host_df_handler
PUBLIC asm_host_gp_handler
PUBLIC asm_host_pf_handler
PUBLIC asm_host_default_handler

EXTERN g_host_nmi_pending:DWORD
EXTERN hv_host_pf_panic:PROC
EXTERN hv_host_exc_panic:PROC
EXTERN g_pf_safe_start:QWORD
EXTERN g_pf_safe_end:QWORD
EXTERN g_pf_recovery_count:DWORD

.code _text


; NMI handler sets per-cpu pending flag, vmexit handler injects to guest.
; (unchanged -- NMI is not fatal)

asm_host_nmi_handler PROC

    push    rax
    push    rcx

    mov     ecx, 0C0000103h            ; IA32_TSC_AUX -> cpu id (no memory access)
    rdmsr
    and     eax, 0FFFh

    lea     rcx, g_host_nmi_pending
    mov     dword ptr [rcx + rax*4], 1

    pop     rcx
    pop     rax
    iretq

asm_host_nmi_handler ENDP


; ---- fatal host exception trampolines ---------------------------------
; Win64 calling convention: arg1=RCX arg2=RDX arg3=R8 arg4=R9.
; hv_host_exc_panic(vector, rip, err)   hv_host_pf_panic(cr2, rip, err, cr3)
; We read err/rip from the frame BEFORE adjusting RSP (frame sits above us and
; is never touched again -- the panic never returns). sub 28h + and -10h yields a
; 16-aligned RSP with >=32 bytes shadow space below the original frame.

; #DF (vector 8, error code pushed)
asm_host_df_handler PROC
    mov     r8,  [rsp]                 ; err
    mov     rdx, [rsp+8]               ; rip
    mov     ecx, 8                     ; vector
    sub     rsp, 28h
    and     rsp, -10h
    call    hv_host_exc_panic
    jmp     $
asm_host_df_handler ENDP


; #GP (vector 13, error code pushed)
asm_host_gp_handler PROC
    mov     r8,  [rsp]                 ; err
    mov     rdx, [rsp+8]               ; rip
    mov     ecx, 13                    ; vector
    sub     rsp, 28h
    and     rsp, -10h
    call    hv_host_exc_panic
    jmp     $
asm_host_gp_handler ENDP


; catch-all for unexpected vectors. Assume NO error code ([rsp]=RIP, [rsp+8]=CS);
; pass both qwords so the dump captures RIP regardless of an error-code presence.
asm_host_default_handler PROC
    mov     rdx, [rsp]                 ; rip (no err) / err (if one was pushed)
    mov     r8,  [rsp+8]               ; cs / rip
    mov     ecx, 0FFh                  ; vector = unknown
    sub     rsp, 28h
    and     rsp, -10h
    call    hv_host_exc_panic
    jmp     $
asm_host_default_handler ENDP


; #PF (vector 14, error code pushed). CR2 = fault VA, CR3 = active host CR3.
; If RIP is in the self-map walk safe range (and range is set): recover.
; Otherwise: BSOD panic with cr2/rip/err/cr3.
asm_host_pf_handler PROC
    mov     rax, [rsp+8]               ; faulting RIP (read before any push)
    push    r10
    push    r11

    ; Check if safe range is set (g_pf_safe_start == 0 -> empty -> panic)
    lea     r10, g_pf_safe_start
    mov     r11, [r10]
    test    r11, r11
    jz      pf_panic
    cmp     rax, r11
    jb      pf_panic
    lea     r10, g_pf_safe_end
    mov     r11, [r10]
    cmp     rax, r11
    jae     pf_panic

    ; In safe range: recover. RAX=0 (not-present PTE for the caller).
    xor     rax, rax
    lea     r10, g_pf_recovery_count
    lock inc dword ptr [r10]
    pop     r11
    pop     r10
    add     qword ptr [rsp+8], 3       ; advance RIP past 3-byte mov
    add     rsp, 8                     ; discard error code
    iretq

pf_panic:
    pop     r11
    pop     r10
    mov     r8,  [rsp]                 ; err
    mov     rdx, rax                   ; rip (preserved through check)
    mov     rcx, cr2                   ; arg1 = cr2 (fault VA)
    mov     r9,  cr3                   ; arg4 = cr3
    sub     rsp, 28h
    and     rsp, -10h
    call    hv_host_pf_panic
    jmp     $
asm_host_pf_handler ENDP

END