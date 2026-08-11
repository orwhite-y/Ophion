; AsmHostIdt.asm
; private host IDT handlers for VMX-root mode
;
; Fatal host exceptions (#PF/#DF/#GP/other) now route to the C panic
; (hv_host_pf_panic / hv_host_exc_panic) which stamps CMOS NVRAM + KeBugCheckEx.
; This replaces the old "add [rsp+8],1" (landed mid-instruction -> #UD -> freeze)
; and "cli;hlt" (silent freeze, no diagnostic). See hostidt.cpp for the layout.
;
; The C panic never returns, so no register preservation is needed: we only set
; up a 16-byte-aligned stack with 32 bytes of shadow space and tail-call it.
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
asm_host_pf_handler PROC
    mov     r8,  [rsp]                 ; err
    mov     rdx, [rsp+8]               ; rip
    mov     rcx, cr2                   ; arg1 = cr2 (fault VA)
    mov     r9,  cr3                   ; arg4 = cr3
    sub     rsp, 28h
    and     rsp, -10h
    call    hv_host_pf_panic
    jmp     $
asm_host_pf_handler ENDP

END