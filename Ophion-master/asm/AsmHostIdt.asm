; AsmHostIdt.asm
; private host IDT handlers for VMX-root mode

PUBLIC asm_host_nmi_handler
PUBLIC asm_host_df_handler
PUBLIC asm_host_gp_handler
PUBLIC asm_host_pf_handler
PUBLIC asm_host_default_handler

EXTERN g_host_nmi_pending:DWORD

.code _text


; NMI handler ??sets per-cpu pending flag, vmexit handler injects to guest

asm_host_nmi_handler PROC

    push    rax
    push    rcx

    ; get cpu id from IA32_TSC_AUX (no memory access needed)
    mov     ecx, 0C0000103h
    rdmsr
    and     eax, 0FFFh

    lea     rcx, g_host_nmi_pending
    mov     dword ptr [rcx + rax*4], 1

    pop     rcx
    pop     rax
    iretq

asm_host_nmi_handler ENDP


; #DF in host mode = unrecoverable, halt

asm_host_df_handler PROC

    cli
    hlt
    jmp     $

asm_host_df_handler ENDP


; #GP in host mode = bug, halt

asm_host_gp_handler PROC

    cli
    hlt
    jmp     $

asm_host_gp_handler ENDP


; catch-all for unexpected vectors, halt

asm_host_default_handler PROC

    cli
    hlt
    jmp     $

asm_host_default_handler ENDP


; #PF in host mode = skip faulting instruction (best effort survival)
; Stack frame (64-bit, IST=0):
;   [rsp+0]  = error code
;   [rsp+8]  = RIP
;   [rsp+16] = CS
;   [rsp+24] = RFLAGS
;   [rsp+32] = RSP
;   [rsp+40] = SS

asm_host_pf_handler PROC

    add     qword ptr [rsp + 8], 1     ; advance RIP past faulting instr
    add     rsp, 8                     ; discard error code
    iretq

asm_host_pf_handler ENDP

END
