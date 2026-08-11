; AsmCommon.asm
; common assembly routines

PUBLIC asm_get_rflags
PUBLIC asm_reload_gdtr
PUBLIC asm_reload_idtr
PUBLIC asm_reload_tr
PUBLIC asm_read_cr2
PUBLIC asm_write_cr2

.code _text


asm_get_rflags PROC
    pushfq
    pop     rax
    ret
asm_get_rflags ENDP

asm_reload_gdtr PROC
    push    rcx
    shl     rdx, 48
    push    rdx
    lgdt    fword ptr [rsp+6]
    pop     rax
    pop     rax
    ret
asm_reload_gdtr ENDP

asm_reload_idtr PROC
    push    rcx
    shl     rdx, 48
    push    rdx
    lidt    fword ptr [rsp+6]
    pop     rax
    pop     rax
    ret
asm_reload_idtr ENDP

asm_reload_tr PROC
    ltr     cx
    ret
asm_reload_tr ENDP

asm_read_cr2 PROC
    mov     rax, cr2
    ret
asm_read_cr2 ENDP

asm_write_cr2 PROC
    mov     cr2, rcx
    ret
asm_write_cr2 ENDP

PUBLIC asm_selfmap_read

; UINT64 asm_selfmap_read(UINT64 addr)
; rcx = address to read. Returns [rcx] in rax.
; MUST be exactly: mov rax,[rcx] (3 bytes: 48 8B 01) + ret (1 byte: C3)
; The host #PF handler matches this exact instruction: sets rax=0, advances RIP by 3.
asm_selfmap_read PROC
    mov     rax, [rcx]
    ret
asm_selfmap_read ENDP


END