; asmVmxOperation.asm
; VMX enable, VMCALL interface

OPHION_VMCALL_ID EQU 04F5048494F4E4558h   ; 'OPHIONEX'

PUBLIC asm_enable_vmx
PUBLIC asm_vmx_vmcall

.code _text

asm_enable_vmx PROC
    xor     rax, rax
    mov     rax, cr4
    or      rax, 02000h         ; Set bit 13 (VMXE)
    mov     cr4, rax
    ret
asm_enable_vmx ENDP

; asm_vmx_vmcall(UINT64 vmcallNumber /*rcx*/, UINT64 param1 /*rdx*/,
;              UINT64 param2 /*r8*/, UINT64 param3 /*r9*/)
;
; uses rax = OPHION_VMCALL_ID so the VM-exit handler dispatches via
; the unified OPHION_VMCALL_ID path. rcx = vmcall number, rdx/r8/r9 = params.
; returns NTSTATUS in RAX (set by the VM-exit handler).

asm_vmx_vmcall PROC
    pushfq
    mov     rax, OPHION_VMCALL_ID
    vmcall
    popfq
    ret
asm_vmx_vmcall ENDP


END
