;
;   vmcall.asm — Ophion EPT hook VMCALL (模仿 UnrealVTDbg 的 __vm_call_ex)
;   rax = identifier, rcx-r9 = 前4个参数, r10-r15 = 后6个参数(从栈加载)
;

OPHION_VMCALL_ID EQU 04F5048494F4E4558h   ; 'OPHIONEX'

.code

;
; bool hv_vmcall_ex(
;     u64 vmcall_reason,   ; rcx
;     u64 param1,          ; rdx
;     u64 param2,          ; r8
;     u64 param3,          ; r9
;     u64 param4,          ; stack → r10
;     u64 param5,          ; stack → r11
;     u64 param6,          ; stack → r12
;     u64 param7,          ; stack → r13
;     u64 param8,          ; stack → r14
;     u64 param9           ; stack → r15
; )
;
hv_vmcall_ex PROC
    ; PITFALL #4: r12-r15 are callee-saved. MUST push/pop or caller crashes after vmcall returns.
    ; 保存非易失性寄存器 (r12-r15)
    push    r12
    push    r13
    push    r14
    push    r15

    ; PITFALL #3: Use rax as identifier (not r10/r11/r12) so r10-r15 are free for parameters.
    ; rax = Ophion identifier
    mov     rax, OPHION_VMCALL_ID

    ; 从栈加载 param4-param9 到 r10-r15
    ; 4 pushes = 0x20, 原始 stack 参数从 [rsp+28h] 开始
    ; 现在偏移: [rsp + 28h + 20h] = [rsp + 48h]
    mov     r10, [rsp + 48h]    ; param4
    mov     r11, [rsp + 50h]    ; param5
    mov     r12, [rsp + 58h]    ; param6
    mov     r13, [rsp + 60h]    ; param7
    mov     r14, [rsp + 68h]    ; param8
    mov     r15, [rsp + 70h]    ; param9

    vmcall

    ; rax = 返回值 (由 VMX-root handler 设置)

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    ret
hv_vmcall_ex ENDP

;
; simple 4-param vmcall (like Ophion's asm_vmx_vmcall).
; no push/pop of r12-r15, no stack parameter loading.
; avoids register pressure issues that corrupt DPC A1/A2.
;
; bool hv_vmcall_simple(
;     u64 vmcall_reason,   ; rcx
;     u64 param1,          ; rdx
;     u64 param2,          ; r8
;     u64 param3           ; r9
; )
;
hv_vmcall_simple PROC
    pushfq
    mov     rax, OPHION_VMCALL_ID
    vmcall
    popfq
    ret
hv_vmcall_simple ENDP

END
