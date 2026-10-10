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

;
; VBox defeat/v1 EPT-hook runtime plane ("remote call").
; ABI must match VBox include/VBox/vmm/EptHook.h:
;   rax = 'EPTH' (045505448h) | (op << 32)
;   rdx = arg0 (page-aligned target GPA)
;   rbx = arg1 (INSTALL: GvaTrigger)   rsi = arg2 (INSTALL: RCX cookie)
;   rdi = arg3 (INSTALL: GvaRedirect)
; VBox returns rax = VMM status (0 = ok, else VERR_* as UINT32),
; rdx = op result (slot index / query word), and skips the vmcall.
;
; UINT64 TdVmcallEptAsm(
;     UINT64 op,            ; rcx
;     UINT64 arg0,          ; rdx
;     UINT64 arg1,          ; r8   -> rbx
;     UINT64 arg2,          ; r9   -> rsi
;     UINT64 arg3,          ; [rsp+28h] -> rdi
;     UINT64 *out_result    ; [rsp+30h] receives VMM rdx
; );
; returns raw VMM rax.  Callers MUST wrap this in __try/__except: a VMM
; without the plane delivers #UD.
;
TdVmcallEptAsm PROC
    push    rbx
    push    rsi
    push    rdi
    ; entry stack: [rsp+28h]=arg3, [rsp+30h]=out_result
    ; after 3 pushes (18h): arg3=[rsp+40h], out_result=[rsp+48h]
    mov     r10, rcx
    shl     r10, 32
    mov     rax, 045505448h
    or      rax, r10
    mov     rbx, r8
    mov     rsi, r9
    mov     rdi, [rsp + 40h]
    mov     r11, [rsp + 48h]
    vmcall
    mov     [r11], rdx
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TdVmcallEptAsm ENDP

END
