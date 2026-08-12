import pathlib

p = pathlib.Path(r'F:\winDriver\te\Ophion-master\Ophion-master\src\vmexit.cpp')
f = p.read_text(encoding='latin-1')

replacements = []

# 1. CR3-load reactivate: add WIDEN after restoring guard state
old1 = (
    '                    // Restore guard state.\n'
    '                    vcpu->nx_timer_real_cr3 = vcpu->shadow_real_cr3;\n'
    '                    // #PF intercept stays NX-fetch-only (NEVER widened).\n'
    '                    // Data #PFs during shadow window are handled by guest\n'
    '                    // natively under shadow CR3.\n'
)
new1 = (
    '                    // Restore guard state.\n'
    '                    vcpu->nx_timer_real_cr3 = vcpu->shadow_real_cr3;\n'
    '                    // Widen #PF intercept: data #PFs during shadow window\n'
    '                    // MUST VM-exit so we can abort before KiPageFault runs\n'
    '                    // under shadow CR3 (PFN db corruption -> 0x1A BSOD).\n'
    '                    WIDEN_PF_INTERCEPT();\n'
)
replacements.append((old1, new1, 'reactivate-widen'))

# 2. CR3-load PENDING: force-narrow after ept_update_pf_intercept
old2 = (
    '                    // Clear guard + narrow #PF (other processes must not VM-exit).\n'
    '                    vcpu->nx_timer_real_cr3 = 0;\n'
    '                    ept_update_pf_intercept(vcpu);\n'
)
new2 = (
    '                    // Clear guard + narrow #PF (other processes must not VM-exit).\n'
    '                    vcpu->nx_timer_real_cr3 = 0;\n'
    '                    ept_update_pf_intercept(vcpu);\n'
    '                    FORCE_NXFETCH_PF_INTERCEPT();\n'
)
replacements.append((old2, new2, 'pending-narrow'))

# 3. pf_passthrough_armed restore: force-narrow
old3 = (
    '                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc3);\n'
    '                ept_update_pf_intercept(vcpu);\n'
    '            }\n'
    '#endif\n'
)
new3 = (
    '                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc3);\n'
    '                ept_update_pf_intercept(vcpu);\n'
    '                FORCE_NXFETCH_PF_INTERCEPT();\n'
    '            }\n'
    '#endif\n'
)
replacements.append((old3, new3, 'passthrough-narrow'))

# 4. Storm breaker: force-narrow after ept_update_pf_intercept
# Need to find the right context - it's after the storm breaker's ept_update_pf_intercept
old4 = (
    '                ept_update_pf_intercept(vcpu);\n'
    '                _InterlockedExchange(&g_wedge_reason_streak[wcpu], 0);\n'
)
new4 = (
    '                ept_update_pf_intercept(vcpu);\n'
    '                FORCE_NXFETCH_PF_INTERCEPT();\n'
    '                _InterlockedExchange(&g_wedge_reason_streak[wcpu], 0);\n'
)
replacements.append((old4, new4, 'storm-breaker-narrow'))

count = 0
for old, new, label in replacements:
    if old in f:
        f = f.replace(old, new, 1)
        count += 1
        print('OK - ' + label)
    else:
        print('NOT FOUND - ' + label)

if count == len(replacements):
    p.write_text(f, encoding='latin-1')
    print('All %d vmexit.cpp replacements done' % count)
else:
    print('Only %d/%d replaced, NOT writing' % (count, len(replacements)))
