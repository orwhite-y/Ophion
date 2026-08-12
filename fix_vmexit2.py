import pathlib

p = pathlib.Path(r'F:\winDriver\te\Ophion-master\Ophion-master\src\vmexit.cpp')
f = p.read_text(encoding='latin-1')

replacements = []

# 5. pfloop breaker: force-narrow after manual shadow close
old5 = (
    '                            if (vcpu->nx_timer_real_cr3) {\n'
    '                                __vmx_vmwrite(VMCS_GUEST_CR3, vcpu->nx_timer_real_cr3);\n'
    '                                vcpu->nx_timer_restore = NULL;\n'
    '                                vcpu->nx_timer_real_cr3 = 0;\n'
    '                                vcpu->shadow_extended = FALSE;\n'
    '                                vcpu->shadow_pending = FALSE;\n'
    '                                vcpu->shadow_real_cr3 = 0;\n'
    '                                vcpu->shadow_cr3_val = 0;\n'
    '                            }\n'
    '                            // DON\'T disable #PF interception! Clearing the\n'
)
new5 = (
    '                            if (vcpu->nx_timer_real_cr3) {\n'
    '                                __vmx_vmwrite(VMCS_GUEST_CR3, vcpu->nx_timer_real_cr3);\n'
    '                                vcpu->nx_timer_restore = NULL;\n'
    '                                vcpu->nx_timer_real_cr3 = 0;\n'
    '                                vcpu->shadow_extended = FALSE;\n'
    '                                vcpu->shadow_pending = FALSE;\n'
    '                                vcpu->shadow_real_cr3 = 0;\n'
    '                                vcpu->shadow_cr3_val = 0;\n'
    '                            }\n'
    '                            FORCE_NXFETCH_PF_INTERCEPT();\n'
    '                            // DON\'T disable #PF interception! Clearing the\n'
)
replacements.append((old5, new5, 'pfloop-narrow'))

# 6. reinject breaker: force-narrow after manual shadow close (before if pf_error_code & 0x10)
old6 = (
    '                            if (vcpu->nx_timer_real_cr3) {\n'
    '                                __vmx_vmwrite(VMCS_GUEST_CR3, vcpu->nx_timer_real_cr3);\n'
    '                                vcpu->nx_timer_restore = NULL;\n'
    '                                vcpu->nx_timer_real_cr3 = 0;\n'
    '                                vcpu->shadow_extended = FALSE;\n'
    '                                vcpu->shadow_pending = FALSE;\n'
    '                                vcpu->shadow_real_cr3 = 0;\n'
    '                                vcpu->shadow_cr3_val = 0;\n'
    '                            }\n'
    '                            if (pf_error_code & 0x10)\n'
)
new6 = (
    '                            if (vcpu->nx_timer_real_cr3) {\n'
    '                                __vmx_vmwrite(VMCS_GUEST_CR3, vcpu->nx_timer_real_cr3);\n'
    '                                vcpu->nx_timer_restore = NULL;\n'
    '                                vcpu->nx_timer_real_cr3 = 0;\n'
    '                                vcpu->shadow_extended = FALSE;\n'
    '                                vcpu->shadow_pending = FALSE;\n'
    '                                vcpu->shadow_real_cr3 = 0;\n'
    '                                vcpu->shadow_cr3_val = 0;\n'
    '                            }\n'
    '                            FORCE_NXFETCH_PF_INTERCEPT();\n'
    '                            if (pf_error_code & 0x10)\n'
)
replacements.append((old6, new6, 'reinject-narrow'))

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
    print('All %d replacements done' % count)
else:
    print('Only %d/%d replaced, NOT writing' % (count, len(replacements)))
