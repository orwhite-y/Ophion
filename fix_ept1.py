import pathlib

p = pathlib.Path(r'F:\winDriver\te\Ophion-master\Ophion-master\src\ept_stealth.cpp')
f = p.read_text(encoding='utf-8')

replacements = []

# L1373: after stealth page registration
old1 = '            if (existing->fake_pt || existing->shadow_cr3_phys)\n                ept_update_pf_intercept(vcpu);'
new1 = '            if (existing->fake_pt || existing->shadow_cr3_phys)\n            {\n                ept_update_pf_intercept(vcpu);\n                FORCE_NXFETCH_PF_INTERCEPT();\n            }'
# This pattern appears twice (L1373 and L1458) - replace both
replacements.append((old1, new1, 'reg_existing', -1))

# L1555: after EPT hook setup
old2 = '        ept_update_pf_intercept(vcpu);\n        break;'
new2 = '        ept_update_pf_intercept(vcpu);\n        FORCE_NXFETCH_PF_INTERCEPT();\n        break;'
replacements.append((old2, new2, 'hook_setup', 1))

# L1696: after InsertHeadList
old3 = '    if (sp->fake_pt || sp->shadow_cr3_phys)\n        ept_update_pf_intercept(vcpu);'
new3 = '    if (sp->fake_pt || sp->shadow_cr3_phys)\n    {\n        ept_update_pf_intercept(vcpu);\n        FORCE_NXFETCH_PF_INTERCEPT();\n    }'
replacements.append((old3, new3, 'insert_head', 1))

# L2517: after cleanup
old4 = '    ept_invept_single(vcpu->ept_pointer);\n    ept_update_pf_intercept(vcpu);'
new4 = '    ept_invept_single(vcpu->ept_pointer);\n    ept_update_pf_intercept(vcpu);\n    FORCE_NXFETCH_PF_INTERCEPT();'
replacements.append((old4, new4, 'cleanup', 1))

count = 0
for old, new, label, maxreplace in replacements:
    n = f.count(old)
    if n > 0:
        if maxreplace == -1:
            f = f.replace(old, new)
            count += n
        else:
            f = f.replace(old, new, maxreplace)
            count += min(n, maxreplace)
        print('OK - %s (%d occurrences)' % (label, n if maxreplace == -1 else min(n, maxreplace)))
    else:
        print('NOT FOUND - ' + label)

p.write_text(f, encoding='utf-8')
print('Total %d replacements done' % count)
