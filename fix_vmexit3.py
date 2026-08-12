import pathlib

p = pathlib.Path(r'F:\winDriver\te\Ophion-master\Ophion-master\src\vmexit.cpp')
f = p.read_text(encoding='latin-1')

replacements = []

# L1350: after free_all + unhook_all - all pages gone, force-narrow harmless but consistent
old1 = '            ept_stealth_free_all();\n            ept_unhook_all();\n            ept_update_pf_intercept(vcpu);\n            ept_invept_single(vcpu->ept_pointer);'
new1 = '            ept_stealth_free_all();\n            ept_unhook_all();\n            ept_update_pf_intercept(vcpu);\n            FORCE_NXFETCH_PF_INTERCEPT();\n            ept_invept_single(vcpu->ept_pointer);'
replacements.append((old1, new1, 'free_all'))

# L1366: after free_by_cr3
old2 = '            stealth_clear_stale_window(vcpu);\n            ept_stealth_free_by_cr3(free_cr3);\n            ept_update_pf_intercept(vcpu);\n            ept_invept_single(vcpu->ept_pointer);'
new2 = '            stealth_clear_stale_window(vcpu);\n            ept_stealth_free_by_cr3(free_cr3);\n            ept_update_pf_intercept(vcpu);\n            FORCE_NXFETCH_PF_INTERCEPT();\n            ept_invept_single(vcpu->ept_pointer);'
replacements.append((old2, new2, 'free_by_cr3'))

# L1471: fake PT setup in VMCALL
old3 = '                        if (pp1) pp1->AsUInt = ex->fake_pt->pt_fake_entry.AsUInt;\n\n                        ept_update_pf_intercept(vcpu);\n                    }'
new3 = '                        if (pp1) pp1->AsUInt = ex->fake_pt->pt_fake_entry.AsUInt;\n\n                        ept_update_pf_intercept(vcpu);\n                        FORCE_NXFETCH_PF_INTERCEPT();\n                    }'
replacements.append((old3, new3, 'vmcall_fakept'))

# L1511: injection setup
old4 = '                if (inj->pt_page_pfn && inj->pt_page_copy)\n                {\n                        ept_update_pf_intercept(vcpu);\n                }'
new4 = '                if (inj->pt_page_pfn && inj->pt_page_copy)\n                {\n                        ept_update_pf_intercept(vcpu);\n                        FORCE_NXFETCH_PF_INTERCEPT();\n                }'
replacements.append((old4, new4, 'inj_setup'))

# L1668: EPT violation fake PT
old5 = '            if (hp->fake_pt && hp->exec_pt_page)\n            {\n                pte->AsUInt = hp->changed_entry.AsUInt;\n\n                ept_update_pf_intercept(vcpu);\n            }'
new5 = '            if (hp->fake_pt && hp->exec_pt_page)\n            {\n                pte->AsUInt = hp->changed_entry.AsUInt;\n\n                ept_update_pf_intercept(vcpu);\n                FORCE_NXFETCH_PF_INTERCEPT();\n            }'
replacements.append((old5, new5, 'ept_violation_fakept'))

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
