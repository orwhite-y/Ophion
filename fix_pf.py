import pathlib

p = pathlib.Path(r'F:\winDriver\te\Ophion-master\Ophion-master\src\ept_stealth.cpp')
f = p.read_text(encoding='utf-8')

old1 = (
    '    // restore the NX-fetch-only #PF intercept (shadow swap does not widen).\n'
    '    // "all" for the duration of the window.\n'
    '    ept_update_pf_intercept(vcpu);'
)
new1 = (
    '    // Restore #PF intercept. ept_update_pf_intercept may widen to\n'
    '    // PFEC_PRESENT|PFEC_USER if need_write_pf=TRUE. Force-narrow to\n'
    '    // NX-fetch-only: data #PFs must NOT VM-exit after abort (reinject storm).\n'
    '    ept_update_pf_intercept(vcpu);\n'
    '    FORCE_NXFETCH_PF_INTERCEPT();'
)

old2 = (
    '    // Restore the NX-fetch-only #PF intercept (shadow swap does not widen).\n'
    '    // Restore the NX-fetch-only #PF intercept (shadow swap does not widen).\n'
    '    ept_update_pf_intercept(vcpu);'
)
new2 = (
    '    // Restore #PF intercept. Force-narrow to NX-fetch-only to prevent\n'
    '    // data #PF reinject storms after stale window clear.\n'
    '    ept_update_pf_intercept(vcpu);\n'
    '    FORCE_NXFETCH_PF_INTERCEPT();'
)

count = 0
for old, new, label in [(old1, new1, 'abort'), (old2, new2, 'clear_stale')]:
    if old in f:
        f = f.replace(old, new)
        count += 1
        print('OK - ' + label)
    else:
        print('NOT FOUND - ' + label)

if count == 2:
    p.write_text(f, encoding='utf-8')
    print('Both force-narrow added')
else:
    print('Only %d/2 replaced, NOT writing' % count)
