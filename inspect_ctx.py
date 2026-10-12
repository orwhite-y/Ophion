import os
out = r'F:\winDriver\te\Ophion-master\qrd_ctx.txt'
with open(out, 'w', encoding='utf-8') as f:
    f.write('type=%r\n' % type(pyrenderdoc))
    f.write('\n'.join(sorted(dir(pyrenderdoc))))
print('dumped')
