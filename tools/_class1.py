
import json, re
from collections import Counter
res = json.load(open(r'C:\PS5contrib\tools\_copyin_census_raw.json'))
c = Counter()
for r in res:
    lw=r['last_write']
    m=lw['mnem']
    op=lw['op']
    if m=='lea':
        mm = re.match(r'rsi, \[(rip [+\-] 0x[0-9a-f]+|[a-z0-9]+(?: [+\-] [a-z0-9]+)?(?: [*] [0-9]+)?)', op)
        if 'rip' in op: c['lea rsi, [rip+..] (global/rodata)']+=1
        elif re.match(r'rsi, \[(rbp|rsp)', op): c['lea rsi, [rbp/rsp..] (stack)']+=1
        else: c['lea rsi, [<reg>..] (object-ish)']+=1
    elif m=='mov':
        m2 = re.match(r'(rsi|esi), (.*)', op)
        dst, src = m2.group(1), m2.group(2)
        if dst=='esi':
            c['mov esi, imm/other']+=1
        elif re.match(r'\[', src):
            c['mov rsi, [mem]']+=1
        elif re.fullmatch(r'r[a-z0-9]+|e[a-z]+', src):
            c['mov rsi, reg']+=1
        else:
            c['mov rsi, misc:'+src[:20]]+=1
    else:
        c['other:'+m+' '+op[:30]]+=1
for k,v in c.most_common(): print(v, k)
print('---- sample of object-ish lea ----')
n=0
for r in res:
    lw=r['last_write']
    if lw['mnem']=='lea' and 'rip' not in lw['op'] and not lw['op'].startswith('rsi, [rbp') and not lw['op'].startswith('rsi, [rsp'):
        print(hex(r['site']), lw['mnem'], lw['op'])
        n+=1
        if n>=30: break
