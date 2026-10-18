from pathlib import Path
import re,json
root=Path('F:/PS5-14.10-Research');out=Path(__file__).parent
p=root/'results/51b_accessible_syscall_deep_20261016_214832.txt';rows=[]
for n in range(627,677):
 hits=[]
 for i,l in enumerate(p.read_text(encoding='utf-8').splitlines(),1):
  if re.search(r'^\s*'+str(n)+r'\(',l) and 'ret=' in l:hits.append({'path':str(p),'line':i,'recorded_text':l.strip()})
 rows.append({'selector':n,'evidence':hits,'status':'RETURN_RECORDED' if hits else 'NO_RETURN_IN_THIS_COMPLETED_LOG','limitation':'This is one explicitly reviewed completed log, not exhaustive corpus coverage; ABI and name not established.'})
(out/'COVERAGE_627_676.json').write_text(json.dumps(rows,indent=2));print('Selectors with recorded returns in this completed log:',[x['selector'] for x in rows if x['evidence']])
