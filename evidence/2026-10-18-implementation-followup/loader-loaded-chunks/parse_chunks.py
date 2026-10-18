from pathlib import Path
import struct,json
p=Path(__file__).parent
names='MOVE LOADK LOADBOOL LOADNIL GETUPVAL GETGLOBAL GETTABLE SETGLOBAL SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORLOOP SETLIST CLOSE CLOSURE VARARG'.split()
class Reader:
 def __init__(self,b):
  self.b=b;assert b[:6]==b'\x1bLua\x51\0';assert b[6:12]==bytes([1,4,8,4,8,0]);self.i=12
 def take(self,n):
  x=self.b[self.i:self.i+n];assert len(x)==n;self.i+=n;return x
 def u(self,n=4):return int.from_bytes(self.take(n),'little')
 def s(self):
  n=self.u(8)
  if not n:return None
  x=self.take(n);assert x[-1]==0;return x[:-1].decode('utf-8',errors='replace')
 def fun(self):
  src=self.s();lo=self.u();hi=self.u();meta=list(self.take(4));code=[self.u() for _ in range(self.u())]; duplicate=[self.u() for _ in range(self.u())];assert duplicate==code;ks=[]
  for _ in range(self.u()):
   t=self.u(1)
   if t==0:v=None
   elif t==1:v=bool(self.u(1))
   elif t==3:v=struct.unpack('<d',self.take(8))[0]
   elif t==4:v=self.s()
   else:raise ValueError(t)
   ks.append(v)
  sub=[self.fun() for _ in range(self.u())];line=[self.u() for _ in range(self.u())];loc=[{'name':self.s(),'start':self.u(),'end':self.u()} for _ in range(self.u())];up=[self.s() for _ in range(self.u())]
  ops=[]
  for pc,x in enumerate(code):
   op=x&63;bx=x>>14;row={'pc':pc,'opcode':names[op] if op<len(names) else str(op),'a':(x>>6)&255,'b':x>>23,'c':(x>>14)&511,'line':line[pc] if pc<len(line) else None}
   if op in (1,5,7):row['constant_index']=bx;row['constant']=ks[bx] if bx<len(ks) else 'OUT_OF_RANGE'
   if op in (22,31,32):row['branch_target_pc']=pc+1+bx-131071
   ops.append(row)
  return {'source':src,'line_start':lo,'line_end':hi,'upvalues':meta[0],'parameters':meta[1],'vararg':meta[2],'maxstack':meta[3],'constants':ks,'instruction_count':len(code),'observed_format_extension':'second identical instruction vector present; semantics unknown','instructions':ops,'nested_functions':sub,'local_names':loc,'upvalue_names':up}
items=[]
for f in p.glob('*.luac.bin'):
 r=Reader(f.read_bytes());d=r.fun();assert r.i==len(r.b);d['file']=f.name;d['limitation']='Lua serialization parsed as data only, not native machine code or firmware attestation';items.append(d)
(p/'PARSED_LUA_CHUNKS.json').write_text(json.dumps(items,indent=2));print(json.dumps([{'file':x['file'],'source':x['source'],'lines':[x['line_start'],x['line_end']],'instructions':x['instruction_count'],'globals':[v['constant'] for v in x['instructions'] if v['opcode']=='GETGLOBAL'],'constants':x['constants']} for x in items],indent=2))
