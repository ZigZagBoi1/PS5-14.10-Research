-- CRASH_CLASS: LOW
-- PROBE 898a: which aio step kills the process? 896a died at round 4 with only two
-- in-flight objects refused per round. Three stages, safest first, each instrumented,
-- so the death point names the operation instead of the round.
print("=== PROBE 898a: aio step bisect ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local pid=to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print("[0] pid="..pid)
local sv=memory.alloc(8); zero(sv,8)
pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd=rd(sv); print("[1] socketpair fd="..tostring(fd))
local N=2
local reqs=memory.alloc(0x28*N); zero(reqs,0x28*N)
local buf=memory.alloc(0x1000); zero(buf,0x1000)
local b=to_num(buf)
for i=0,N-1 do local r=reqs+i*0x28
  wd(r+0x08,0x1000); wd(r+0x10,b%4294967296); wd(r+0x14,math.floor(b/4294967296)); wd(r+0x20,fd) end
local ids=memory.alloc(16); local st=memory.alloc(16); local er=memory.alloc(16)
local function submit(tag)
  zero(ids,16); zero(st,16)
  local o,r=pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end)
  print(string.format("    %-10s submit ret=%-3s ids=%X,%X",tag,tostring(o and to_num(r) or "FAIL"),rd(ids) or 0,rd(ids+8) or 0))
  return o
end
local function poll(tag)
  zero(st,16)
  local o,r=pcall(function() return mk(664)(uint64(ids),uint64(N),uint64(st)) end)
  print(string.format("    %-10s poll   ret=%-3s st=%s,%s",tag,tostring(o and to_num(r) or "FAIL"),tostring(rd(st)),tostring(rd(st+4))))
end
print("[A] submit + poll only")
for round=1,6 do submit("A"..round) poll("A"..round) end
print("[A] survived 6 rounds")
print("[B] submit + cancel + poll")
local function cancel(tag)
  local o,r=pcall(function() return mk(666)(uint64(ids),uint64(N),uint64(st)) end)
  print(string.format("    %-10s cancel ret=%-3s st=%s,%s",tag,tostring(o and to_num(r) or "FAIL"),tostring(rd(st)),tostring(rd(st+4))))
end
for round=1,3 do submit("B"..round) cancel("B"..round) poll("B"..round) end
print("[B] survived 3 rounds")
print("[C] submit + cancel + poll + delete")
for round=1,3 do
  submit("C"..round) cancel("C"..round) poll("C"..round)
  zero(er,16)
  local o,r=pcall(function() return mk(662)(uint64(ids),uint64(N),uint64(er)) end)
  print(string.format("    %-10s delete ret=%-3s errs=%X,%X","C"..round,tostring(o and to_num(r) or "FAIL"),rd(er) or 0,rd(er+4) or 0))
  poll("C"..round)
end
print("[C] survived 3 rounds")
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
