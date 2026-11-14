-- CRASH_CLASS: LOW
-- PROBE 897a: does 662 actually delete, or are we calling it wrong? One id, polled
-- after every step. If the state survives a delete that returned 0x80020003, the
-- argument shape is wrong, not the kernel.
print("=== PROBE 897a: aio delete argument check ===")
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
local req=memory.alloc(0x28); zero(req,0x28)
local buf=memory.alloc(0x1000); zero(buf,0x1000)
local b=to_num(buf)
wd(req+0x08,0x1000); wd(req+0x10,b%4294967296); wd(req+0x14,math.floor(b/4294967296)); wd(req+0x20,fd)
local ids=memory.alloc(16); local st=memory.alloc(16); local er=memory.alloc(16)
local function poll(tag) zero(st,16); local ok,r=pcall(function() return mk(664)(uint64(ids),uint64(1),uint64(st)) end)
  print(string.format("    %-12s poll ret=%s st=%s",tag,tostring(ok and to_num(r) or "FAIL"),tostring(rd(st)))) return rd(st) end
zero(ids,16); zero(st,16)
local ok,r=pcall(function() return mk(669)(uint64(0x1001),uint64(req),uint64(1),uint64(3),uint64(ids)) end)
print(string.format("[2] submit ret=%s id=%X",tostring(ok and to_num(r) or "FAIL"),rd(ids) or 0))
poll("after submit")
for i=1,3 do
  zero(er,16)
  local o2,r2=pcall(function() return mk(662)(uint64(ids),uint64(1),uint64(er)) end)
  print(string.format("[3.%d] delete ret=%s errs=%X,%X,%X,%X",i,
     tostring(o2 and to_num(r2) or "FAIL"),rd(er) or 0,rd(er+4) or 0,rd(er+8) or 0,rd(er+12) or 0))
  poll("after delete"..i)
end
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
