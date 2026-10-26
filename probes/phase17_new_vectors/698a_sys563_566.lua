-- CRASH_CLASS: MODERATE
-- PROBE 698a: four unidentified syscalls. 563/564 take one dword (a pid) and
-- do a privilege check then a pfind; 565/566 take (pid, index<6, address),
-- which is the shape of debug-register or watchpoint control. Test our own pid
-- and a few system pids first.
print("=== PROBE 698a: SYS 563/564/565/566 ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("[A] our pid=%d",pid))
local page=memory.alloc(0x100)
local function zero() for i=0,0xFC,4 do pcall(function() memory.write_dword(N(page)+i,0xDEADBEEF) end) end end
for _,target in ipairs({pid,1,2,7,100}) do
  for _,num in ipairs({563,564}) do
    zero()
    local o,r=pcall(function() return mk(num)(U(target),U(N(page)),U(0x100),U(0),U(0),U(0)) end)
    print(string.format("[B] %d(%d) ok=%s rv=%s p0=%08X p4=%08X",num,target,tostring(o),tostring(r),rd(N(page)) or 0,rd(N(page)+4) or 0))
  end
end
for _,target in ipairs({pid,1}) do
  for _,num in ipairs({565,566}) do
    for idx=0,5 do
      local o,r=pcall(function() return mk(num)(U(target),U(idx),U(0x310700000),U(0),U(0),U(0)) end)
      print(string.format("[C] %d(pid=%d,idx=%d,addr) ok=%s rv=%s",num,target,idx,tostring(o),tostring(r)))
    end
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
