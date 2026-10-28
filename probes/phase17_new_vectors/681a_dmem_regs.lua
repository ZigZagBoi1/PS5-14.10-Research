-- CRASH_CLASS: MODERATE
-- PROBE 681a: map /dev/dmem0 offset 0 the way 599a did (MAP_SHARED=1, prot RW),
-- dump 0x100 bytes, then write each qword back unchanged and confirm the
-- read-back. Nothing is changed in the register block.
print("=== PROBE 681a: DMEM REGISTER BLOCK (READ, THEN SAME-VALUE WRITE) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function wq(a,v) local o=pcall(function() memory.write_qword(uint64(string.format("0x%08X%08X",math.floor(v/4294967296),v%4294967296))) if false then end end) end
local function WQ(a,v)
  local ok=pcall(function()
    local lo=uint64(string.format("0x%X",v%4294967296))
    local hi=uint64(string.format("0x%X",math.floor(v/4294967296)))
    local x=uint64(string.format("0x%08X%08X",math.floor(v/4294967296),v%4294967296))
    memory.write_qword(uint64(string.format("0x%X",a)), x)
  end)
  return ok
end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
print(string.format("[A] fd=%d",fd))
local addr=N(select(2,pcall(function() return mk(477)(U(0),U(0x4000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[B] mmap=0x%X",addr))
if addr==0 or addr>0xFFFFFFFF then
  local base=addr
  for i=0,0x1F do
    local a=base+i*8
    local v=rq(a)
    print(string.format("  +%03X %016X",i*8,v or 0))
  end
  print("[C] writing each qword back unchanged")
  local bad=0
  for i=0,7 do
    local a=base+i*8
    local v=rq(a)
    if v then
      local ok=WQ(a,v)
      local v2=rq(a)
      if not ok or v2~=v then bad=bad+1; print(string.format("  +%03X wrote %016X back=%016X ok=%s",i*8,v,v2 or 0,tostring(ok))) end
    end
  end
  print(string.format("[D] mismatches=%d",bad))
else
  print("[B] mmap refused, nothing mapped")
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
