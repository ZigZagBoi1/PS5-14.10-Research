-- CRASH_CLASS: LOW
-- PROBE 680a: map /dev/dmem0 and check the protection the VM map reports for
-- the resulting range, then dump the first 0x100 bytes as dwords. Read-only.
print("=== PROBE 680a: DMEM MAPPING AND REGISTER BLOCK ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc_open,sc_mmap=mk(5),mk(477)
local path=memory.alloc(0x20)
for i,p in ipairs({47,100,101,118,47,100,109,101,109,48,0}) do
  pcall(function() memory.write_byte(N(path)+i-1,p) end)
end
local fd=N(select(2,pcall(function() return sc_open(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
print(string.format("[A] open fd=%d",fd))
if fd<0 then return end
local addr=N(select(2,pcall(function() return sc_mmap(U(0),U(0x4000),U(3),U(0x1002),U(fd),U(0)) end)))
print(string.format("[B] mmap=0x%X",addr))
local R=memory.alloc(0x40000)
local n=N(select(2,pcall(function() return mk(674)(U(N(R)),U(72),U(512),U(N(R)+0x3F000),U(0x40000000),U(0)) end)))
local cnt=rd(N(R)+0x3F000) or 0
print(string.format("[C] regions=%s count=%d",tostring(n),cnt))
for i=0,math.min(cnt,400)-1 do
  local b=N(R)+i*72
  local s_lo,s_hi=rd(b) or 0,rd(b+4) or 0
  local e_lo=rd(b+8) or 0
  local st=s_hi*4294967296+s_lo
  if st<=addr and addr<st+0x4000 then
    print(string.format("[D] region %d start=0x%X end_lo=0x%X prot=%X",i,st,e_lo,rd(b+0x18) or 0))
  end
end
local out=""
for i=0,0xFC,4 do
  local v=rd(addr+i)
  if v then out=out..string.format("%08X ",v) end
  if (i+4)%16==0 then out=out.."\n" end
end
print(out)
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
