-- CRASH_CLASS: HIGH
-- PROBE 694a: after mapping dmem0, what does the VM map say the region is?
-- Name, protection and extent identify whether it is VRAM, a DMA buffer or
-- plain user memory. Then one canary inside the mapping only.
print("=== PROBE 694a: DMEM REGION IDENTITY ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return 0 end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x10000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[A] fd=%d base=0x%X",fd,base))
if base==0 or base>0x800000000000 then print("[Z] no map") return end
local buf=memory.alloc(0x20000)
local cnt=memory.alloc(8)
pcall(function() memory.write_dword(N(cnt),0) end)
local r=N(select(2,pcall(function() return mk(674)(U(N(buf)),U(72),U(512),U(N(cnt)),U(0x40000000),U(0)) end)))
print(string.format("[B] 674 ret=%s count=%d",tostring(r),rd(N(cnt))))
local n=rd(N(cnt))
for i=0,math.min(n,511) do
  local rec=N(buf)+i*72
  local slo,s_hi=rd(rec),rd(rec+4)
  local elo,e_hi=rd(rec+8),rd(rec+0xC)
  local prot=rd(rec+0x18)
  local s=s_hi*4294967296+slo
  local e=e_hi*4294967296+elo
  if base>=s and base<e then
    local name=""
    for k=0,31 do
      local b=rd(rec+0x20+k)
      if b==0 then break end
      if b>=32 and b<127 then name=name..string.char(b) end
    end
    print(string.format("[C] region %X-%X prot=%X name=%s",s,e,prot,name))
  end
end
-- one canary inside the mapping
pcall(function() memory.write_qword(base+0x8000,uint64("0x00000000ABC00FFE")) end)
local o,v=pcall(function() return memory.read_qword(base+0x8000) end)
print(string.format("[D] canary +8000 = %016X",o and N(v) or 0))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
