-- CRASH_CLASS: HIGH
-- PROBE 695a: narrow version of the system-RAM question. Fill one fresh page
-- with a canary, map 128 KiB of dmem0, and search page by page, printing each
-- page's result immediately so a crash cannot hide the answer.
print("=== PROBE 695a: DMEM vs SYSTEM RAM (NARROW) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local buf=memory.alloc(0x1000)
for i=0,0x1FF do pcall(function() memory.write_qword(N(buf)+i*8, uint64("0x00000000C0FFEE99")) end) end
print(string.format("[A] canary page=0x%X self-read=%016X",N(buf),rq(N(buf)) or 0))
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x20000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[B] fd=%d base=0x%X",fd,base))
if base==0 or base>0x800000000000 then print("[Z] no map") return end
local can=0x00C0FFEE99
for p=0,0x1F do
  local hits,nz=0,0
  for i=0,0x1FF do
    local v=rq(base+p*0x1000+i*8)
    if v==nil then print(string.format("  page %02X FAULT",p)); break end
    if v==can then hits=hits+1 end
    if v~=0 then nz=nz+1 end
  end
  if p<4 or hits>0 or nz>0 then
    print(string.format("  page %02X nz=%d hits=%d",p,nz,hits))
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
