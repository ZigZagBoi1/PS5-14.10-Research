-- CRASH_CLASS: MODERATE
-- PROBE 696a: dump the structured pages of the dmem0 window (0x00 engine block,
-- 0x0F fence area, 0x10-0x11 the large filled array) as qwords.
print("=== PROBE 696a: DMEM STRUCTURE DUMP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return -1 end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
local base=N(select(2,pcall(function() return mk(477)(U(0),U(0x20000),U(3),U(1),U(fd),U(0)) end)))
print(string.format("[A] base=0x%X",base))
if base==0 or base>0x800000000000 then print("[Z] no map") return end
for _,p in ipairs({0x00,0x0F,0x10,0x11}) do
  print(string.format("-- page %02X",p))
  for row=0,7 do
    local t={}
    for c=0,3 do t[c+1]=string.format("%016X",rq(base+p*0x1000+(row*4+c)*8)) end
    print(string.format("  +%03X %s",row*0x20,table.concat(t," ")))
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
