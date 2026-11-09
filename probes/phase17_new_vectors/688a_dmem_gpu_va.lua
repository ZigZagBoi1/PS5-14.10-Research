-- CRASH_CLASS: MODERATE
-- PROBE 688a: the register block at dmem offset 0 holds GPU addresses such as
-- 0xC0012800 and 0xC0027600. If dmem maps GPU memory, those addresses are
-- themselves valid mmap offsets. Try them.
print("=== PROBE 688a: DMEM AT GPU VIRTUAL ADDRESSES ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
print(string.format("[A] fd=%d",fd))
local offs={0xC0000000,0xC0012000,0xC0012800,0xC0027000,0xC0027600,0xD0000000,0x100000000}
for _,off in ipairs(offs) do
  local ok,r=pcall(function() return mk(477)(U(0),U(0x1000),U(3),U(1),U(fd),U(off)) end)
  local a=N(r)
  if ok and a>0 and a<0x800000000000 then
    local q={}
    for i=0,3 do local o,v=pcall(function() return memory.read_qword(a+i*8) end); q[i]=o and N(v) or -1 end
    print(string.format("  off=%09X va=%X %016X %016X %016X %016X",off,a,q[0],q[1],q[2],q[3]))
    pcall(function() mk(73)(U(a),U(0x1000),U(0),U(0),U(0),U(0)) end)
  else
    print(string.format("  off=%09X mmap failed",off))
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
