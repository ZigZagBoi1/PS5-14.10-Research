-- CRASH_CLASS: MODERATE
-- PROBE 686a: with MAP_SHARED the aperture is readable and writable. Does the
-- mmap OFFSET select what is behind it? Map 4 KiB at increasing offsets and
-- read the first two qwords of each.
print("=== PROBE 686a: DMEM OFFSET SELECTION ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local fd=N(select(2,pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)))
print(string.format("[A] fd=%d",fd))
local offs={0,0x1000,0x10000,0x100000,0x1000000,0x4000000,0x10000000,0x40000000,0x100000000,0x200000000,0x800000000}
for _,off in ipairs(offs) do
  local ok,r=pcall(function() return mk(477)(U(0),U(0x1000),U(3),U(1),U(fd),U(off)) end)
  local a=N(r)
  if ok and a>0 and a<0x800000000000 then
    local o1,v1=pcall(function() return memory.read_qword(a) end)
    local o2,v2=pcall(function() return memory.read_qword(a+8) end)
    print(string.format("  off=%010X va=%X q0=%s q1=%s",off,a,
      string.format("%016X",o1 and N(v1) or 0),string.format("%016X",o2 and N(v2) or 0)))
    pcall(function() mk(73)(U(a),U(0x1000),U(0),U(0),U(0),U(0)) end)
  else
    print(string.format("  off=%010X mmap failed (%s)",off,tostring(r)))
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
