-- CRASH_CLASS: MODERATE
-- PROBE 684a: the dmem0 aperture maps with MAP_SHARED. Is it writable, and does
-- a write to it survive a read-back? Every write here is the SAME value that
-- was just read, so no register is changed; only writability is measured.
print("=== PROBE 684a: DMEM WRITE-BACK TEST ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local path=memory.alloc(0x20)
for i,ch in ipairs({47,100,101,118,47,100,109,101,109,48}) do pcall(function() memory.write_byte(N(path)+i-1,ch) end) end
pcall(function() memory.write_byte(N(path)+10,0) end)
local okf,fdv=pcall(function() return mk(5)(U(N(path)),U(2),U(0),U(0),U(0),U(0)) end)
local fd=N(fdv)
print(string.format("[A] open fd=%d",fd))
local okm,addr=pcall(function() return mk(477)(U(0),U(0x2000),U(3),U(1),U(fd),U(0)) end)
local base=N(addr)
print(string.format("[B] mmap=0x%X",base))
if okm and base>0 and base<0x800000000000 then
  local vals={}
  for i=0,0x3F do
    local o,v=pcall(function() return memory.read_qword(base+i*8) end)
    if o then vals[i]=v end
  end
  local nonz=0
  for i=0,0x3F do
    if vals[i] and tostring(vals[i])~="0x0000000000000000" then nonz=nonz+1 end
  end
  print(string.format("[C] nonzero qwords in 0x200 bytes = %d",nonz))
  local wrote,kept=0,0
  for i=0,0x3F do
    if vals[i] then
      local o=pcall(function() memory.write_qword(base+i*8, vals[i]) end)
      if o then
        wrote=wrote+1
        local o2,back=pcall(function() return memory.read_qword(base+i*8) end)
        if o2 and tostring(back)==tostring(vals[i]) then kept=kept+1 end
      end
    end
  end
  print(string.format("[D] write ok=%d/64 readback same=%d/64",wrote,kept))
  print(string.format("[E] sample after: +000=%s +018=%s +0F8=%s",
    tostring(vals[0]), tostring(vals[3]), tostring(vals[0x1F])))
else
  print("[B] mmap refused")
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
