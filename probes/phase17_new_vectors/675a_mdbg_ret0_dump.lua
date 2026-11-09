-- CRASH_CLASS: MODERATE
-- PROBE 675a: the mdbg commands that return 0 without failing. The sweep only
-- printed page[0]; dump every byte that differs from the 0xA5 fill and flag any
-- qword whose high half looks like a kernel address.
print("=== PROBE 675a: MDBG RET-0 OUTPUT DUMP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return N(v) end return -1 end
local P=memory.alloc(0x1000)
local CMDS={0x00,0x07,0x09,0x0B,0x0D,0x0E,0x13,0x14,0x19,0x1A,0x1D,0x20}
for _,cmd in ipairs(CMDS) do
  for i=0,0x3FF,4 do wd(N(P)+i,0xA5A5A5A5) end
  local r=N(select(2,pcall(function() return mk(601)(U(cmd),U(N(P)),U(0),U(0),U(0),U(0)) end)))
  local changed,nkern=0,0
  for i=0,0x3FF do if rb(N(P)+i)~=0xA5 then changed=changed+1 end end
  local out=""
  for i=0,0x3F,4 do
    local b0,b1,b2,b3=rb(N(P)+i),rb(N(P)+i+1),rb(N(P)+i+2),rb(N(P)+i+3)
    if b0>=0 then
      out=out..string.format("%02X%02X%02X%02X ",b3,b2,b1,b0)
    end
  end
  print(string.format("[%02X] ret=%s changed=%d  %s",cmd,tostring(r),changed,out))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
