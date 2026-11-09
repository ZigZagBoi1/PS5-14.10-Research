-- CRASH_CLASS: HIGH
-- PROBE 676a: the 13.60 dossiers say mdbg command 0x05 copies out 0xb8 bytes of
-- process info, 0x0d enumerates threads and 0x10 allocates 0x1000 bytes and
-- copies them out. Our sweep only ever put the buffer in arg2 and zeros
-- elsewhere, so those commands returned -1. Here the pid and the buffer move
-- across the argument slots.
print("=== PROBE 676a: MDBG 05/0D/10 ARGUMENT LAYOUTS ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return N(v) end return -1 end
local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("[A] pid=%d",pid))
local P=memory.alloc(0x3000)
local CMDS={0x05,0x0D,0x10,0x12}
local SHAPES={
  {"cmd,pid,buf,0,size,0", function(c,b,s) return mk(601)(U(c),U(pid),U(b),U(0),U(s),U(0)) end},
  {"cmd,pid,buf,size,0,0", function(c,b,s) return mk(601)(U(c),U(pid),U(b),U(s),U(0),U(0)) end},
  {"cmd,buf,pid,size,0,0", function(c,b,s) return mk(601)(U(c),U(b),U(pid),U(s),U(0),U(0)) end},
  {"cmd,buf,0,size,pid,0", function(c,b,s) return mk(601)(U(c),U(b),U(0),U(s),U(pid),U(0)) end},
  {"cmd,buf,0,pid,size,0", function(c,b,s) return mk(601)(U(c),U(b),U(0),U(pid),U(s),U(0)) end},
  {"cmd,0,buf,pid,size,0", function(c,b,s) return mk(601)(U(c),U(0),U(b),U(pid),U(s),U(0)) end},
}
for _,cmd in ipairs(CMDS) do
  for _,sh in ipairs(SHAPES) do
    for i=0,0x1FF,4 do wd(N(P)+i,0xA5A5A5A5) end
    local r=N(select(2,pcall(function() return sh[2](cmd,N(P),0x200) end)))
    local changed=0
    for i=0,0x1FF do if rb(N(P)+i)~=0xA5 then changed=changed+1 end end
    local head=""
    for i=0,0x1F,4 do
      local b0,b1,b2,b3=rb(N(P)+i),rb(N(P)+i+1),rb(N(P)+i+2),rb(N(P)+i+3)
      if b0>=0 then head=head..string.format("%02X%02X%02X%02X ",b3,b2,b1,b0) end
    end
    print(string.format("[%02X] %-22s ret=%s changed=%d %s",cmd,sh[1],tostring(r),changed,head))
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
