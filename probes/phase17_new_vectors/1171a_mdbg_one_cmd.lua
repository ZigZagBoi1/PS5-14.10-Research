-- CRASH_CLASS: MODERATE  (one 601 command, chosen by the CMD_SELECT line)
-- PROBE 1171a: one mdbg command, with a proved sentinel buffer and ASCII readback.
-- Driven by tools/601_arm_bruteforce.py, which rewrites the CMD_SELECT line and runs one command per
-- TCP connection (one fresh process each), so a blocking or lethal command costs one relaunch and is
-- recorded instead of losing the rest of the sweep.
print("=== PROBE 1171a: ONE MDBG COMMAND ===")
local CMD = 0x09 -- CMD_SELECT
local LEN = 0x4000
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return N(v) end return -1 end
local P = memory.alloc(LEN)
local base = N(P)
for i=0,LEN-1,4 do wd(base+i,0xA5A5A5A5) end
local ok=0 for i=0,LEN-1,4 do if rb(base+i)==0xA5 then ok=ok+1 end end
print(string.format("[S] buf=%s proved=%s (%d/%d)", tostring(P), tostring(ok==LEN/4), ok, LEN/4))
local sc = mk(601)
local rv = N(select(2, pcall(function() return sc(U(CMD), U(base), U(LEN), U(0), U(0), U(0)) end)))
local changed, firstchg = 0, -1
for i=0,LEN-1 do local b=rb(base+i); if b~=0xA5 then changed=changed+1; if firstchg<0 then firstchg=i end end end
local function ascii_of(off,n) local s="" for i=off,off+n-1 do local b=rb(base+i) if b<0 then break end if b>=32 and b<127 then s=s..string.char(b) else s=s.."." end end return s end
local head = ascii_of(0,48)
local hit = false
if changed > 0 then
  for off=0,LEN-512,64 do if string.find(ascii_of(off,512), "mDBG", 1, true) then hit = true break end end
end
print(string.format("[R] cmd=0x%02X rv=%d changed=%d first=%d text_hit=%s", CMD, rv, changed, firstchg, tostring(hit)))
if changed > 0 then
  print('    ascii="' .. head .. '"')
  local function hex8(off)
    local s = ""
    for i=7,0,-1 do s = s .. string.format("%02X", rb(base+off+i)) end
    return s
  end
  print(string.format("    qwords=%s %s %s %s", hex8(0), hex8(8), hex8(16), hex8(24)))
end
print("=== 1171a DONE ===")
