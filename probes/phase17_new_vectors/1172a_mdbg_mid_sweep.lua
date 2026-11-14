-- CRASH_CLASS: MODERATE
-- PROBE 1172a: 601 commands 0x09..0x26 in one process (62 bytes 0x03/0x04/0x08 are below this range
-- and 0x27 is excluded because it kills the loader; 1171a/1170a measured both). Ascending with a
-- per-command print, so a killer is localised by the last line. Looking for the unprivileged kernel
-- log drain (HANDLER_SHAPE_HUNT finding 1): any command returning thousands of changed bytes, or the
-- string "mDBG", is the drain.
print("=== PROBE 1172a: MDBG MID-SWEEP 0x09..0x26 ===")
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
local function ascii_of(off,n) local s="" for i=off,off+n-1 do local b=rb(base+i) if b<0 then break end if b>=32 and b<127 then s=s..string.char(b) else s=s.."." end end return s end
local function hex8(off) local s="" for i=7,0,-1 do s=s..string.format("%02X",rb(base+off+i)) end return s end
local interesting = {}
for cmd=0x09,0x26 do
  for i=0,LEN-1,4 do wd(base+i,0xA5A5A5A5) end
  local rv = N(select(2, pcall(function() return sc(U(cmd), U(base), U(LEN), U(0), U(0), U(0)) end)))
  local changed, firstchg = 0, -1
  for i=0,LEN-1 do local b=rb(base+i) if b~=0xA5 then changed=changed+1 if firstchg<0 then firstchg=i end end end
  print(string.format("[%02X] rv=%d changed=%d first=%d", cmd, rv, changed, firstchg))
  if changed > 0 then
    print('    ascii="' .. ascii_of(0,48) .. '"')
    print(string.format("    qwords=%s %s %s %s", hex8(0), hex8(8), hex8(16), hex8(24)))
    interesting[#interesting+1] = cmd
    if changed >= 512 then print("    <== LARGE OUTPUT, check for the drain") end
  end
end
local s = "" for i=1,#interesting do s = s .. string.format("%02X ", interesting[i]) end
print(string.format("[SUM] commands=30 wrote_something=%d [%s]", #interesting, s))
print("=== 1172a DONE ===")
