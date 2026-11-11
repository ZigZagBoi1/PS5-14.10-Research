-- CRASH_CLASS: MODERATE
-- PROBE 1170a: the mdbg log drain. docs/HANDLER_SHAPE_HUNT_14_10.md finding 1 says a command in
-- 601's table memcpy's the kernel log list (0x3e0d870) into a 0x4000 bounce buffer and uiomove's it
-- to the caller, with the log created lazily by "mdbglog" and every 601 call appending
-- "mDBG: Debughandler starting(...)". No probe has ever looked at returned BYTES for log text, so
-- this sweeps every command 0..0x2f (except the two known-lethal ones) with a 0x4000 buffer and
-- prints what changed, as ASCII where printable. One call per command, printed immediately, so a
-- death localises the command.
print("=== PROBE 1170a: MDBG LOG DRAIN SWEEP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return N(v) end return -1 end
local BUF, LEN = 0x4000, 0x4000
local P = memory.alloc(BUF)
local base = N(P)
print(string.format("[S] buffer=%s len=%d", tostring(P), LEN))
-- prove the sentinel
for i=0,BUF-1,4 do wd(base+i, 0xA5A5A5A5) end
local ok = 0
for i=0,BUF-1,4 do if rb(base+i)==0xA5 then ok=ok+1 end end
print(string.format("[S] sentinel_proved=%s (%d/%d dwords)", tostring(ok==BUF/4), ok, BUF/4))
local sc = mk(601)
local SKIP = { [0x03]=true, [0x04]=true }
local function ascii_of(off, n)
  local s = ""
  for i=off,off+n-1 do
    local b = rb(base+i)
    if b < 0 then break end
    if b >= 32 and b < 127 then s = s .. string.char(b) else s = s .. "." end
  end
  return s
end
local hits = 0
for cmd = 0x00, 0x2F do
  if not SKIP[cmd] then
    for i=0,BUF-1,4 do wd(base+i, 0xA5A5A5A5) end
    local rv = N(select(2, pcall(function() return sc(U(cmd), U(base), U(LEN), U(0), U(0), U(0)) end)))
    local changed, firstchg = 0, -1
    for i=0,BUF-1 do
      local b = rb(base+i)
      if b ~= 0xA5 then changed = changed + 1; if firstchg < 0 then firstchg = i end end
    end
    local line = string.format("[%02X] rv=%d changed=%d first=%d", cmd, rv, changed, firstchg)
    if changed > 0 then
      line = line .. '  ascii="' .. ascii_of(0, 48) .. '"'
      if string.find(ascii_of(0, 512), "mDBG", 1, true) then line = line .. "  <== mDBG TEXT" ; hits = hits + 1 end
    end
    print(line)
  end
end
print(string.format("[SUM] commands_swept=%d text_hits=%d", 0x30-2, hits))
print(string.format("[Z] alive=%d", N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== DONE ===")
