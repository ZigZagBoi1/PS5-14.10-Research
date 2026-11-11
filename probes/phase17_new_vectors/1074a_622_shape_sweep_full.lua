-- CRASH_CLASS: HIGH
-- PROBE 1074a: the corrected uap shape across the 622 command space, one arm per connection.
--
-- Probe 55c swept 0x100-0x520 with the command in slot 2; the handler reads it from slot 0
-- (*param_2), so that sweep measured a command of 0 for all 400+ entries and every reply was
-- the same 0x800E0001 no-device-context stub. 1039a fixed the shape and tested five commands.
-- The four dispatch arms are indirect jumps through tables at 0x178057c / 0x1780a4c /
-- 0x1780c10 / 0x1780c8c, all outside the 4 MB kernel_data.bin capture, so the arm bodies are
-- not local: this sweep is the only way to see what they do.
--
-- Two measurement defects this revision fixes:
--   1. The all-ones sentinel could not distinguish "wrote 0xFFFFFFFF" from "wrote nothing",
--      because the band's own status IS 0xFFFFFFFF and every C line printed identical bytes.
--      The fill is now 0xA5A5A5A5 per dword and the scan counts differing dwords over the whole
--      buffer, so a status write and silence are different rows.
--   2. A command that kills the process costs the rest of its arm, and 0x201, 0x302 and 0x400
--      each kill on the first command of their range. Each arm is therefore selected by ARM
--      and run in its own connection; bump ARM between runs to resume.
print("=== PROBE 1074a: 622 COMMAND SWEEP (slot-0 command) ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rw(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) or 0 end return -1 end
local function rqw(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end
local function hi_of(q) if type(q)=="table" and q.h then return q.h, q.l end local n=to_num(q) return math.floor(n/4294967296), n%4294967296 end

local sc_sig=mk(416); local sc622=mk(622); local sc_pid=mk(20)
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local okS,vS=pcall(function() return sc_sig(uint64(12),uint64(aa),uint64(0)) end)
print(string.format("[S] sigsys-ignore ok=%s rv=%s pid=%s", tostring(okS), okS and tostring(to_num(vS)) or "-",
  tostring(to_num(select(2,pcall(function() return sc_pid() end))))))
print("")

local NB=0x100
local buf=memory.alloc(NB); local ba=as_addr(buf)
local SENT=0xA5A5A5A5
local function fill() for i=0,NB/8-1 do wd(ba+i*8,SENT); wd(ba+i*8+4,SENT) end end
-- count dwords that differ from the sentinel, and remember the first differing byte offset
local function scan()
  local n=0; local first=-1
  for o=0,NB-4,4 do
    if rw(ba+o) ~= SENT then n=n+1; if first<0 then first=o end end
  end
  return n, first
end
fill()
local n0,f0 = scan()
print(string.format("[V] sentinel A5A5A5A5 dirty=%d first=%d %s", n0, f0,
  (n0==0) and "CLEAN" or "BROKEN - do not trust C lines"))
print("")

-- ARM selects one range; 1..6. Every arm is run in its own connection because a killing
-- command ends the process, and the killers sit at the head of arms 2 and 5.
local ARMS = {
  { 0x134, 0x200, "low"     },  -- measured: every command writes 0xFFFFFFFF at +0
  { 0x201, 0x271, "arm201"  },  -- dies on 0x201 and takes the game with it
  { 0x300, 0x301, "arm300a" },
  { 0x303, 0x320, "arm300b" },
  { 0x400, 0x493, "arm400"  },  -- dies on 0x400
  { 0x302, 0x302, "kill302" },  -- dies at any shape
  { 0x202, 0x271, "arm202"  },  -- resumes past the 0x201 killer
  { 0x401, 0x493, "arm401"  },  -- resumes past the 0x400 killer
}
local ARM = 7 -- ARM_SELECT
local lo,hi,label = ARMS[ARM][1], ARMS[ARM][2], ARMS[ARM][3]
print(string.format("[A] arm %d/%d %s 0x%X..0x%X  commands=%d", ARM, #ARMS, label, lo, hi, hi-lo+1))

local diff=0
for c=lo,hi do
  fill()
  print(string.format("  > %X", c))
  local ok,rv=pcall(function() return sc622(uint64(c),uint64(0),uint64(ba),uint64(0),uint64(0),uint64(0)) end)
  local r = ok and to_num(rv) or -999
  local n,first = scan()
  if n>0 or r~=-1 then
    diff=diff+1
    local h,l=hi_of(rqw(ba))
    print(string.format("  C %X rv=%d touched=%d first=%+d q0=%X_%08X", c, r, n, first, h, l))
  end
end
print(string.format("  [%s] rows=%d of %d", label, diff, hi-lo+1))
print("")
print("=== DONE 1074a ===")
