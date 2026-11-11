-- CRASH_CLASS: RISKY  (the last step is the exact shape that wedged the loader in 1192a)
-- PROBE 1193b: isolate what makes 601 cmd 0x00 wedge. One variable per step, each printed before the
-- next one runs, so a hang localises itself.
--   A  0xA5-filled struct, arg3 = 0            (known safe, 1170a control)
--   B  zeroed struct,     arg3 = 0            -> isolates "the struct contents"
--   C  0xA5-filled struct, arg3 = 0x4000       (known safe, 1170a shape)
--   D  zeroed struct,     arg3 = 0x4000       -> both known-safe shapes combined
--   E  0xA5-filled struct, arg3 = mapped ptr   -> isolates "arg3 is a wild pointer" (1192a minus zeroing)
--   F  zeroed struct,     arg3 = mapped ptr    -> the exact 1192a shape
print("=== PROBE 1193b: WHAT MAKES 601/0x00 WEDGE ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hexn(v) v=N(v) return string.format("0x%08X%08X", math.floor(v/4294967296), v % 4294967296) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local S1 = N(memory.alloc(0x100))   -- struct buffer
local S2 = N(memory.alloc(0x1000))  -- out buffer used as a length-or-pointer
local function zero(a,n) for o=0,n-4,4 do wd(a+o,0) end end
local function fill(a,n,v) for o=0,n-4,4 do wd(a+o,v) end end
local sc = mk(601)

local function step(tag, desc, bufval, arg3, outk)
  if bufval then fill(S1,0x100,bufval) else zero(S1,0x100) end
  if outk then fill(S2,0x1000,0xC7C7C7C7) end
  print(string.format("[%s] %s  struct=%s arg3=%s", tag, desc,
        bufval and string.format("0x%08X fill", bufval) or "zeroed", tostring(arg3)))
  local ok, ret = pcall(function() return sc(U(0x00), U(S1), U(arg3), U(0), U(0), U(0)) end)
  if not ok then print("   PCALL-FAIL"); return end
  local raw = "?" pcall(function() raw = tostring(ret) end)
  print(string.format("   rv=%s raw=%s errno=%s struct0=%s out0=%s",
        tostring(N(ret)), raw, es(), hexn(rd(S1)), hexn(rd(S2))))
end

step("A","A5 struct, arg3=0",            0xA5A5A5A5, 0,        false)
step("B","zeroed struct, arg3=0",        nil,        0,        false)
step("C","A5 struct, arg3=0x4000",       0xA5A5A5A5, 0x4000,   false)
step("D","zeroed struct, arg3=0x4000",   nil,        0x4000,   false)
step("E","A5 struct, arg3=mapped ptr",   0xA5A5A5A5, S2,       true)
step("F","zeroed struct, arg3=mapped ptr", nil,       S2,       true)
print("[Z] alive")
print("=== DONE ===")
