-- CRASH_CLASS: MODERATE (call 1 is the suspected wedge trigger from 1192a, with arg3 forced to 0)
-- PROBE 1193c: two-call discrimination for the 601 cmd-0x00 wedge.
--   1) zeroed 0x100 struct, arg3 = 0     <- 1192a's struct, arg3 neutralised
--   2) 0xA5-filled struct, arg3 = 0      <- 1170a's struct, arg3 neutralised
-- If step 1 wedges, the struct contents are the trigger. If both return, arg3 was the trigger.
print("=== PROBE 1193c: 601/0x00 STRUCT-VS-ARG3 DISCRIMINATION ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hexn(v) v=N(v) return string.format("0x%08X%08X", math.floor(v/4294967296), v % 4294967296) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local B = N(memory.alloc(0x100))
local sc = mk(601)
local function call(tag, fillv)
  if fillv then for o=0,0xFC,4 do wd(B+o,fillv) end else for o=0,0xFC,4 do wd(B+o,0) end end
  print(string.format("[%s] about to call 601(0x00, %s, 0)", tag, fillv and "0xA5 struct" or "zeroed struct"))
  local ok, ret = pcall(function() return sc(U(0x00), U(B), U(0), U(0), U(0), U(0)) end)
  if not ok then print("   PCALL-FAIL"); return end
  local raw="?" pcall(function() raw=tostring(ret) end)
  print(string.format("   returned rv=%s raw=%s errno=%s buf0=%s", tostring(N(ret)), raw, es(), hexn(rd(B))))
end
call("1", nil)
call("2", 0xA5A5A5A5)
print("[Z] alive")
print("=== DONE ===")
