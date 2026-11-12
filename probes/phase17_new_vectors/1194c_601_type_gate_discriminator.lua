-- CRASH_CLASS: MODERATE (arg3 = 0 everywhere; type-4 unlink path with an empty list is a no-op)
-- PROBE 1194c: find 601's second-stage commands by the TYPE GATE signature.
-- Stage two dispatches on struct+0x24 (see docs/SYS601_SECOND_STAGE_14_10.md). With an out-of-range
-- type it returns 1 (userland: rv=-1 errno=1 EPERM); with type 4 and flags 0 it takes the unlink path
-- and returns 0. A command whose answer flips between those two structs is a stage-two entry.
print("=== PROBE 1194c: 601 STAGE-TWO TYPE-GATE DISCRIMINATION ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return 0 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local B = N(memory.alloc(0x100))
local sc = mk(601)
local function setA5() for o=0,0xFC,4 do wd(B+o,0xA5A5A5A5) end end
local function setT4() for o=0,0xFC,4 do wd(B+o,0) end
  wd(B+0x08,0x10)   -- fieldA
  wd(B+0x0c,0)      -- ptr
  wd(B+0x14,0)      -- flags
  wd(B+0x18,0)      -- ptrB
  wd(B+0x20,0)      -- len
  wd(B+0x24,4)      -- TYPE 4
end
local function call(cmd)
  local ok, ret = pcall(function() return sc(U(cmd), U(B), U(0), U(0), U(0), U(0)) end)
  if not ok then return "PCALLFAIL", "-" end
  return tostring(N(ret)), es()
end
local SKIP = {[0x00]=true,[0x03]=true,[0x04]=true,[0x08]=true,[0x0C]=true,[0x1B]=true,[0x27]=true}
local flips = {}
for cmd=0,0x2F do
  if not SKIP[cmd] then
    setA5() local rx, ex = call(cmd)
    setT4() local ry, ey = call(cmd)
    local flip = (rx ~= ry)
    if flip then flips[#flips+1] = cmd end
    print(string.format("[%02X] A5struct: rv=%-3s errno=%-28s | T4struct: rv=%-3s errno=%-28s %s",
          cmd, rx, ex, ry, ey, flip and "<<< FLIP" or ""))
  end
end
print("[SUM] flips = "..table.concat(flips, ","))
print("[Z] alive")
print("=== DONE ===")
