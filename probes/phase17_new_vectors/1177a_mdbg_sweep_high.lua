-- CRASH_CLASS: LOW  (heavy work on the main thread, child does one syscall + one print - see 1176a)
-- PROBE 1177a: finish 601's command space where 1176b stopped.
-- 1176b measured 0x09..0x1A in one process, absorbed the 0x0C park on a thread, and died at 0x1B with no
-- crash blob. This run covers the rest DESCENDING from 0x2F so that an unknown killer costs the fewest
-- commands, and leaves 0x1B for last because it is the one known to kill.
-- Excluded: 0x03/0x04 (raw struct proc*, panic) and 0x27 (LOADER-DEAD, already measured).
print("=== PROBE 1177a: 601 SWEEP, 0x2F DOWN TO 0x1B ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function spin(n) local x=0 for i=1,n do x=x+i end return x end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local fd = 0
do local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end) if ok then fd = v end end
local base = N(memory.alloc(0x1000))
print(string.format("[F] socket fd=%d buf=0x%08X", fd, base % 4294967296))

local CMDS = {}
for c=0x2F,0x1C,-1 do if c ~= 0x27 then CMDS[#CMDS+1] = c end end
CMDS[#CMDS+1] = 0x1B
print(string.format("[L] %d commands: 0x2F..0x1C then 0x1B", #CMDS))

local function refill()
  for i=0,0xFFC,4 do pcall(function() memory.write_dword(base+i, 0xA5A5A5A5) end) end
end
local function report(cmd)
  local changed, first, hex = 0, -1, ""
  for i=0,0xFFC,4 do
    local d = RD(base+i)
    if d ~= -1 and d ~= 0xA5A5A5A5 then changed = changed + 1; if first < 0 then first = i end end
    if i < 32 then hex = hex .. string.format("%08X ", d) end
  end
  local ascii = ""
  for b=0,31 do
    local d = RD(base + (b - b % 4))
    local v = math.floor(d / 2^((b % 4) * 8)) % 256
    if v >= 32 and v < 127 then ascii = ascii .. string.char(v) else ascii = ascii .. "." end
  end
  print(string.format("[B%02X] changed=%d first=%d ascii=\"%s\" dw=%s", cmd, changed, first, ascii, hex))
end

local TMPL = [[
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(a) a=N(a) return uint64(string.format("0x%%08X%%08X",math.floor(a/4294967296),a%%4294967296)) end
local ok, rv = pcall(function()
  local t = {}
  for k,v in pairs(syscall.pipe) do t[k]=v end
  t.syscall_no = 601
  setmetatable(t, getmetatable(syscall.pipe))
  return t(U(0x%02X), U(%d), U(0x1000), U(0), U(0), U(0))
end)
if ok then print(string.format("T%%02X rv=%%d", 0x%02X, N(rv))) else print(string.format("T%%02X ERR %%s", 0x%02X, tostring(rv))) end
]]

for i=1,#CMDS do
  local cmd = CMDS[i]
  refill()
  local ok, res = pcall(run_lua_code_in_new_thread, string.format(TMPL, cmd, base, cmd, cmd), { async = true, client_fd = fd })
  if not ok then print(string.format("[S] 0x%02X spawn FAILED %s", cmd, tostring(res))) end
  spin(3000000)
  report(cmd)
end
for i=1,6 do print(string.format("WAIT-%d", i)) spin(4000000) end
print("[Z] alive")
print("=== DONE ===")
