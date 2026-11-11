-- CRASH_CLASS: MODERATE  (one thread per command; a parking command costs a thread, not a relaunch)
-- PROBE 1176a: sweep 601's command space with the sacrificial thread from 1175a.
-- 1175a proved run_lua_code_in_new_thread async=true keeps the main thread running while a second
-- thread parks inside the kernel: 601 0x0C parked and MAIN2-1..8 still printed. That removes the cost
-- that stopped the sweep at 0x08 (1170a) and 0x0C (1172a). Known hazards stay excluded: 0x03/0x04 take
-- a raw struct proc* (panic) and 0x27 faults the whole process (LOADER-DEAD), which a thread cannot
-- survive either, so it is left to its own run.
-- Each thread gets its own 0x1000 buffer, fills it with 0xA5A5A5A5, calls 601(cmd,buf,0x1000,0,0,0),
-- and reports rv, changed dwords, first changed offset, ASCII of the first 64 bytes, and whether the
-- text "mDBG" appears in them (docs/HANDLER_SHAPE_HUNT_14_10.md finding 1).
print("=== PROBE 1176a: 601 COMMAND SWEEP ON SACRIFICIAL THREADS ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function spin(n) local x=0 for i=1,n do x=x+i end return x end
local fd = 0
do local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end) if ok then fd = v end end
print(string.format("[F] socket fd=%d", fd))

local CMDS = {}
for c=0x09,0x2F do if c ~= 0x27 then CMDS[#CMDS+1] = c end end
print(string.format("[L] %d commands, 0x03/0x04/0x27 excluded", #CMDS))

local TMPL = [[
local cmd = 0x%02X
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(a) a=N(a) return uint64(string.format("0x%%08X%%08X",math.floor(a/4294967296),a%%4294967296)) end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local base = N(memory.alloc(0x1000))
for i=0,0xFFC,4 do pcall(function() memory.write_dword(base+i, 0xA5A5A5A5) end) end
local ok, rv = pcall(function()
  local t = {}
  for k,v in pairs(syscall.pipe) do t[k]=v end
  t.syscall_no = 601
  setmetatable(t, getmetatable(syscall.pipe))
  return t(U(cmd), U(base), U(0x1000), U(0), U(0), U(0))
end)
if not ok then print(string.format("T%%02X ERR %%s", cmd, tostring(rv))) return end
local changed, first = 0, -1
local words, hex = {}, ""
for i=0,0xFFC,4 do
  local d = RD(base+i)
  if d ~= -1 and d ~= 324508639 then  -- 0xA5A5A5A5
    changed = changed + 1
    if first < 0 then first = i end
    if #words < 4 then words[#words+1] = i end
  end
  if i < 128 then hex = hex .. string.format("%%08X", d) end -- escaped: this template is formatted twice
end
local ascii = ""
for b=0,63 do
  local d = RD(base + (b - b %% 4))
  local shift = (b %% 4) * 8
  local v = math.floor(d / 2^shift) %% 256
  if v >= 32 and v < 127 then ascii = ascii .. string.char(v) else ascii = ascii .. "." end
end
print(string.format("T%%02X rv=%%d changed=%%d first=%%d ascii=\"%%s\" dw=%%s", cmd, N(rv), changed, first, ascii, hex))
]]

for i=1,#CMDS do
  local cmd = CMDS[i]
  local ok, res = pcall(run_lua_code_in_new_thread, string.format(TMPL, cmd), { async = true, client_fd = fd })
  if ok then print(string.format("[S] spawned 0x%02X", cmd))
  else print(string.format("[S] 0x%02X spawn FAILED %s", cmd, tostring(res))) end
  spin(2000000)
end
for i=1,10 do print(string.format("WAIT-%d", i)) spin(4000000) end
print("[Z] alive")
print("=== DONE ===")
