-- CRASH_CLASS: LOW  (the heavy memory work stays on the main thread; a child does one syscall and one print)
-- PROBE 1176b: sweep 601's command space with the sacrificial thread, restructured after 1176a.
-- 1175a proved the mechanism: async thread + client_fd, a parking 601 0x0C did not stop the main thread.
-- 1176a then killed the PROCESS on the first child (0x09) and sent no crash blob - the child did 1024
-- memory.write_dword and 1024 memory.read_dword calls, and native primitives are the documented race
-- (.local/loader_payload/thread.lua:111-113). So here the child does the absolute minimum: one syscall
-- on a buffer the MAIN thread allocated and filled, one print of rv. Main inspects the buffer itself.
-- Excluded: 0x03/0x04 (raw struct proc*, panic) and 0x27 (faults the whole process, LOADER-DEAD).
print("=== PROBE 1176b: 601 SWEEP, CHILD DOES ONE SYSCALL ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function spin(n) local x=0 for i=1,n do x=x+i end return x end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local fd = 0
do local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end) if ok then fd = v end end
local base = N(memory.alloc(0x1000))
print(string.format("[F] socket fd=%d buf=0x%08X", fd, base % 4294967296))

local CMDS = {}
for c=0x09,0x2F do if c ~= 0x27 then CMDS[#CMDS+1] = c end end
print(string.format("[L] %d commands", #CMDS))

local function refill()
  for i=0,0xFFC,4 do pcall(function() memory.write_dword(base+i, 0xA5A5A5A5) end) end
end
local function report(cmd)
  local changed, first, hex = 0, -1, ""
  for i=0,0xFFC,4 do
    local d = RD(base+i)
    if d ~= -1 and d ~= 2785017861 then -- 0xA5A5A5A5; 324508639 was a decimal I made up and made every dword read as changed changed = changed + 1; if first < 0 then first = i end end
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
  local code = string.format(TMPL, cmd, base, cmd, cmd)
  local ok, res = pcall(run_lua_code_in_new_thread, code, { async = true, client_fd = fd })
  if not ok then print(string.format("[S] 0x%02X spawn FAILED %s", cmd, tostring(res))) end
  spin(3000000)
  report(cmd)
end
for i=1,6 do print(string.format("WAIT-%d", i)) spin(4000000) end
print("[Z] alive")
print("=== DONE ===")
