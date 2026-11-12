-- CRASH_CLASS: MODERATE  (unmeasured commands; a killer is possible, a panic is possible)
-- PROBE 1180a: 601 commands 0x30..0x4F, descending, one sacrificial thread each (docs/SACRIFICIAL_THREAD_14_10.md).
-- Everything below 0x30 is mapped in docs/MDBG_601_COMMAND_MAP_14_10.md: only 0x00, 0x0E and 0x1A
-- ever write, nothing writes ASCII, and 0x03/0x04 panic while 0x08/0x0C park and 0x1B/0x27 kill.
-- Child does one syscall and one print; main owns the buffer (1176a killed the process when the child
-- did the memory work).
print("=== PROBE 1180a: 601 SWEEP 0x30..0x4F ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function spin(n) local x=0 for i=1,n do x=x+i end return x end
local function RD(a) local o,v = pcall(function() return memory.read_dword(a) end) if o then return N(v) end return -1 end
local fd = 0
do local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end) if ok then fd = v end end
local base = N(memory.alloc(0x1000))
print(string.format("[F] fd=%d buf=0x%08X", fd, base % 4294967296))
local LO, HI = 0x30, 0x4F
local CMDS = {}
for c=HI,LO,-1 do CMDS[#CMDS+1] = c end
print(string.format("[L] %d commands", #CMDS))
local function refill() for i=0,0xFFC,4 do pcall(function() memory.write_dword(base+i, 0xA5A5A5A5) end) end end
local function report(cmd)
  local changed, first, hex = 0, -1, ""
  for i=0,0xFFC,4 do
    local d = RD(base+i)
    if d ~= -1 and d ~= 0xA5A5A5A5 then
      changed = changed + 1
      if first < 0 then first = i end
      if changed <= 8 then hex = hex .. string.format("@%X=%08X ", i, d) end
    end
  end
  if changed > 0 then print(string.format("[B%02X] changed=%d first=%d %s", cmd, changed, first, hex)) end
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
