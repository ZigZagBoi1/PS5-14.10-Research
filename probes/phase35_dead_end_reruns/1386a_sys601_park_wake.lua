-- CRASH_CLASS: MODERATE -- one parked thread in a loader-spawned Lua thread (the loader's own
-- native primitive warns of a race); nothing in this probe has ever killed the process.
-- PROBE 1386a: park one thread in 601 cmd 0x0C and see which other command wakes it, with what
--
-- Measured on 14.10: 601(0x0C, 0, 0) never returns and never kills - the connection stays open
-- and the caller is simply gone (results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_
-- 20261109_133353.txt ended in IDLE_TIMEOUT there). 1175a proved a parked thread inside
-- run_lua_code_in_new_thread does not stop the main thread, so the pair can be driven from one
-- connection. The 13.60 map calls 0x0D thread enumeration, 0x0E partial, 0x13+ device state and
-- 0x14-0x19 device name/config, i.e. a family that talks to the same object 0x0C waits on.
--
-- If any main-thread command releases the parked 0x0C, its return value and the bytes it wrote
-- are the answer of a blocking kernel wait - the first such datum this project would have, and
-- the highest-value target in the 601 family after the arbitrary 0x480-byte copyout.
--
-- The thread source is built with the addresses formatted in, because a spawned Lua thread gets a
-- fresh global environment: 1350a died on `attempt to index global 'G'` for exactly that reason.
--
-- -- prior art:
--   results/phase17_new_vectors/1175a_loader_thread_api_20261104_160547.txt (park does not stop main)
--   results/phase35_dead_end_reruns/1350b_sys622_kill_in_thread_20261109_*.txt (a kill is not contained)
--   results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt (0x0C parks)
--   results/kernel_handlers/analysis/sys_601_deep.md (command map)

print("=== PROBE 1386a: 601 0x0C PARKED THREAD vs THE REST OF THE FAMILY ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local fd = 0
do
    local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end)
    if ok then fd = v end
end
print(string.format("[0] pid=%d socket=%d", N(mk(20)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0))), fd))

local TB = memory.alloc(0x1000)
local TBU = N(TB)
pcall(function() memory.write_buffer(TB, string.rep("\0", 0x1000)) end)

local src = string.format([[
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local TB = %d
print("T-ENTER 0x0C")
local ok, rv = pcall(function()
    local t = {}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no = 601
    setmetatable(t, getmetatable(syscall.pipe))
    return t(0x0C, TB, 0x1000, 0, 0, 0)
end)
print("T-WOKE ok="..tostring(ok).." rv="..tostring(ok and N(rv) or rv))
local nz = 0
local head = ""
for i = 0, 63 do
    local ok2, v = pcall(function() return memory.read_dword(TB + i*4) end)
    if ok2 and N(v) ~= 0 then
        nz = nz + 1
        if #head < 120 then head = head .. string.format(" %%08X", N(v)) end
    end
end
print(string.format("T-BUF nz=%%d%%s", nz, head))
]], TBU)

local ok, res = pcall(run_lua_code_in_new_thread, src, { async = true, client_fd = fd })
print(string.format("[1] park thread spawn=%s", tostring(ok)))
if not ok then print("ABORT spawn: " .. tostring(res)); return end

local function spin(n) local x = 0 for i = 1, n do x = x + i end return x end
local ORD = {0x00, 0x0D, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x0E, 0x1A}
for i = 1, #ORD do
    local c = ORD[i]
    local BUF = memory.alloc(0x200)
    local BU = N(BUF)
    pcall(function() memory.write_buffer(BUF, string.rep("\0", 0x200)) end)
    local ok2, rv = pcall(function()
        return mk(601)(uint64(c), uint64(BU), uint64(BU), uint64(0), uint64(0), uint64(0))
    end)
    local r = ok2 and N(rv) or -99999
    local nz, head = 0, ""
    for j = 0, 15 do
        local ok3, v = pcall(function() return N(memory.read_dword(BU + j * 4)) end)
        if ok3 and v ~= 0 then nz = nz + 1; if #head < 60 then head = head .. string.format(" %08X", v) end end
    end
    print(string.format("  main 601(0x%02X) rv=%-6s errno=%-22s nz=%d%s", c, tostring(r),
        ok2 and es() or "EXC", nz, head))
    for k = 1, 6 do print(string.format("  MAIN-%d", k)) spin(2000000) end
end

print("[2] final: still alive, spinning to let the parked thread report")
for i = 1, 10 do print(string.format("TAIL-%d", i)) spin(4000000) end
print("=== PROBE 1386a COMPLETE ===")
