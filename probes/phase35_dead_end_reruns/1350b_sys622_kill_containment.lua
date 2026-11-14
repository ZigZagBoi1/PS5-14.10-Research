-- CRASH_CLASS: HIGH (the whole point is to call a command that kills)
-- PROBE 1350b: 622 kill containment, second attempt
--
-- Context: 1350a (results/phase35_dead_end_reruns/1350a_sys622_kill_containment_20261109_110035.txt)
-- spawned its thread code but that code read a global `G`, and the new Lua
-- thread does not share the caller's globals: it failed with
--   [string "..."]:6: attempt to index global 'G' (a nil value)
-- so the 622 call never ran. The process survived because the thread only
-- raised a Lua error.
--
-- This version formats the addresses and the command straight into the thread
-- source, so the spawned chunk is self-contained. Everything else is the same
-- question: does a 622 kill take the whole process, or only the calling thread?
-- A thread-scoped kill turns the entire lethal low range into one sweep per
-- connection; a process kill keeps the cost at one relaunch per command.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1350a_sys622_kill_containment_20261109_110035.txt
--   results/phase17_new_vectors/1175a_loader_thread_api_20261104_160547.txt
--   results/phase35_dead_end_reruns/1351a_sys622_kill_signal_20261109_105100.txt

print("=== PROBE 1350b: 622 KILL CONTAINMENT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local sc477 = make_syscall(477)
local getpid = make_syscall(20)
local fd = 0
do
    local ok, v = pcall(function() return to_num(memory.read_qword(signal.fd_addr)) end)
    if ok then fd = v end
end

local shared = to_num(memory.alloc(0x40))
local page = to_num(sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
local buf = to_num(memory.alloc(0x200))
print(string.format("[0] pid=%d fd=%d page=0x%X buf=0x%X shared=0x%X",
    to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), fd, page, buf, shared))
if page == 0 then print("[!] mmap failed"); return end
safe_wq(shared, 0)

local function spin(n)
    local x = 0
    for i = 1, n do x = x + i end
    return x
end

local function stage(label, cmd, size, spins)
    safe_wq(shared, 0)
    print(string.format("[%s] spawn cmd=0x%X size=0x%X", label, cmd, size))
    local src = string.format([[
local S = 0x%X
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local t = {}
for k, v in pairs(syscall.pipe) do t[k] = v end
t.syscall_no = 622
setmetatable(t, getmetatable(syscall.pipe))
print("T-ENTER")
local okc, rv = pcall(function()
    return t(uint64(0x%X), uint64(0), uint64(0x%X), uint64(0x%X), uint64(0x%X), uint64(0))
end)
print("T-RETURNED ok=" .. tostring(okc))
memory.write_qword(uint64(S), uint64(0xC0DE))
]], shared, cmd, buf, page, size)
    local ok, res = pcall(run_lua_code_in_new_thread, src, { async = true, client_fd = fd })
    if not ok then
        print(string.format("[%s] spawn FAILED: %s", label, tostring(res)))
        return false
    end
    for i = 1, spins do
        print(string.format("[%s] MAIN-%d", label, i))
        spin(4000000)
    end
    local marker = safe_rq(shared)
    print(string.format("[%s] marker=0x%X %s", label, marker or 0,
        marker == 0xC0DE and "THREAD SURVIVED" or "NO-MARKER"))
    return marker == 0xC0DE
end

local a = stage("A", 0x01, 0x40, 40)
if a then
    stage("B", 0x00, 0x40, 30)
    stage("C", 0x400, 0x40, 30)
else
    print("[A] no marker - either the kill takes the process, or the thread died before storing")
end

print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1350b COMPLETE ===")
