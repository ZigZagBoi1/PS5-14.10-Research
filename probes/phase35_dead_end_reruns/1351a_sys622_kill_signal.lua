-- CRASH_CLASS: HIGH
-- PROBE 1351a: is a lethal 622 command a catchable signal, or a silent process kill?
--
-- Context: 622 low cmd 0x00 and 0x01 stop the capture dead with no fault dump
-- (1346a/1347a/1348a). The loader installs its stack-pivot handler for SIGILL,
-- SIGBUS and SIGSEGV only (`.local/loader_payload/signal.lua:4`), and that
-- handler writes a 0x18-byte siginfo record plus 0x100 bytes of mcontext to the
-- client socket — a death that carries no dump is therefore not one of those
-- three signals. The remaining ways a syscall can end the process are another
-- fatal signal (SIGTRAP, SIGABRT, SIGEMT, SIGFPE, SIGSYS, SIGXCPU, ...) or a
-- deliberate kernel-side exit, which no signal disposition can stop.
--
-- This probe ignores every fatal signal that is not already handled and then
-- repeats the measured killer. Return value present  -> the kill is a signal,
-- and the range becomes sweepable with that disposition installed.
-- Canary missing                                      -> deliberate kill or
-- SIGKILL; the range stays one relaunch per command.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1346a_sys622_low_commands_20261109_104306.txt
--   results/phase35_dead_end_reruns/1347a_sys622_low_resume_20261109_104444.txt
--   results/phase35_dead_end_reruns/1348a_sys622_low_page_20261109_104528.txt
--   .local/loader_payload/signal.lua:1-20
--   probes/phase17_new_vectors/353b_lethal_reclassify.lua:41-57

print("=== PROBE 1351a: 622 KILL MECHANISM ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

local sc416 = make_syscall(416)
local sc477 = make_syscall(477)
local sc622 = make_syscall(622)
local getpid = make_syscall(20)

print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

-- SIG_IGN for every fatal signal the loader does not already own.
-- 4 (ILL), 10 (BUS) and 11 (SEGV) are the loader's own handler - leave them.
local ignore = {5, 6, 7, 8, 12, 24, 25, 26, 30, 31}
local sa = memory.alloc(0x80)
for i = 0, 0x7C, 4 do safe_wd(sa + i, 0) end
safe_wq(sa, 1) -- SIG_IGN
print("[1] sigaction(sig, SIG_IGN)")
for _, sig in ipairs(ignore) do
    local ok, ret = pcall(function() return sc416(uint64(sig), uint64(sa), uint64(0)) end)
    print(string.format("  sig %d -> %s", sig, ok and sgn(ret) or "EXC"))
end
local check = memory.alloc(0x80)
for i = 0, 0x7C, 4 do safe_wd(check + i, 0) end
pcall(function() sc416(uint64(12), uint64(0), uint64(check)) end)
print(string.format("  readback sig 12 handler=0x%X (1 = SIG_IGN)", safe_rd(check) or 0))

local page = to_num(sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
for i = 0, 0x3FF8, 4 do safe_wd(page + i, 0) end
local buf = memory.alloc(0x200)
print(string.format("  page=0x%X buf=0x%X", page, to_num(buf)))

local function call(cmd)
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), uint64(page), uint64(0x40), uint64(0))
    end)
    return ok and sgn(ret) or "PCALL-FAIL", safe_rd(buf)
end

print("")
print("[2] 622(0x01, 0, buf, page, 0x40) with fatal signals ignored")
local r, b = call(0x01)
print(string.format("  ret=%s buf=%s", tostring(r), sgn(b)))
print(string.format("  canary pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("[3] 622(0x00, 0, buf, page, 0x40)")
local r2, b2 = call(0x00)
print(string.format("  ret=%s buf=%s", tostring(r2), sgn(b2)))
print(string.format("  canary pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1351a COMPLETE ===")
