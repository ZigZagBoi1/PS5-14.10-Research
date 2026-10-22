-- CRASH_CLASS: HIGH
-- PROBE 258a: what 560 debug_init(1) opens
--
-- 257a found 560(1) returns 0 where 560(0), 560(0x10) and the two-argument
-- shapes return -1, and then 561(0) killed the process before anything else
-- could be measured. A call named debug_init that succeeds is worth one probe on
-- its own: every candidate it could plausibly unlock was refused before it, so
-- each one is retried here after it and compared with the recorded refusal.
--
--   A  560(1), then the pid - a new pid means the call forked
--   B  656 dynlib_get_info_for_libdbg  (was -1 for every shape)
--   C  593 with mode 1                 (was -1; mode 0 works without this call)
--   D  634 thr_get_ucontext on this tid (was: returns 0, writes nothing)
--   E  mprotect to RWX on a mapped page (was -1, W^X)
--   F  643 chicken switches with 0xFFFFFFFF (was already 0 with no effect)
--
-- Nothing here is expected to kill, so a stop names the row that did.

print("=== PROBE 258a: what debug_init opens ===")
print("")

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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end
local function call(num, a, b, c, d, e, f)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0), e or uint64(0), f or uint64(0))
    end)
    if not ok then return nil end
    return rv
end
local function count_written(buf, size)
    local wrote, first, total = 0, nil, nil
    for off = 0, size - 4, 4 do
        local ok, v = pcall(function() return memory.read_dword(buf + off) end)
        if ok and v ~= nil then
            local n = to_num(v)
            if n ~= 0 then
                wrote = wrote + 1
                if first == nil then first = off end
                if total == nil then total = n end
            end
        end
    end
    return wrote, first, total
end

local BUF = memory.alloc(0x1000)
local function zero(buf, n)
    pcall(function() for o = 0, n - 4, 4 do memory.write_dword(buf + o, 0) end end)
end

print("[0] pid before = " .. tostring(pid()))

print("")
print("[A] 560(1) -> " .. q(call(560, uint64(1), uint64(0), uint64(0))))
print("    pid after  = " .. tostring(pid()))

print("")
print("[B] 656 dynlib_get_info_for_libdbg")
zero(BUF, 0x1000)
pcall(function() memory.write_dword(BUF, 0x160) end)
local rv = call(656, uint64(0), uint64(BUF), uint64(0))
local w, f, t = count_written(BUF, 0x200)
print(string.format("    656(0, struct{s=0x160}) -> %s wrote=%d%s first=%s  pid=%s",
    q(rv), w, f and (" first_val=" .. string.format("0x%X", t or 0)) or "", f and string.format("+0x%03X", f) or "-", tostring(pid())))

print("")
print("[C] 593 with mode 1")
zero(BUF, 0x1000)
pcall(function() memory.write_dword(BUF, 0x160) end)
rv = call(593, uint64(1), uint64(BUF), uint64(0))
w, f, t = count_written(BUF, 0x200)
print(string.format("    593(1, struct{s=0x160}) -> %s wrote=%d%s  pid=%s", q(rv), w,
    f and (" first=+0x" .. string.format("%03X", f) .. " val=" .. string.format("0x%X", t or 0)) or "", tostring(pid())))
zero(BUF, 0x1000)
pcall(function() memory.write_dword(BUF, 0x160) end)
rv = call(593, uint64(0), uint64(BUF), uint64(0))
w, f, t = count_written(BUF, 0x200)
print(string.format("    593(0, ...) control        -> %s wrote=%d%s  pid=%s", q(rv), w,
    f and (" first=+0x" .. string.format("%03X", f) .. " val=" .. string.format("0x%X", t or 0)) or "", tostring(pid())))

print("")
print("[D] 634 thr_get_ucontext on this pid's tid")
local sc432 = make_syscall(432)
local ok, tids = pcall(function()
    local b = memory.alloc(8)
    sc432(uint64(b))
    return to_num(memory.read_dword(b))
end)
zero(BUF, 0x1000)
if ok and tids ~= nil then
    rv = call(634, uint64(tids), uint64(BUF), uint64(0))
    w, f = count_written(BUF, 0x400)
    print(string.format("    634(tid %s) -> %s wrote=%d%s  pid=%s", tostring(tids), q(rv), w,
        f and (" first=+0x" .. string.format("%03X", f)) or "", tostring(pid())))
else
    print("    could not read this thread's tid")
end

print("")
print("[E] mprotect to RWX")
local page = call(477, uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local pn = to_num(page)
print("    mmap -> " .. q(page))
if pn > 0 and pn < 0x100000000000 then
    print("    74(mmap page, RX)  -> " .. q(call(74, uint64(pn), uint64(0x4000), uint64(5))) .. "  pid=" .. tostring(pid()))
    print("    74(mmap page, RWX) -> " .. q(call(74, uint64(pn), uint64(0x4000), uint64(7))) .. "  pid=" .. tostring(pid()))
end

print("")
print("[F] 643 chicken switches")
print("    643(0xFFFFFFFF) -> " .. q(call(643, uint64(0xFFFFFFFF), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 258a COMPLETE ===")
