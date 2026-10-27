-- CRASH_CLASS: LOW
-- PROBE 821b: what does mprotect(74) actually validate?
--
-- 821a: mmap refuses every kernel VA, but mprotect(0xFFFFFFFF8A9C0000,
-- 0x4000, 3) returned 0 and the process kept running. Either mprotect
-- ignores unmapped kernel addresses, or it talks to a different map. This
-- sweep separates the cases: a real mprotect must fail on unmapped ranges.

print("=== PROBE 821b: mprotect validation ===")
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
local function u(v)
    if type(v) == "table" then
        return uint64(to_num(v.h or 0)) * uint64(4294967296) + uint64(to_num(v.l or 0))
    end
    return uint64(v)
end

local function hx(v)
    if type(v) == "table" then
        return string.format("%08X%08X", to_num(v.h or 0), to_num(v.l or 0))
    end
    return string.format("%016X", v)
end

local sc_mprot = make_syscall(74)
local sc_mmap  = make_syscall(477)

-- a real, mapped page as the control: mmap, not memory.alloc, so the
-- allocator never touches it
local sc_mmap0 = make_syscall(477)
local ctl_raw = -1
pcall(function() ctl_raw = to_num(sc_mmap0(u(0), u(0x4000), u(3), u(0x1002), u(-1), u(0))) end)
local ctl_addr = u(ctl_raw)

local cases = {
    { "control (mapped)",     ctl_addr,               0x4000 },
    { "zero page",            0x0000000000000000,     0x4000 },
    { "low 0x10",             0x0000000000000010,     0x4000 },
    { "0x1000",               0x0000000000001000,     0x4000 },
    { "unmapped 0x7FFF00000000", 0x00007FFF00000000,  0x4000 },
    { "kernel neg",           0xFFFF800000000000,     0x4000 },
    { "13.60 kbase",          0xFFFFFFFF8A9C0000,     0x4000 },
    { "13.60 ktop",           0xFFFFFFFF8C140000,     0x4000 },
    { "max-0x4000",           0xFFFFFFFFFFFFC000,     0x4000 },
    { "control len 0",        ctl_addr,               0 },
    { "kbase len 0",          0xFFFFFFFF8A9C0000,     0 },
    { "control huge len",     ctl_addr,               0xFFFFFFFFFFFFF000 },
}

for _, c in ipairs(cases) do
    local r = -1
    pcall(function() r = to_num(sc_mprot(u(c[2]), u(c[3]), u(3))) end)
    print(string.format("[A] %-24s addr=%s len=%016X prot=3 ret=%d", c[1], hx(c[2]), c[3], r))
end
print("")

-- prot matrix on the kernel base only
for _, prot in ipairs({0, 1, 2, 3, 4, 5, 7}) do
    local r = -1
    pcall(function() r = to_num(sc_mprot(u(0xFFFFFFFF8A9C0000), u(0x4000), u(prot))) end)
    print(string.format("[B] kbase prot=%d ret=%d", prot, r))
end
print("")

-- control: a fresh mmap'd page, prot 3 -> 0, prot 4 (exec) -> ?
local p = -1
pcall(function() p = to_num(sc_mmap(u(0), u(0x4000), u(3), u(0x1002), u(-1), u(0))) end)
print(string.format("[C] mmap page=%s", hx(p)))
if p ~= -1 and p ~= 0xFFFFFFFFFFFFFFFF then
    for _, prot in ipairs({0, 3, 5}) do
        local r = -1
        pcall(function() r = to_num(sc_mprot(u(p), u(0x4000), u(prot))) end)
        print(string.format("[C] mapped-page prot=%d ret=%d", prot, r))
    end
end
print("[D] survived")
