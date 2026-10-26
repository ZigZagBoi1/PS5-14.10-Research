-- CRASH_CLASS: MODERATE
-- PROBE 351a: the 23-command MSR interface, called for the first time
--
-- results/kernel_handlers/analysis/sys_625.md: four slots (command32, domain32,
-- index32, value64), a range test (command-1) <= 22, a jump table whose
-- selectors are unmapped, and several blocks that write a caller-controlled
-- 64-bit value to a fixed indexed MSR. There is no credential read in the root.
-- Nobody has ever called this number with a real command, so the first pass only
-- has to answer: which commands are reachable, and what do they return.
-- Values stay small and ordinary - PMU control words, not all-ones - so a live
-- console cannot be driven into an unknown hardware state by this probe.

print("=== PROBE 351a: SYS 625 COMMANDS ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end

local sc625 = make_syscall(625)

local function call(cmd, dom, idx, val)
    local ok, rv = pcall(function()
        return sc625(uint64(cmd), uint64(dom), uint64(idx), uint64(val),
            uint64(0), uint64(0))
    end)
    if not ok then return "EXC" end
    local h, l = get_hi_lo(rv)
    local hi, lo = to_num(h), to_num(l)
    if hi == 0xFFFFFFFF and lo == 0xFFFFFFFF then return -1 end
    if hi ~= 0 then return string.format("%08X_%08X", hi, lo) end
    return sgn(rv)
end

print("[A] command sweep, everything else zero")
for cmd = 0, 24 do
    print(string.format("  cmd=%2d dom=0 idx=0 val=0 -> %s", cmd, tostring(call(cmd, 0, 0, 0))))
end

print("[B] the three selectors the dossier calls out")
for cmd = 1, 23 do
    local a = call(cmd, 1, 0, 0)
    if a ~= 22 and a ~= 6 then
        print(string.format("  cmd=%2d dom=1 idx=0 val=0 -> %s", cmd, tostring(a)))
        print(string.format("  cmd=%2d dom=2 idx=0 val=0 -> %s", cmd, tostring(call(cmd, 2, 0, 0))))
        print(string.format("  cmd=%2d dom=0 idx=-1 val=0x400000 -> %s", cmd, tostring(call(cmd, 0, 0xFFFFFFFF, 0x400000))))
    end
end

print("[C] index boundaries on whichever commands answered")
for _, cmd in ipairs({ 1, 2, 3, 4, 5 }) do
    for _, idx in ipairs({ 0, 5, 6, 7, 0xFFFFFFFF }) do
        local r = call(cmd, 1, idx, 0x400000)
        if r ~= 22 and r ~= 6 then
            print(string.format("  cmd=%d dom=1 idx=%d -> %s", cmd, idx, tostring(r)))
        end
    end
end

print("")
print("=== 351a DONE ===")
