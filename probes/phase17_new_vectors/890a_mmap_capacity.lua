-- CRASH_CLASS: LOW
-- PROBE 890a: GPU mmap capacity, and whether 637 changes it
--
-- Context: 888a mapped 256 MiB successfully once, then failed after the limit
-- was restored (C4). 889a then failed every 256 MiB request. The two runs
-- report the SAME pid (104), so the loader is very likely reusing one game
-- process across TCP connections -- which means 888a's 256 MiB allocation is
-- still present in 889a's address space, and "the arena is nearly full" can
-- explain C4 without syscall 637 doing anything.
--
-- This probe measures capacity in 64 MiB steps in the current process, then
-- asks 637 to raise the limit and retries. If capacity does not move, 637's
-- value is not enforced against GPU mappings at all.

print("=== PROBE 890a: MMAP CAPACITY ===")
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
local function show(tag, ok, rv)
    if not ok then
        print(string.format("  [%s] PCALL-FAIL", tag))
        return false
    end
    local h, l = get_hi_lo(rv)
    local failed = (l == 0xFFFFFFFF and h == 0xFFFFFFFF)
    print(string.format("  [%s] ret=0x%08X_%08X%s", tag, h, l, failed and "  <-- FAIL" or ""))
    return not failed
end

local sc20 = make_syscall(20)
local pid = 0
repeat
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
until true
print(string.format("[A] self pid = %u", pid))

local sc477 = make_syscall(477)
local function gpu_map(size)
    local ok, rv = pcall(function()
        return sc477(uint64(0), uint64(size), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    return ok, rv
end

local STEP = 0x4000000   -- 64 MiB
print("[B] 64 MiB steps until a failure (max 16):")
local total = 0
local first_fail = -1
for i = 1, 16 do
    local ok, rv = gpu_map(STEP)
    local good = show(string.format("step %d (total %d MiB)", i, total), ok, rv)
    if not good then
        first_fail = i
        break
    end
    total = total + 64
end
print(string.format("[B] mapped before failure: %d MiB", total))

local sc637 = make_syscall(637)
print("[C] raise the limit, then retry one step:")
local okc, rvc = pcall(function() return sc637(uint64(pid), uint64(0x100000000)) end)
show("637(pid,4GiB)", okc, rvc)
local okr, rvr = gpu_map(STEP)
local goodr = show("retry step", okr, rvr)
print(string.format("[C] retry after raised limit: %s", goodr and "OK" or "still FAIL"))

print("[D] lower the limit to 64 MiB, then retry:")
local okd, rvd = pcall(function() return sc637(uint64(pid), uint64(0x4000000)) end)
show("637(pid,64MiB)", okd, rvd)
local okl, rvl = gpu_map(STEP)
local goodl = show("retry under 64MiB", okl, rvl)
print(string.format("[D] retry under small limit: %s", goodl and "OK" or "FAIL"))

print("")
print("=== PROBE 890a DONE ===")
