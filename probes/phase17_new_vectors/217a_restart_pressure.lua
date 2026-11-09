-- CRASH_CLASS: LOW
-- PROBE 217a: sample the counters a fresh loader process starts with
--
-- Context: a kill costs one loader process, and roughly fifteen to twenty
-- kills since boot make the game take longer and longer to bring the loader
-- back (9 s at first, 37/54/66/>90 s later, then the port stops accepting).
-- A power cycle clears it, so something accumulates in a process that does
-- NOT die with ours - the game, or the kernel.
--
-- This probe answers where the accumulation shows up. It reads only
-- counters, so it can be run once per restarted loader and compared:
--   624  VM operation counter (no args; +5 per mmap, zero jitter)
--   671  resource class query (0xFFFFFFFF, mode, outA, outB)
--   674  virtual_query_all region count for this process
--   593  dynlib_get_info module count (sanity: this is a fresh process)
-- If 624 or 671 climb across restarts they are system-wide, not per-process,
-- and become a way to read the console's state without the game's consent.
-- If everything resets to the same value, the accumulation is invisible from
-- here and only the recovery time can see it.

print("=== PROBE 217a: RESTART PRESSURE SAMPLE ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc20 = make_syscall(20)
local pid = to_num(pcall(function() return sc20() end) and sc20() or 0)
if pid == 0 then
    local ok, ret = pcall(function() return sc20() end)
    if ok then pid = to_num(ret) end
end

-- [624] VM operation counter
local ops624 = -1
do
    local sc624 = make_syscall(624)
    local ok, ret = pcall(function() return sc624() end)
    if ok then ops624 = to_num(ret) end
end

-- [593] module count, so a fresh process is recognisable
local mods593 = -1
do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc593 = make_syscall(593)
    local n = 0
    for h = 0, 63 do
        local ok, ret = pcall(function() return sc593(uint64(h), info) end)
        if ok and to_num(ret) == 0 then n = n + 1 end
    end
    mods593 = n
end

-- [674] VM region count for this process
local vm674 = -1
do
    local sc674 = make_syscall(674)
    local STRIDE = 72
    local MAX = 512
    local buf = memory.alloc(STRIDE * MAX)
    safe_wd(buf, 0)
    local countp = memory.alloc(16)
    safe_wd(countp, 0)
    safe_wd(countp + 4, 0)
    local ok, ret = pcall(function()
        return sc674(uint64(buf), uint64(STRIDE), uint64(MAX),
                     uint64(countp), uint64(0x40000000))
    end)
    if ok and to_num(ret) == 0 then
        vm674 = safe_rd(countp) or -1
    end
end

-- [671] resource class query, both modes
local function klass(mode)
    local sc671 = make_syscall(671)
    local outA = memory.alloc(16)
    local outB = memory.alloc(16)
    safe_wd(outA, 0)
    safe_wd(outB, 0)
    local ok, ret = pcall(function()
        return sc671(uint64(0xFFFFFFFF), uint64(mode), uint64(outA), uint64(outB))
    end)
    if ok and to_num(ret) == 0 then
        return (safe_rd(outA) or -1), (safe_rd(outB) or -1)
    end
    return -1, -1
end
local c1a, c1b = klass(1)
local c2a, c2b = klass(2)

print(string.format(
    "SAMPLE pid=%d ops624=%d mods593=%d vm674=%d c1=%d/%d c2=%d/%d",
    pid, ops624, mods593, vm674, c1a, c1b, c2a, c2b))
print("DONE")
