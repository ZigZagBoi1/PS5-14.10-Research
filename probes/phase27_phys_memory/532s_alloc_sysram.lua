-- CRASH_CLASS: LOW
-- PROBE 532s: AllocateDirectMemory with system RAM range
--
-- AllocateDirectMemory(searchStart, searchEnd, len, align, memType, &physOut)
-- Normal: searchStart=0, searchEnd=0x150000000 → gives 0x110000000+
-- Question: can we request allocation in system RAM (< 0x100000000)?
-- Or with different memType values?
--
-- Also: what if we allocate with searchStart=0x100000000?
-- The GPU pool starts at 0x100000000. System RAM is below.

print("=== PROBE 532s: ALLOC SYSRAM ===")
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
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

-- Get libkernel base
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
local error_fn = lk + uint64(0x02E10)
local alloc_fn = lk + uint64(0x17EF0)
print("lk=" .. q(lk))

local function get_errno()
    local errno_val = -1
    pcall(function()
        local errno_ptr = native.fcall_with_rax(error_fn, 0)
        if errno_ptr and to_num(errno_ptr) ~= 0 then
            errno_val = rd(to_num(errno_ptr)) or -1
        end
    end)
    return errno_val
end

local sc_628 = make_syscall(628)

-- Helper: try allocate + map
local function try_alloc_map(label, start_a, end_a, mem_type)
    local phys_buf = memory.alloc(8); wq(phys_buf, uint64(0))
    local ok_a, rv_a = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            start_a, end_a, uint64(0x4000),
            uint64(0x4000), uint64(mem_type), uint64(phys_buf))
    end)
    local rvn = -999
    if ok_a then rvn = to_num(rv_a) end
    local errno_a = get_errno()
    local phys = rq(phys_buf)
    local pn = to_num(phys); if pn < 0 then pn = pn + 0x100000000 end

    local extra = ""
    if rvn == 0 and pn > 0 then
        extra = " phys=" .. q(phys)
        -- Try to map it
        local ok_m, va = pcall(function()
            return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
                uint64(3), uint64(0), phys)
        end)
        if ok_m and to_num(va) > 0 then
            extra = extra .. " VA=" .. q(va)
            -- Read first dword
            local v = rd(va)
            if v then
                if v < 0 then v = v + 0x100000000 end
                extra = extra .. string.format(" [0x%08X]", v)
            end
        else
            extra = extra .. " map_fail"
        end
    end
    print(string.format("  %-35s rv=%d e=%d%s", label, rvn, errno_a, extra))
end

-- [A] Normal allocation (baseline)
print("[A] Normal (GPU pool)")
try_alloc_map("start=0 end=0x150000000 t=0",
    uint64(0), uint64("0x150000000"), 0)

-- [B] System RAM range
print("")
print("[B] System RAM range attempts")
-- Range 0 to 0x100000000 (below GPU pool)
try_alloc_map("0-0x100000000 t=0",
    uint64(0), uint64("0x100000000"), 0)
try_alloc_map("0-0x100000000 t=1",
    uint64(0), uint64("0x100000000"), 1)
try_alloc_map("0-0x100000000 t=2",
    uint64(0), uint64("0x100000000"), 2)
try_alloc_map("0-0x80000000 t=0",
    uint64(0), uint64("0x80000000"), 0)

-- [C] Different memTypes with full range
print("")
print("[C] Different memTypes")
for mt = 0, 15 do
    try_alloc_map(string.format("full_range type=%d", mt),
        uint64(0), uint64("0x150000000"), mt)
end

-- [D] searchStart at specific locations
print("")
print("[D] Specific searchStart")
try_alloc_map("start=0x100000000",
    uint64("0x100000000"), uint64("0x150000000"), 0)
try_alloc_map("start=0x110000000",
    uint64("0x110000000"), uint64("0x150000000"), 0)
try_alloc_map("start=0x140000000",
    uint64("0x140000000"), uint64("0x150000000"), 0)

-- [E] Beyond the pool
print("")
print("[E] Beyond pool")
try_alloc_map("0x150000000-0x200000000",
    uint64("0x150000000"), uint64("0x200000000"), 0)
try_alloc_map("0x200000000-0x300000000",
    uint64("0x200000000"), uint64("0x300000000"), 0)

print("")
print("=== 532s DONE ===")
