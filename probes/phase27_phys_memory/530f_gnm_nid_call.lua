-- CRASH_CLASS: MODERATE
-- PROBE 530f: Parse GnmDriver NID table and call submit function
--
-- 530e found the NID resolution table in GnmDriver .data:
-- Each 8-byte entry: {nid_hash(hi32):text_offset(lo32)}
-- NIDs are 0xFFFF4xxx pattern.
--
-- Known PS5 GNM NIDs (from PS5 SDK leaks / ps5-hen research):
-- sceGnmSubmitCommandBuffers: various candidates
-- sceGnmSubmitDone: signal completion
-- sceGnmGetGpuCoreClockFrequency: simple query, good test
--
-- Plan:
-- 1. Dump full NID table
-- 2. Call ALL functions with 0 args — the ones that don't crash are queries
-- 3. Try calling submit candidate functions with proper args

print("=== PROBE 530f: GNM NID TABLE + CALL ===")
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

-- Get GnmDriver
local gnm_ib = memory.alloc(0x200)
wd(N(gnm_ib), 0x160)
pcall(function() mk(593)(uint64(56), gnm_ib) end)
local gnm_text_lo = rd(N(gnm_ib) + 0x108) or 0
local gnm_text_hi = rd(N(gnm_ib) + 0x10C) or 0
if gnm_text_lo < 0 then gnm_text_lo = gnm_text_lo + 0x100000000 end
if gnm_text_hi < 0 then gnm_text_hi = gnm_text_hi + 0x100000000 end
local gnm_text = uint64(string.format("0x%X%08X", gnm_text_hi, gnm_text_lo))
print("gnm_text=" .. fmt(gnm_text))

-- Get .data
local sc_649 = mk(649)
local data_tb = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(3), uint64(data_tb)) end)
local gnm_data = rq(N(data_tb))
local gnm_data_n = N(gnm_data)
print("gnm_data=" .. fmt(gnm_data))

-- ============================================================
-- [A] Parse NID table
-- ============================================================
print("")
print("[A] NID table (full)")

local nids = {}
-- Start at .data + 8 (first entry was a version/header at +0x000)
for off = 8, 0x400 - 8, 8 do
    local v = rq(gnm_data_n + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end

        -- NID entries have 0xFFFF4xxx pattern in high dword
        if vh >= 0xFFFF4000 and vh <= 0xFFFF5000 then
            local nid = vh
            local text_off = vl
            table.insert(nids, {nid = nid, off = text_off, data_off = off})
        else
            -- End of NID table
            if #nids > 0 then break end
        end
    end
end

print(string.format("  %d NID entries found", #nids))
for i, e in ipairs(nids) do
    print(string.format("  [%2d] NID=0x%08X -> text+0x%04X", i, e.nid, e.off))
end

-- ============================================================
-- [B] Call each function with 0 args (safe probe)
-- Functions that return normally are queries/getters
-- ============================================================
print("")
print("[B] Call each (0 args)")

local safe_funcs = {}
local crash_funcs = {}

for i, e in ipairs(nids) do
    local addr = gnm_text + uint64(e.off)
    local ok_c, rv_c = pcall(function()
        return native.fcall_with_rax(addr, 0)
    end)
    local ret = -999
    if ok_c and rv_c then ret = N(rv_c) end

    if ok_c then
        table.insert(safe_funcs, {nid = e.nid, off = e.off, ret = ret})
        local hex = ""
        if ret >= 0 then hex = string.format(" (0x%X)", ret) end
        print(string.format("  NID 0x%08X text+0x%04X: OK rv=%d%s", e.nid, e.off, ret, hex))
    else
        table.insert(crash_funcs, {nid = e.nid, off = e.off})
        print(string.format("  NID 0x%08X text+0x%04X: CRASH", e.nid, e.off))
    end
end

print(string.format("  safe=%d crash=%d", #safe_funcs, #crash_funcs))

-- ============================================================
-- [C] For safe functions that returned 0: try with 1 arg
-- Submit functions typically take (count, cmd_addrs, sizes, ...)
-- sceGnmSubmitDone() takes 0 args and returns 0
-- ============================================================
print("")
print("[C] Submit candidate test")

-- Allocate test buffers
local ib2 = memory.alloc(0x200)
local alloc_fn = nil

-- Get libkernel for AllocateDirectMemory
local lk_ib = memory.alloc(0x200)
wd(N(lk_ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), lk_ib) end)
local lk_lo = rd(N(lk_ib) + 0x108) or 0
local lk_hi = rd(N(lk_ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
alloc_fn = lk_base + uint64(0x17EF0)

-- Allocate physical buffer for cmd
local dm_fd = N(native.fcall_with_rax(stub, 5,
    uint64(N(memory.alloc(0x20))), uint64(2), uint64(0)))
-- Actually need to write "/dev/dmem0" first
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i2 = 1, #dname do wd(N(devpath) + i2 - 1, string.byte(dname, i2)) end
wd(N(devpath) + #dname, 0)
dm_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))

local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local cmd_phys = rq(N(phys_out))
print("  cmd_phys=" .. fmt(cmd_phys))

-- Map it
local sc_477 = mk(477)
local cmd_ph, cmd_pl = get_hi_lo(cmd_phys)
if cmd_ph < 0 then cmd_ph = cmd_ph + 0x100000000 end
if cmd_pl < 0 then cmd_pl = cmd_pl + 0x100000000 end

local ok_m, rv_m = pcall(function()
    return sc_477(uint64(0), uint64(0x4000), uint64(3), uint64(1),
                   uint64(dm_fd), uint64(string.format("0x%X%08X", cmd_ph, cmd_pl)))
end)
local cmd_va = 0
if ok_m and rv_m then
    local rh = get_hi_lo(rv_m)
    if rh < 0 then rh = rh + 0x100000000 end
    if rh ~= 0xFFFFFFFF then cmd_va = N(rv_m) end
end
print("  cmd_va=0x" .. string.format("%X", cmd_va))

if cmd_va ~= 0 then
    -- Write a NOP PM4 packet
    wd(cmd_va, 0xC0FF1000)  -- NOP, big count (pad rest with zeros)
    for off = 4, 0x100, 4 do wd(cmd_va + off, 0) end

    -- For the submit call:
    -- sceGnmSubmitCommandBuffers(count, cmd_addrs[], cmd_sizes[], ...)
    -- Build: cmd_addrs[0] = cmd_va, cmd_sizes[0] = 0x100 (dwords? bytes?)
    local addrs = memory.alloc(0x10)
    wq(N(addrs), uint64(string.format("0x%X", cmd_va)))
    local sizes = memory.alloc(0x10)
    wd(N(sizes), 0x40)  -- 64 dwords

    -- Try calling safe functions that returned 0 with submit-like args
    -- Most PS5 GNM submit signatures:
    -- sceGnmSubmitCommandBuffers(u32 count, void** addrs, u32* sizes, ...)
    for _, sf in ipairs(safe_funcs) do
        if sf.ret == 0 then
            local addr = gnm_text + uint64(sf.off)
            -- Try with (1, addrs_array, sizes_array)
            local ok_s, rv_s = pcall(function()
                return native.fcall_with_rax(addr, 0,
                    uint64(1), uint64(N(addrs)), uint64(N(sizes)), uint64(0), uint64(0))
            end)
            local ret = rv_s and N(rv_s) or -999
            if ok_s and ret ~= sf.ret then
                -- Return value changed — this function reacted to our args
                print(string.format("  *** NID 0x%08X text+0x%04X: with_args rv=%d (was %d)",
                    sf.nid, sf.off, ret, sf.ret))
            end
        end
    end
end

print("")
print("=== 530f DONE ===")
