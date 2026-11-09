-- CRASH_CLASS: LOW
-- PROBE 66b: dynlib_get_info2 (660) full dump + kernel pointer scan
--
-- 660 is the v2 filler for dynlib_get_info (593). The 13.60 decode shows
-- it's UNGATED with the same prologue as 593. It has never been tested
-- with real module handles — only with zeros (returned -1). The v2 struct
-- may include kernel pointer fields that 593 omits.
--
-- Convention: 660(id: u32, info: void*) — same as 593

print("=== PROBE 66b: DYNLIB INFO2 + KPTR SCAN ===")

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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("pid=" .. pid_val)

-- [A] Get valid handles from 593
print("")
print("-- A: valid handles --")
local info593 = memory.alloc(0x200)
local valid = {}
for h = 0, 50 do
    wd(N(info593), 0x160)
    for i = 4, 0x15C, 4 do wd(N(info593) + i, 0) end
    local ok, rv = pcall(function() return mk(593)(uint64(h), info593) end)
    if ok and N(rv) == 0 then
        valid[#valid + 1] = h
    end
end
print(string.format("  %d valid handles", #valid))

-- [B] Test 660 on each valid handle — dump full 0x160 and diff against 593
print("")
print("-- B: 660 vs 593 comparison --")

local info660 = memory.alloc(0x200)
local kptr_total = 0
local found_any = false

local hi = 1
while hi <= #valid and hi <= 10 do
    local h = valid[hi]

    -- Get 593 data
    wd(N(info593), 0x160)
    for i = 4, 0x15C, 4 do wd(N(info593) + i, 0) end
    pcall(function() mk(593)(uint64(h), info593) end)

    -- Get 660 data
    wd(N(info660), 0x160)
    for i = 4, 0x15C, 4 do wd(N(info660) + i, 0) end
    local ok, rv = pcall(function() return mk(660)(uint64(h), info660) end)
    local ret = ok and N(rv) or -999

    if ret == 0 then
        found_any = true
        -- Compare every qword and look for kernel pointers
        local diffs = 0
        local kptrs = 0
        local off = 0
        while off < 0x160 do
            local v593_lo = rd(N(info593) + off) or 0
            local v593_hi = rd(N(info593) + off + 4) or 0
            local v660_lo = rd(N(info660) + off) or 0
            local v660_hi = rd(N(info660) + off + 4) or 0

            -- Check for kernel pointer in 660 data
            if v660_hi >= 0xFFFF8000 and v660_hi ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                kptr_total = kptr_total + 1
                print(string.format("  ★ h=%d +0x%03X KPTR: %08X_%08X (593: %08X_%08X)",
                    h, off, v660_hi, v660_lo, v593_hi, v593_lo))
            end

            -- Check for diff
            if v660_lo ~= v593_lo or v660_hi ~= v593_hi then
                diffs = diffs + 1
                if diffs <= 5 then
                    print(string.format("  h=%d +0x%03X diff: 660=%08X_%08X 593=%08X_%08X",
                        h, off, v660_hi, v660_lo, v593_hi, v593_lo))
                end
            end
            off = off + 8
        end
        print(string.format("  h=%d: diffs=%d kptrs=%d", h, diffs, kptrs))
    else
        if hi <= 3 then
            print(string.format("  h=%d: 660 rv=%d", h, ret))
        end
    end
    hi = hi + 1
end

if not found_any then
    print("  660 returned error for ALL handles")
end

-- [C] Full hexdump of 660 result for first valid handle (if it worked)
if found_any then
    print("")
    print("-- C: full hexdump of 660 for handle " .. valid[1] .. " --")
    wd(N(info660), 0x160)
    for i = 4, 0x15C, 4 do wd(N(info660) + i, 0) end
    pcall(function() mk(660)(uint64(valid[1]), info660) end)

    local off = 0
    while off < 0x160 do
        local d0 = rd(N(info660) + off) or 0
        local d1 = rd(N(info660) + off + 4) or 0
        local d2 = rd(N(info660) + off + 8) or 0
        local d3 = rd(N(info660) + off + 12) or 0
        print(string.format("  +%03X: %08X %08X  %08X %08X", off, d0, d1, d2, d3))
        off = off + 16
    end
end

-- [D] Also test 656 (debug-unit gated) — single call determines gate status
print("")
print("-- D: 656 dynlib_get_info_for_libdbg --")
wd(N(info660), 0x160)
for i = 4, 0x15C, 4 do wd(N(info660) + i, 0) end
local ok656, rv656 = pcall(function() return mk(656)(uint64(valid[1] or 0), info660) end)
local ret656 = ok656 and N(rv656) or -999
print(string.format("  h=%d rv=%d", valid[1] or 0, ret656))
if ret656 == 0 then
    print("  ★ DEBUG GATE PASSED — dump available")
end

-- [E] Test 599 dynlib_process_needed_and_relocate
print("")
print("-- E: 599 process_needed_and_relocate --")
local ok599, rv599 = pcall(function() return mk(599)(uint64(0), uint64(0)) end)
print(string.format("  rv=%d", ok599 and N(rv599) or -999))

print(string.format("\nTOTAL kernel pointers found: %d", kptr_total))
print("=== 66b DONE ===")
