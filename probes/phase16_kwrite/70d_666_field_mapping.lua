-- CRASH_CLASS: LOW
-- PROBE 70d: Map exactly what 666 returns and which AIO object it reads from
--
-- Critical question: does 666's per-ID status dword come from R, I, Q, or D?
-- If from R (which has kernel pointers at +0x00/+0x08): reading freed R = KASLR
-- If from Q (which has count/pending/state): no kernel pointers
-- If from a separate table: no overlap with any freed object
--
-- METHOD: Submit AIO requests with DIFFERENT parameters and observe how
-- 666's return value changes. This maps the status dword to its source object.
--
-- Tests:
--   1. Compare 666 status for cmd=1 vs cmd=2 (different R objects, same Q)
--   2. Compare 666 status for class=1 vs class=2 (different zones?)
--   3. Submit, DON'T poll, check 666 (pre-completion status)
--   4. Submit, poll, check 666 (post-completion status)
--   5. Submit, poll, wait via 663, check 666 (post-wait status)
--   6. Multiple IDs sharing same batch (same D) - do they share 666 status?
--   7. OVERSIZED output: give 666 a huge output buffer, scan ALL written bytes

print("=== PROBE 70d: 666 FIELD MAPPING ===")
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

local pid = N(mk(20)())
print("pid=" .. pid)

-- /dev/zero fd
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)
local ok, zerofd = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local zfd = N(zerofd)
print("zero_fd=" .. zfd)

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(8)

-- Helper: submit one AIO request with given cmd and class
local function aio_one(cmd, class, fd)
    local req = memory.alloc(0x28)
    wq(req + 0x00, uint64(0))
    wq(req + 0x08, uint64(16))
    wq(req + 0x10, uint64(N(data_buf)))
    wq(req + 0x18, uint64(N(result_buf)))
    wq(req + 0x20, uint64(fd))
    local ids_buf = memory.alloc(8)
    wd(ids_buf, 0)
    local ok2, ret = pcall(function()
        return mk(669)(uint64(cmd), uint64(N(req)), uint64(1), uint64(class), uint64(N(ids_buf)))
    end)
    return rd(ids_buf) or 0, ok2 and N(ret) or -1
end

-- Helper: read 666 with large output buffer, return all modified dwords
local function read_666(aid, bufsize)
    bufsize = bufsize or 256
    local out = memory.alloc(bufsize + 16)
    for j = 0, bufsize - 1, 4 do wd(out + j, 0xCCCCCCCC) end
    local ids_buf = memory.alloc(8)
    wd(ids_buf, aid); wd(ids_buf + 4, 0)
    local ok2, ret = pcall(function()
        return mk(666)(uint64(N(ids_buf)), uint64(1), uint64(N(out)))
    end)
    local modified = {}
    local all_data = {}
    for j = 0, bufsize - 4, 4 do
        local v = rd(out + j)
        all_data[j] = v
        if v ~= 0xCCCCCCCC then
            modified[#modified + 1] = {off = j, val = v}
        end
    end
    return ok2 and N(ret) or -999, modified, all_data
end

-- Helper: read 664 with large output buffer
local function read_664(aid, bufsize)
    bufsize = bufsize or 256
    local out = memory.alloc(bufsize + 16)
    for j = 0, bufsize - 1, 4 do wd(out + j, 0xCCCCCCCC) end
    local ids_buf = memory.alloc(8)
    wd(ids_buf, aid); wd(ids_buf + 4, 0)
    local ok2, ret = pcall(function()
        return mk(664)(uint64(N(ids_buf)), uint64(1), uint64(N(out)))
    end)
    local modified = {}
    for j = 0, bufsize - 4, 4 do
        local v = rd(out + j)
        if v ~= 0xCCCCCCCC then
            modified[#modified + 1] = {off = j, val = v}
        end
    end
    return ok2 and N(ret) or -999, modified
end

-- Helper: read 663 with large output buffer
local function read_663(aid, wait_type, bufsize)
    bufsize = bufsize or 256
    local out = memory.alloc(bufsize + 16)
    for j = 0, bufsize - 1, 4 do wd(out + j, 0xCCCCCCCC) end
    local ids_buf = memory.alloc(8)
    wd(ids_buf, aid); wd(ids_buf + 4, 0)
    local ok2, ret = pcall(function()
        return mk(663)(uint64(N(ids_buf)), uint64(1), uint64(N(out)),
            uint64(wait_type), uint64(0), uint64(0))
    end)
    local modified = {}
    for j = 0, bufsize - 4, 4 do
        local v = rd(out + j)
        if v ~= 0xCCCCCCCC then
            modified[#modified + 1] = {off = j, val = v}
        end
    end
    return ok2 and N(ret) or -999, modified
end

print("")

-- [A] 666 output with 1KB buffer: how many bytes does it ACTUALLY write?
print("[A] 666 with 1KB sentinel buffer per ID")
local id_a, ret_a = aio_one(1, 1, zfd)
print(string.format("  id=0x%X submit_ret=%d", id_a, ret_a))

-- Check BEFORE poll
local r1, m1 = read_666(id_a, 1024)
print(string.format("  before_poll: ret=%d modified=%d", r1, #m1))
for _, e in ipairs(m1) do
    print(string.format("    +0x%03X: 0x%08X", e.off, e.val))
end

-- Poll
local ids_b = memory.alloc(8)
local st_b = memory.alloc(8)
wd(ids_b, id_a)
pcall(function() mk(664)(uint64(N(ids_b)), uint64(1), uint64(N(st_b))) end)
local poll_st = rd(st_b)
print(string.format("  poll status: 0x%08X", poll_st or 0))

-- Check AFTER poll
local r2, m2 = read_666(id_a, 1024)
print(string.format("  after_poll: ret=%d modified=%d", r2, #m2))
for _, e in ipairs(m2) do
    print(string.format("    +0x%03X: 0x%08X", e.off, e.val))
end
print("")

-- [B] 664 output with 1KB buffer
print("[B] 664 with 1KB sentinel buffer")
local id_b2, _ = aio_one(1, 1, zfd)
local r3, m3 = read_664(id_b2, 1024)
print(string.format("  before_poll: ret=%d modified=%d", r3, #m3))
for _, e in ipairs(m3) do
    print(string.format("    +0x%03X: 0x%08X", e.off, e.val))
end

-- Poll then recheck
wd(ids_b, id_b2)
pcall(function() mk(664)(uint64(N(ids_b)), uint64(1), uint64(N(st_b))) end)
local r4, m4 = read_664(id_b2, 1024)
print(string.format("  after_poll: ret=%d modified=%d", r4, #m4))
for _, e in ipairs(m4) do
    print(string.format("    +0x%03X: 0x%08X", e.off, e.val))
end
print("")

-- [C] 663 output with 1KB buffer (wait_type=0,1,2)
print("[C] 663 with 1KB sentinel buffer")
local id_c, _ = aio_one(1, 1, zfd)
wd(ids_b, id_c)
pcall(function() mk(664)(uint64(N(ids_b)), uint64(1), uint64(N(st_b))) end)

for _, wt in ipairs({0, 1, 2}) do
    local r5, m5 = read_663(id_c, wt, 1024)
    print(string.format("  wait_type=%d: ret=%d modified=%d", wt, r5, #m5))
    for _, e in ipairs(m5) do
        print(string.format("    +0x%03X: 0x%08X", e.off, e.val))
    end
end
print("")

-- [D] Compare status across cmd=1 vs cmd=2
print("[D] cmd=1 vs cmd=2 status comparison")
local id_cmd1, r_cmd1 = aio_one(1, 1, zfd)
local id_cmd2, r_cmd2 = aio_one(2, 1, zfd)
print(string.format("  cmd=1: id=0x%X ret=%d", id_cmd1, r_cmd1))
print(string.format("  cmd=2: id=0x%X ret=%d", id_cmd2, r_cmd2))

-- Poll both
for _, aid in ipairs({id_cmd1, id_cmd2}) do
    wd(ids_b, aid)
    pcall(function() mk(664)(uint64(N(ids_b)), uint64(1), uint64(N(st_b))) end)
end

local _, m_cmd1 = read_666(id_cmd1, 64)
local _, m_cmd2 = read_666(id_cmd2, 64)
print("  cmd=1 666:")
for _, e in ipairs(m_cmd1) do print(string.format("    +0x%02X: 0x%08X", e.off, e.val)) end
print("  cmd=2 666:")
for _, e in ipairs(m_cmd2) do print(string.format("    +0x%02X: 0x%08X", e.off, e.val)) end
print("")

-- [E] Compare status across class=1 vs class=2 vs class=3
print("[E] class=1 vs class=2 vs class=3 status comparison")
for _, cls in ipairs({1, 2, 3}) do
    local id_cls, r_cls = aio_one(1, cls, zfd)
    print(string.format("  class=%d: id=0x%X ret=%d", cls, id_cls, r_cls))
    if id_cls ~= 0 then
        wd(ids_b, id_cls)
        pcall(function() mk(664)(uint64(N(ids_b)), uint64(1), uint64(N(st_b))) end)
        local _, m_cls = read_666(id_cls, 64)
        for _, e in ipairs(m_cls) do
            print(string.format("    +0x%02X: 0x%08X", e.off, e.val))
        end
    end
end
print("")

-- [F] Multi-ID batch: do shared-D IDs return identical or different 666 status?
print("[F] Multi-ID batch sharing same D")
local batch_ids = {}
local batch_req = memory.alloc(0x28 * 8)
local batch_ids_buf = memory.alloc(8 * 8)
for i = 0, 7 do
    wq(batch_req + i * 0x28 + 0x00, uint64(0))
    wq(batch_req + i * 0x28 + 0x08, uint64(16))
    wq(batch_req + i * 0x28 + 0x10, uint64(N(data_buf)))
    wq(batch_req + i * 0x28 + 0x18, uint64(N(result_buf)))
    wq(batch_req + i * 0x28 + 0x20, uint64(zfd))
    wd(batch_ids_buf + i * 4, 0)
end
pcall(function()
    mk(669)(uint64(1), uint64(N(batch_req)), uint64(8), uint64(1), uint64(N(batch_ids_buf)))
end)
for i = 0, 7 do
    local aid = rd(batch_ids_buf + i * 4)
    if aid and aid ~= 0 then batch_ids[#batch_ids + 1] = aid end
end
print(string.format("  batch submitted: %d IDs", #batch_ids))

-- Poll all
for _, aid in ipairs(batch_ids) do
    wd(ids_b, aid)
    pcall(function() mk(664)(uint64(N(ids_b)), uint64(1), uint64(N(st_b))) end)
end

-- Read 666 on each
for _, aid in ipairs(batch_ids) do
    local _, m_batch = read_666(aid, 64)
    local vals = {}
    for _, e in ipairs(m_batch) do vals[#vals + 1] = string.format("+%X=%08X", e.off, e.val) end
    print(string.format("  id=0x%04X: %s", aid, table.concat(vals, " ")))
end
print("")

-- [G] Read 666 on ID=0 and ID=0xFFFFFFFF (invalid IDs)
print("[G] 666 on invalid IDs")
for _, bad_id in ipairs({0, 0xFFFF, 0xDEAD, 0xFFFFFFFF}) do
    local r_bad, m_bad = read_666(bad_id, 64)
    local vals = {}
    for _, e in ipairs(m_bad) do vals[#vals + 1] = string.format("+%X=%08X", e.off, e.val) end
    print(string.format("  id=0x%X: ret=%d %s", bad_id, r_bad, table.concat(vals, " ")))
end
print("")

-- Cleanup
for _, aid in ipairs(batch_ids) do
    wd(ids_b, aid)
    pcall(function() mk(662)(uint64(N(ids_b)), uint64(1), uint64(N(st_b))) end)
end

print("alive=YES")
print("=== PROBE 70d COMPLETE ===")
