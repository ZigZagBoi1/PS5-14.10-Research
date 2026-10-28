-- CRASH_CLASS: LOW
-- PROBE 73d: Does the kernel write back to the AIO request struct?
--
-- Every AIO probe reads the STATUS output buffer (662/663/666 3rd arg).
-- Nobody has checked whether the kernel ALSO writes back to the REQUEST
-- struct (the 0x28-byte record passed to 669 submit). If the kernel
-- writes kernel-derived values into the request struct, we can read
-- them back from userland since the request lives in our heap.
--
-- Request struct layout (stride 0x28):
--   +0x00 = offset (u64)
--   +0x08 = nbytes (u64)
--   +0x10 = buf (ptr)
--   +0x18 = result (u64) — bytes transferred? or kernel data?
--   +0x20 = fd (u64)
--
-- For each AIO lifecycle event (submit/poll/query/delete), we fill the
-- request with a known pattern and check what changed.

print("=== PROBE 73d: AIO REQUEST STRUCT WRITEBACK ===")
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

local function dump_req(label, req)
    print("  " .. label .. ":")
    for off = 0, 0x27, 8 do
        local q = rq(N(req) + off)
        local h, l = get_hi_lo(q)
        local tag = ""
        if h >= 0xFFFF8000 then tag = " *** KPTR ***" end
        print(string.format("    +0x%02X: %s%s", off, fmt(q), tag))
    end
end

-- Test 1: Basic lifecycle tracking
print("")
print("[A] Request struct lifecycle — /dev/zero read, 64 bytes")
do
    -- Allocate larger area to detect overwrites past 0x28
    local req = memory.alloc(0x80)
    local ids = memory.alloc(8)

    -- Fill with sentinel pattern (each qword distinct)
    wq(N(req) + 0x00, uint64(0))           -- offset = 0
    wq(N(req) + 0x08, uint64(64))          -- nbytes = 64
    wq(N(req) + 0x10, data_buf)            -- buf
    wq(N(req) + 0x18, uint64(0xAAAAAAAAAAAAAAAA))  -- result = sentinel
    wq(N(req) + 0x20, uint64(fd_zero))     -- fd
    -- Past 0x28: fill with distinct sentinels to detect overwrite
    wq(N(req) + 0x28, uint64(0xBBBBBBBBBBBBBBBB))
    wq(N(req) + 0x30, uint64(0xDDDDDDDDDDDDDDDD))
    wq(N(req) + 0x38, uint64(0xEEEEEEEEEEEEEEEE))

    dump_req("BEFORE 669 submit", req)

    local ret = N(sc669(uint64(1), req, uint64(1), uint64(1), ids))
    local id = rd(N(ids))
    if id and id < 0 then id = id + 0x100000000 end
    print(string.format("  669 ret=%d id=0x%X", ret, id or 0))
    dump_req("AFTER 669 submit", req)

    -- Check past-0x28 sentinels
    local past = rq(N(req) + 0x28)
    local h28, l28 = get_hi_lo(past)
    if h28 ~= 0xBBBBBBBB or l28 ~= 0xBBBBBBBB then
        print("  *** OVERWRITE past 0x28: " .. fmt(past) .. " ***")
    end

    if id and id > 0 then
        -- Poll
        pcall(function() sc664(uint64(id)) end)
        dump_req("AFTER 664 poll", req)

        -- 666 query
        local qbuf = memory.alloc(8)
        wd(N(qbuf), 0xCCCCCCCC)
        pcall(function() sc666(uint64(id), uint64(1), qbuf, uint64(0), uint64(0), uint64(0)) end)
        dump_req("AFTER 666 query", req)

        -- Delete
        local dbuf = memory.alloc(4)
        local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
        dump_req("AFTER 662 delete", req)
    end
end

-- Test 2: Different nbytes values
print("")
print("[B] Result word vs nbytes — does result = bytes transferred?")
for _, nbytes in ipairs({1, 8, 32, 128, 512, 4096, 0x4000}) do
    local req = memory.alloc(0x30)
    local ids = memory.alloc(8)
    local big_buf = memory.alloc(math.max(nbytes, 64))
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(nbytes))
    wq(N(req) + 0x10, big_buf)
    wq(N(req) + 0x18, uint64(0xDEADDEADDEADDEAD))
    wq(N(req) + 0x20, uint64(fd_zero))

    local ret = N(sc669(uint64(1), req, uint64(1), uint64(1), ids))
    local id = rd(N(ids))
    if id and id < 0 then id = id + 0x100000000 end

    -- Result after submit
    local rw_submit = rq(N(req) + 0x18)

    if id and id > 0 then
        pcall(function() sc664(uint64(id)) end)
        local rw_poll = rq(N(req) + 0x18)

        print(string.format("  nbytes=%5d: submit_rw=%s poll_rw=%s",
            nbytes, fmt(rw_submit), fmt(rw_poll)))

        -- Clean up
        local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
    else
        print(string.format("  nbytes=%5d: submit FAILED (ret=%d)", nbytes, ret))
    end
end

-- Test 3: Different fd types
print("")
print("[C] Result word with different fd types")
-- /dev/null
local fd_null = N(mk(5)(put_str("/dev/null"), uint64(0), uint64(0)))
-- socketpair
local sp_buf = memory.alloc(16)
local sp_ret = N(mk(135)(uint64(1), uint64(2), uint64(0), sp_buf))
local sp0 = (sp_ret == 0) and rd(N(sp_buf)) or -1
local sp1 = (sp_ret == 0) and rd(N(sp_buf) + 4) or -1

local fd_tests = {
    {"/dev/zero", fd_zero, "read"},
    {"/dev/null", fd_null, "read"},
}
if sp_ret == 0 and sp0 and sp0 > 0 then
    fd_tests[#fd_tests + 1] = {"socketpair", sp0, "read"}
    -- Write data so read completes
    pcall(function() mk(4)(uint64(sp1), data_buf, uint64(8)) end)
end

for _, ft in ipairs(fd_tests) do
    local req = memory.alloc(0x30)
    local ids = memory.alloc(8)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(64))
    wq(N(req) + 0x10, data_buf)
    wq(N(req) + 0x18, uint64(0xFEEDFEEDFEEDFEED))
    wq(N(req) + 0x20, uint64(ft[2]))

    local ret = N(sc669(uint64(1), req, uint64(1), uint64(1), ids))
    local id = rd(N(ids))
    if id and id < 0 then id = id + 0x100000000 end

    if id and id > 0 then
        pcall(function() sc664(uint64(id)) end)
        local rw = rq(N(req) + 0x18)
        local rwh, rwl = get_hi_lo(rw)
        local tag = ""
        if rwh >= 0xFFFF8000 then tag = " *** KPTR ***" end
        print(string.format("  %s (fd=%d): result_word=%s%s", ft[1], ft[2], fmt(rw), tag))

        local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
    else
        print(string.format("  %s (fd=%d): submit FAILED", ft[1], ft[2]))
    end
end

-- Test 4: cmd=2 (WRITE) — the kernel reads FROM the user buffer
print("")
print("[D] cmd=2 (write) request lifecycle")
do
    -- Need a writable fd — use socketpair
    if sp_ret == 0 and sp1 and sp1 > 0 then
        local req = memory.alloc(0x30)
        local ids = memory.alloc(8)
        -- Fill write buffer with known data
        for i = 0, 63 do wb(N(data_buf) + i, i) end
        wq(N(req) + 0x00, uint64(0))
        wq(N(req) + 0x08, uint64(64))
        wq(N(req) + 0x10, data_buf)
        wq(N(req) + 0x18, uint64(0xCAFECAFECAFECAFE))
        wq(N(req) + 0x20, uint64(sp1))

        local ret = N(sc669(uint64(2), req, uint64(1), uint64(1), ids))
        local id = rd(N(ids))
        if id and id < 0 then id = id + 0x100000000 end

        if id and id > 0 then
            pcall(function() sc664(uint64(id)) end)
            local rw = rq(N(req) + 0x18)
            print(string.format("  cmd=2 write: result_word=%s", fmt(rw)))
            dump_req("  cmd=2 AFTER poll", req)

            local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
            wd(N(ibuf), id)
            pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
        else
            print(string.format("  cmd=2 write: submit FAILED (ret=%d)", ret))
        end
    else
        print("  SKIP: no socketpair")
    end
end

-- Test 5: Class 2 and 3
print("")
print("[E] class=2 and class=3 request lifecycle")
for _, cls in ipairs({2, 3}) do
    local req = memory.alloc(0x30)
    local ids = memory.alloc(8)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(64))
    wq(N(req) + 0x10, data_buf)
    wq(N(req) + 0x18, uint64(0xBEEFBEEFBEEFBEEF))
    wq(N(req) + 0x20, uint64(fd_zero))

    local ret = N(sc669(uint64(1), req, uint64(1), uint64(cls), ids))
    local id = rd(N(ids))
    if id and id < 0 then id = id + 0x100000000 end

    if id and id > 0 then
        pcall(function() sc664(uint64(id)) end)
        local rw = rq(N(req) + 0x18)
        print(string.format("  class=%d: id=0x%X result_word=%s", cls, id, fmt(rw)))

        local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
    else
        print(string.format("  class=%d: submit FAILED (ret=%d)", cls, ret))
    end
end

-- Test 6: Multi-request batch (count>1) struct writeback
print("")
print("[F] Batch submit (count=4) struct writeback — stride check")
do
    local batch = memory.alloc(4 * 0x28 + 0x20)
    local ids = memory.alloc(32)
    for i = 0, 3 do
        local base = N(batch) + i * 0x28
        wq(base + 0x00, uint64(0))
        wq(base + 0x08, uint64(64))
        wq(base + 0x10, data_buf)
        wq(base + 0x18, uint64(0xAA00 + i))  -- distinct sentinel per slot
        wq(base + 0x20, uint64(fd_zero))
    end
    -- Past-end sentinel
    wq(N(batch) + 4 * 0x28, uint64(0xFFFFFFFFFFFFFFFF))

    local ret = N(sc669(uint64(1), batch, uint64(4), uint64(1), ids))
    print(string.format("  batch submit ret=%d", ret))

    -- Check each slot's result word
    for i = 0, 3 do
        local base = N(batch) + i * 0x28
        local rw = rq(base + 0x18)
        local id = rd(N(ids) + i * 4)
        if id and id < 0 then id = id + 0x100000000 end
        print(string.format("  slot[%d] id=0x%X result_word=%s", i, id or 0, fmt(rw)))
    end

    -- Check past-end sentinel
    local past = rq(N(batch) + 4 * 0x28)
    local ph, pl = get_hi_lo(past)
    if ph ~= 0xFFFFFFFF or pl ~= 0xFFFFFFFF then
        print("  *** OVERWRITE past batch end: " .. fmt(past) .. " ***")
    end
end

print("")
print("alive=YES")
print("=== PROBE 73d COMPLETE ===")
