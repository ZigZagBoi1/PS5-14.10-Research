-- CRASH_CLASS: LOW
-- PROBE 557d: AIO fd comparison — which devices support AIO completion?
--
-- 557c: ALL urandom AIO entries stuck at state=0x1 from the very first batch.
-- 555k/556a WORKED with socketpairs. Hypothesis: /dev/urandom doesn't support
-- the AIO dispatch path. This would mean 540c's "64/64 swaps" were just
-- stuck entries, not type confusion.
--
-- Test: submit AIO reads on multiple fd types, compare completion behavior.

print("=== PROBE 557d: AIO FD COMPARISON ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local Z = uint64(0)
local sc5   = mk(5)
local sc6   = mk(6)
local sc20  = mk(20)
local sc135 = mk(135)
local sc240 = mk(240)
local sc477 = mk(477)
local sc662 = mk(662)
local sc664 = mk(664)
local sc666 = mk(666)
local sc669 = mk(669)
local sc670 = mk(670)

local pid = N(sc20())
print("pid=" .. pid)

-- AIO init — check return value!
local ok_init, rv_init = pcall(function() return sc670(Z, Z, Z, Z, Z, Z) end)
print("sc670 init rv=" .. (ok_init and N(rv_init) or "CRASH"))

-- Helpers
local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)
local ts_buf   = memory.alloc(16)

local function aio_submit(fd, mode)
    local db = memory.alloc(64)
    local rb = memory.alloc(16)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))     -- length
    wq(reqs_buf + 0x10, uint64(N(db)))  -- data buf
    wq(reqs_buf + 0x18, uint64(N(rb)))  -- result buf
    wd(reqs_buf + 0x20, fd)
    wd(reqs_buf + 0x24, 0)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(N(reqs_buf)), uint64(1), uint64(mode or 1), uint64(N(ids_out)))
    end)
    return (ok and N(rv) or -999), (rd(ids_out) or 0)
end

local function aio_poll(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc664(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function aio_delete(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc662(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function aio_cancel(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc666(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function sleep_ms(ms)
    wq(uint64(N(ts_buf)), Z)
    wq(uint64(N(ts_buf) + 8), uint64(ms * 1000000))
    pcall(function() sc240(uint64(N(ts_buf)), Z) end)
end

local sv = memory.alloc(16)

local function test_fd(label, fd, do_close_write, write_fd, do_cancel)
    print(string.format("\n--- %s (fd=%d) ---", label, fd))

    -- Submit with mode=1 (read) and mode=3
    for _, mode in ipairs({1, 3}) do
        local rv, id = aio_submit(fd, mode)
        if rv ~= 0 then
            print(string.format("  mode=%d: submit FAIL rv=%d", mode, rv))
        else
            print(string.format("  mode=%d: id=0x%X", mode, id))

            -- Poll immediately
            local st0 = aio_poll(id)
            print(string.format("    immediate poll: 0x%X", st0))

            -- If requested, close write end (for socketpairs)
            if do_close_write and write_fd then
                pcall(function() sc6(uint64(write_fd)) end)
            end

            -- Wait 500ms
            sleep_ms(500)
            local st1 = aio_poll(id)
            print(string.format("    after 500ms: 0x%X", st1))

            -- Cancel
            if do_cancel and st1 < 3 then
                local cst = aio_cancel(id)
                print(string.format("    cancel: 0x%X", cst))
                sleep_ms(100)
                local st2 = aio_poll(id)
                print(string.format("    after cancel: 0x%X", st2))
            end

            -- Try delete
            local dst = aio_delete(id)
            print(string.format("    delete: 0x%X %s", dst, dst == 0 and "OK" or "FAIL"))
        end
    end
end

-- ============================================================
-- TEST 1: Socketpair (KNOWN WORKING from 555k/556a)
-- ============================================================
print("========================================")
print("TEST 1: Socketpair (AF_UNIX, SOCK_DGRAM)")
local ok_sp, rv_sp = pcall(function()
    return sc135(uint64(1), uint64(2), Z, uint64(N(sv)))
end)
local sp_rd = rd(sv) or -1
local sp_wr = rd(sv + 4) or -1
print(string.format("socketpair: rd=%d wr=%d", sp_rd, sp_wr))
-- Write some data so read can complete
pcall(function()
    local wbuf = memory.alloc(16)
    wq(wbuf, uint64(0x4141414141414141))
    mk(4)(uint64(sp_wr), uint64(N(wbuf)), uint64(8))
end)
test_fd("socketpair+data", sp_rd, false, nil, true)
pcall(function() sc6(uint64(sp_rd)) end)
pcall(function() sc6(uint64(sp_wr)) end)

-- TEST 1b: Socketpair with write end closed (EOF)
print("")
print("TEST 1b: Socketpair (write end closed → EOF)")
local ok_sp2, rv_sp2 = pcall(function()
    return sc135(uint64(1), uint64(2), Z, uint64(N(sv)))
end)
local sp2_rd = rd(sv) or -1
local sp2_wr = rd(sv + 4) or -1
test_fd("socketpair+eof", sp2_rd, true, sp2_wr, true)
pcall(function() sc6(uint64(sp2_rd)) end)

-- ============================================================
-- TEST 2: /dev/urandom
-- ============================================================
print("")
print("========================================")
print("TEST 2: /dev/urandom")
local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_u, urand_fd = pcall(function() return sc5(uint64(N(urand_path)), Z, Z) end)
urand_fd = ok_u and N(urand_fd) or -1
print("urandom fd=" .. urand_fd)
test_fd("/dev/urandom", urand_fd, false, nil, true)

-- ============================================================
-- TEST 3: /dev/zero
-- ============================================================
print("")
print("========================================")
print("TEST 3: /dev/zero")
local zero_path = memory.alloc(16)
write_string(zero_path, "/dev/zero\0")
local ok_z, zero_fd = pcall(function() return sc5(uint64(N(zero_path)), Z, Z) end)
zero_fd = ok_z and N(zero_fd) or -1
print("zero fd=" .. zero_fd)
if zero_fd >= 0 then
    test_fd("/dev/zero", zero_fd, false, nil, true)
end

-- ============================================================
-- TEST 4: /dev/null
-- ============================================================
print("")
print("========================================")
print("TEST 4: /dev/null")
local null_path = memory.alloc(16)
write_string(null_path, "/dev/null\0")
local ok_n, null_fd = pcall(function() return sc5(uint64(N(null_path)), Z, Z) end)
null_fd = ok_n and N(null_fd) or -1
print("null fd=" .. null_fd)
if null_fd >= 0 then
    test_fd("/dev/null", null_fd, false, nil, true)
end

-- ============================================================
-- TEST 5: Socketpair + cancel (556a pattern)
-- ============================================================
print("")
print("========================================")
print("TEST 5: Socketpair + cancel + close (556a pattern)")
local ok_sp3, rv_sp3 = pcall(function()
    return sc135(uint64(1), uint64(1), Z, uint64(N(sv)))
end)
local sp3_rd = rd(sv) or -1
local sp3_wr = rd(sv + 4) or -1
print(string.format("socketpair: rd=%d wr=%d", sp3_rd, sp3_wr))

local rv5, id5 = aio_submit(sp3_rd, 3)
print(string.format("  submit mode=3: rv=%d id=0x%X", rv5, id5))
if rv5 == 0 and id5 > 0 then
    local st0 = aio_poll(id5)
    print(string.format("  immediate: 0x%X", st0))

    local cst = aio_cancel(id5)
    print(string.format("  cancel: 0x%X", cst))

    pcall(function() sc6(uint64(sp3_wr)) end)
    sleep_ms(200)

    local st1 = aio_poll(id5)
    print(string.format("  after cancel+close: 0x%X", st1))

    local dst = aio_delete(id5)
    print(string.format("  delete: 0x%X %s", dst, dst == 0 and "OK" or "FAIL"))
end
pcall(function() sc6(uint64(sp3_rd)) end)

-- ============================================================
-- TEST 6: Multiple socketpair entries (batch)
-- ============================================================
print("")
print("========================================")
print("TEST 6: Batch 16 socketpair entries")
local batch_ids = {}
local batch_rds = {}
local batch_wrs = {}
for i = 1, 16 do
    local ok_b, rv_b = pcall(function()
        return sc135(uint64(1), uint64(1), Z, uint64(N(sv)))
    end)
    batch_rds[i] = rd(sv) or -1
    batch_wrs[i] = rd(sv + 4) or -1
    local brv, bid = aio_submit(batch_rds[i], 3)
    if brv == 0 and bid > 0 then
        batch_ids[i] = bid
    else
        batch_ids[i] = 0
    end
end

-- Cancel all + close write ends
for i = 1, 16 do
    if batch_ids[i] > 0 then aio_cancel(batch_ids[i]) end
    pcall(function() sc6(uint64(batch_wrs[i])) end)
end
sleep_ms(300)

-- Poll all
local b_states = {}
for i = 1, 16 do
    if batch_ids[i] > 0 then
        local st = aio_poll(batch_ids[i])
        local key = string.format("0x%X", st)
        b_states[key] = (b_states[key] or 0) + 1
    end
end
print("  states after cancel+close:")
for k, v in pairs(b_states) do print("    " .. k .. " x" .. v) end

-- Delete all
local b_del = {}
for i = 1, 16 do
    if batch_ids[i] > 0 then
        local dst = aio_delete(batch_ids[i])
        local key = string.format("0x%X", dst)
        b_del[key] = (b_del[key] or 0) + 1
    end
end
print("  delete results:")
for k, v in pairs(b_del) do print("    " .. k .. " x" .. v) end

-- Close read ends
for i = 1, 16 do pcall(function() sc6(uint64(batch_rds[i])) end) end

-- ============================================================
-- Health check
-- ============================================================
print("")
print("[HEALTH]")
local ok_hsp, rv_hsp = pcall(function()
    return sc135(uint64(1), uint64(1), Z, uint64(N(sv)))
end)
local h_rd = rd(sv) or -1
local h_wr = rd(sv + 4) or -1
if h_rd >= 0 then
    local hrv, hid = aio_submit(h_rd, 3)
    if hrv == 0 and hid > 0 then
        aio_cancel(hid)
        pcall(function() sc6(uint64(h_wr)) end)
        sleep_ms(200)
        local hst = aio_poll(hid)
        local hdst = aio_delete(hid)
        print(string.format("  poll=0x%X del=0x%X → %s", hst, hdst,
            (hst >= 3 and hdst == 0) and "HEALTHY" or "UNHEALTHY"))
    end
    pcall(function() sc6(uint64(h_rd)) end)
end

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 557d DONE ===")
