-- CRASH_CLASS: MODERATE
-- PROBE 69i: AIO 669 untested code paths — cmd=2 (write), class=2/3
--
-- All AIO testing so far used cmd=1 (read) and class=1.
-- The 669 submit handler may have different code paths for:
--   cmd=2 (write) — writes data TO the fd instead of reading
--   class=2/3 — may use different zones or different handling
--
-- Tests:
--   [A] cmd=2 write on /dev/zero
--   [B] cmd=2 write on socketpair (verify data delivery)
--   [C] class=2 with cmd=1
--   [D] class=3 with cmd=1
--   [E] class boundaries: 0, 4, 5, 255
--   [F] cmd boundaries: 0, 3, 4, 5, 255
--   [G] Cross-class poll/delete interop

print("=== PROBE 69i: AIO cmd=2 + class=2/3 ===")
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

local pid = N(mk(20)())
print("pid=" .. pid)
local function alive() return N(mk(20)()) == pid end

-- Ignore SIGSYS
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), uint64(N(sa_buf)), uint64(0)) end)

-- Open /dev/zero
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(2), uint64(0)))  -- O_RDWR=2
print("zero_fd=" .. fd_zero)

-- Create socketpair for write tests
local sp_fds = memory.alloc(16)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_fds))) end)
local sp0 = rd(N(sp_fds)) or -1
local sp1 = rd(N(sp_fds) + 4) or -1
print(string.format("socketpair: sp0=%d sp1=%d", sp0, sp1))

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(64)

-- Fill data_buf with recognizable pattern for write tests
for i = 0, 15 do wd(N(data_buf) + i * 4, 0xCAFE0000 + i) end

local function aio_submit(cmd, fd, cls)
    local req = memory.alloc(0x28)
    wq(N(req) + 0x00, uint64(0))          -- offset
    wq(N(req) + 0x08, uint64(16))         -- nbytes
    wq(N(req) + 0x10, uint64(N(data_buf)))-- buffer
    wq(N(req) + 0x18, uint64(N(result_buf)))
    wq(N(req) + 0x20, uint64(fd))         -- fd
    local id_out = memory.alloc(8); wd(N(id_out), 0)
    local ok, ret = pcall(function()
        return mk(669)(uint64(cmd), uint64(N(req)), uint64(1), uint64(cls), uint64(N(id_out)))
    end)
    local new_id = rd(N(id_out)) or 0
    return ok, N(ret or 0), new_id
end

local function aio_status(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(666)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_poll(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(664)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_delete(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(662)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function test_submit(label, cmd, fd, cls)
    if not alive() then
        print(string.format("  %s: *** PROCESS DEAD ***", label))
        return nil
    end
    local ok, ret, new_id = aio_submit(cmd, fd, cls)
    local st = 0xDEAD
    if new_id ~= 0 then st = aio_status(new_id) or 0xDEAD end
    print(string.format("  %s: ok=%s ret=%d id=0x%X sts=0x%08X",
        label, tostring(ok), ret, new_id, st))
    if new_id ~= 0 then
        aio_poll(new_id)
        aio_delete(new_id)
    end
    return new_id
end

print("")

-- ============================================================
-- [A] cmd=2 (write) on /dev/zero
-- ============================================================
print("[A] cmd=2 (write) on /dev/zero, class=1")
test_submit("cmd2_zero", 2, fd_zero, 1)
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [B] cmd=2 (write) on socketpair — does data arrive?
-- ============================================================
print("[B] cmd=2 (write) on socketpair sp1, class=1")
-- Write CAFE pattern via AIO write to sp1
local ok_b, ret_b, id_b = aio_submit(2, sp1, 1)
print(string.format("  submit: ok=%s ret=%d id=0x%X", tostring(ok_b), ret_b, id_b))
if id_b ~= 0 then
    local st_b = aio_status(id_b)
    print(string.format("  status=0x%08X", st_b or 0))
    aio_poll(id_b)

    -- Try to read from sp0 to see if data arrived
    local recv_buf = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(recv_buf) + i, 0) end
    local ok_rd, rv_rd = pcall(function()
        return mk(3)(uint64(sp0), uint64(N(recv_buf)), uint64(16))
    end)
    local bytes_read = N(rv_rd or 0)
    local word0 = rd(N(recv_buf)) or 0
    print(string.format("  read sp0: ok=%s bytes=%d first_word=0x%08X (expect 0xCAFE0000)",
        tostring(ok_rd), bytes_read, word0))
    if word0 == 0xCAFE0000 then
        print("  *** AIO WRITE DELIVERED DATA ***")
    end
    aio_delete(id_b)
end
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [C] class=2 with cmd=1 (read)
-- ============================================================
print("[C] class=2, cmd=1 read on /dev/zero")
test_submit("class2_read", 1, fd_zero, 2)
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [D] class=3 with cmd=1 (read)
-- ============================================================
print("[D] class=3, cmd=1 read on /dev/zero")
test_submit("class3_read", 1, fd_zero, 3)
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [E] class boundaries: 0, 4, 5, 255
-- ============================================================
print("[E] Class boundaries")
for _, cls in ipairs({0, 4, 5, 255}) do
    test_submit(string.format("class%d", cls), 1, fd_zero, cls)
    if not alive() then print("DEAD after class=" .. cls); return end
end
print("")

-- ============================================================
-- [F] cmd boundaries: 0, 3, 4, 5, 255
-- ============================================================
print("[F] Cmd boundaries")
for _, cmd in ipairs({0, 3, 4, 5, 255}) do
    test_submit(string.format("cmd%d", cmd), cmd, fd_zero, 1)
    if not alive() then print("DEAD after cmd=" .. cmd); return end
end
print("")

-- ============================================================
-- [G] Cross-class interop: submit class=2, poll/status/delete
-- ============================================================
print("[G] Cross-class interop")
-- Submit with each valid class and see if 664/666/662 work
for _, cls in ipairs({1, 2, 3}) do
    local ok_g, ret_g, id_g = aio_submit(1, fd_zero, cls)
    if id_g ~= 0 then
        local st_pre = aio_status(id_g)
        local poll_st = aio_poll(id_g)
        local st_post = aio_status(id_g)
        local del_st = aio_delete(id_g)
        print(string.format("  class=%d id=0x%X pre=0x%08X poll=0x%08X post=0x%08X del=0x%08X",
            cls, id_g, st_pre or 0, poll_st or 0, st_post or 0, del_st or 0))
    else
        print(string.format("  class=%d: no ID returned (ok=%s ret=%d)", cls, tostring(ok_g), ret_g))
    end
    if not alive() then print("DEAD after class=" .. cls); return end
end
print("")

-- Also test cmd=2 with class=2 and class=3
print("[G2] cmd=2 cross-class")
for _, cls in ipairs({1, 2, 3}) do
    test_submit(string.format("cmd2_class%d", cls), 2, fd_zero, cls)
    if not alive() then print("DEAD"); return end
end
print("")

print("alive=YES")
print("=== PROBE 69i COMPLETE ===")
