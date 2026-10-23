-- CRASH_CLASS: LOW
-- PROBE 353a: AIO async detection — is sys 669 truly asynchronous?
--
-- All 352-series results used /dev/zero and /dev/urandom, which complete
-- instantly. If AIO is synchronous (completes inside the syscall), there's
-- no race window. If it's async, we can race fd-close (Relapse cousin).
--
-- Test: submit AIO READ on empty socketpair fd. No data available.
-- Case A: submit blocks until data → synchronous, no race window
-- Case B: submit returns immediately with pending state → ASYNC, race possible
-- Case C: submit returns error → kernel rejects non-seekable fds
--
-- Also test: submit AIO read on a pipe (read end, nothing written)
-- Also test: large read from /dev/urandom (slow operation)

print("=== PROBE 353a: AIO ASYNC DETECTION ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc_close = mk(6)
local sc_open = mk(5)
local sc_socketpair = mk(135)  -- socketpair(domain, type, protocol, sv)
local sc_pipe2 = mk(542)       -- pipe2(fildes, flags)
local sc_submit = mk(669)
local sc_poll = mk(664)
local sc_delete = mk(662)
local sc_write = mk(4)         -- write(fd, buf, nbytes)
local sc_read = mk(3)          -- read(fd, buf, nbytes)

-- Helper: open a path
local function open_dev(path, flags)
    local pbuf = memory.alloc(#path + 4)
    for i = 1, #path do wd(N(pbuf) + i - 1, string.byte(path, i)) end
    wd(N(pbuf) + #path, 0)
    local ret = nil
    pcall(function() ret = sc_open(pbuf, uint64(flags or 0), uint64(0)) end)
    if ret then
        local fd = sgn(ret)
        if fd >= 0 and fd < 0x10000 then return fd end
    end
    return -1
end

-- AIO descriptor builder
local reqs = memory.alloc(0x100)
local data = memory.alloc(0x4000)
local result = memory.alloc(0x100)
local ids = memory.alloc(0x100)

local function zero_aio()
    for off = 0, 0x3F, 4 do
        wd(N(reqs) + off, 0)
        wd(N(result) + off, 0)
        wd(N(ids) + off, 0)
    end
    for off = 0, 0xFF, 4 do wd(N(data) + off, 0) end
end

local function fill_req(off, len, fd)
    local base = N(reqs)
    wq(base + 0x00, uint64(off))           -- offset
    wq(base + 0x08, uint64(len))           -- byte_count
    wq(base + 0x10, data)                  -- data_ptr
    wq(base + 0x18, result)                -- result_ptr
    wd(base + 0x20, fd)                    -- fd
    wd(base + 0x24, 0)                     -- padding
end

local function aio_submit(cmd, fd, len, label)
    zero_aio()
    fill_req(0, len, fd)
    local ret = nil
    local t0 = os.clock()
    local ok = pcall(function()
        ret = sc_submit(uint64(cmd), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids)))
    end)
    local dt = os.clock() - t0
    local id_val = rd(N(ids)) or 0
    local res_val = rd(N(result)) or 0
    local d0 = rd(N(data)) or 0
    if ok and ret then
        print(string.format("  %s: submit=%d id=0x%X result=0x%08X data[0]=0x%08X dt=%.4fs",
            label, sgn(ret), id_val, res_val, d0, dt))
    else
        print(string.format("  %s: EXCEPTION dt=%.4fs", label, dt))
    end
    return ok and ret and sgn(ret) or -999, id_val, res_val
end

local function aio_poll(id_val, label)
    local states = memory.alloc(0x40)
    wd(N(states), 0)
    wd(N(ids), id_val)
    local ret = nil
    pcall(function()
        ret = sc_poll(uint64(N(ids)), uint64(1), uint64(N(states)))
    end)
    local st = rd(N(states)) or 0
    local res = rd(N(result)) or 0
    print(string.format("  %s: poll=%s state=0x%X result=0x%08X",
        label, ret and tostring(sgn(ret)) or "exc", st, res))
    return st
end

local function aio_delete(id_val)
    local states = memory.alloc(0x40)
    wd(N(states), 0)
    wd(N(ids), id_val)
    pcall(function() sc_delete(uint64(N(ids)), uint64(1), uint64(N(states))) end)
end

-- ============ TEST 1: Control — /dev/zero (instant) ============
print("[1] Control: AIO read from /dev/zero (should be instant)")
local fd_zero = open_dev("/dev/zero", 0)
print("  fd_zero=" .. fd_zero)
if fd_zero >= 0 then
    local sr, sid, sres = aio_submit(1, fd_zero, 16, "zero-read")
    if sid ~= 0 then
        aio_poll(sid, "zero-poll")
        aio_delete(sid)
    end
end

-- ============ TEST 2: Socketpair — empty read ============
print("")
print("[2] AIO read from EMPTY socketpair (critical test)")
local sv_buf = memory.alloc(16)
wd(N(sv_buf), 0)
wd(N(sv_buf) + 4, 0)
local sp_ret = nil
pcall(function()
    sp_ret = sc_socketpair(uint64(1), uint64(1), uint64(0), sv_buf)
end)
local sp_fd0 = rd(N(sv_buf)) or -1
local sp_fd1 = rd(N(sv_buf) + 4) or -1
print(string.format("  socketpair ret=%s fd0=%d fd1=%d",
    sp_ret and tostring(sgn(sp_ret)) or "exc", sp_fd0, sp_fd1))

if sp_fd0 >= 0 and sp_fd0 < 0x10000 then
    -- Read from fd0, no data written to fd1 yet
    local sr, sid, sres = aio_submit(1, sp_fd0, 16, "empty-socket-read")
    if sid ~= 0 then
        aio_poll(sid, "empty-poll-immed")
        -- If state != 0x3 (not completed), it might be pending!
        -- Write data to the other end and check again
        local wbuf = memory.alloc(16)
        for i = 0, 3 do wd(N(wbuf) + i * 4, 0xDEADBEEF) end
        pcall(function()
            sc_write(uint64(sp_fd1), wbuf, uint64(16))
        end)
        aio_poll(sid, "after-write-poll")
        -- Check if data arrived
        local got = rd(N(data)) or 0
        print(string.format("  data[0] after write = 0x%08X", got))
        aio_delete(sid)
    end
    pcall(function() sc_close(uint64(sp_fd0)) end)
    pcall(function() sc_close(uint64(sp_fd1)) end)
end

-- ============ TEST 3: Pipe — empty read ============
print("")
print("[3] AIO read from EMPTY pipe")
local pipe_buf = memory.alloc(16)
wd(N(pipe_buf), 0)
wd(N(pipe_buf) + 4, 0)
local pp_ret = nil
pcall(function()
    pp_ret = sc_pipe2(pipe_buf, uint64(0))
end)
local pp_rd = rd(N(pipe_buf)) or -1
local pp_wr = rd(N(pipe_buf) + 4) or -1
print(string.format("  pipe2 ret=%s rd=%d wr=%d",
    pp_ret and tostring(sgn(pp_ret)) or "exc", pp_rd, pp_wr))

if pp_rd >= 0 and pp_rd < 0x10000 then
    local sr, sid, sres = aio_submit(1, pp_rd, 16, "empty-pipe-read")
    if sid ~= 0 then
        aio_poll(sid, "pipe-poll-immed")
        -- Write to pipe
        local wbuf2 = memory.alloc(16)
        for i = 0, 3 do wd(N(wbuf2) + i * 4, 0xCAFEBABE) end
        pcall(function()
            sc_write(uint64(pp_wr), wbuf2, uint64(16))
        end)
        aio_poll(sid, "pipe-after-write")
        local got2 = rd(N(data)) or 0
        print(string.format("  data[0] after write = 0x%08X", got2))
        aio_delete(sid)
    end
    pcall(function() sc_close(uint64(pp_rd)) end)
    pcall(function() sc_close(uint64(pp_wr)) end)
end

-- ============ TEST 4: Large urandom read (timing) ============
print("")
print("[4] AIO read 0x4000 bytes from /dev/urandom (timing)")
local fd_urand = open_dev("/dev/urandom", 0)
print("  fd_urandom=" .. fd_urand)
if fd_urand >= 0 then
    local bigdata = memory.alloc(0x4000)
    -- Point data to the big buffer
    local base = N(reqs)
    zero_aio()
    wq(base + 0x00, uint64(0))
    wq(base + 0x08, uint64(0x4000))
    wq(base + 0x10, bigdata)
    wq(base + 0x18, result)
    wd(base + 0x20, fd_urand)
    wd(base + 0x24, 0)

    local t0 = os.clock()
    local ret = nil
    pcall(function()
        ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids)))
    end)
    local dt = os.clock() - t0
    local id_val = rd(N(ids)) or 0
    local res = rd(N(result)) or 0
    print(string.format("  submit=%s id=0x%X result=0x%08X dt=%.4fs",
        ret and tostring(sgn(ret)) or "exc", id_val, res, dt))
    if id_val ~= 0 then
        aio_poll(id_val, "urand-big-poll")
        aio_delete(id_val)
    end
    pcall(function() sc_close(uint64(fd_urand)) end)
end

-- ============ TEST 5: Submit then close fd immediately ============
print("")
print("[5] Submit AIO read, then close fd, then poll")
local fd_zero2 = open_dev("/dev/zero", 0)
print("  fd_zero2=" .. fd_zero2)
if fd_zero2 >= 0 then
    local sr, sid, sres = aio_submit(1, fd_zero2, 16, "pre-close-read")
    -- Close the fd immediately
    pcall(function() sc_close(uint64(fd_zero2)) end)
    print("  fd closed")
    if sid ~= 0 then
        -- Can we still poll/delete the AIO request?
        aio_poll(sid, "post-close-poll")
        aio_delete(sid)
        print("  delete OK")
    end
end

-- ============ TEST 6: Non-blocking socket AIO ============
print("")
print("[6] AIO read from O_NONBLOCK socket")
local sv2 = memory.alloc(16)
wd(N(sv2), 0); wd(N(sv2) + 4, 0)
pcall(function()
    sc_socketpair(uint64(1), uint64(2 + 0x800), uint64(0), sv2)  -- SOCK_DGRAM | O_NONBLOCK
end)
local nb_fd0 = rd(N(sv2)) or -1
local nb_fd1 = rd(N(sv2) + 4) or -1
print(string.format("  nb socketpair fd0=%d fd1=%d", nb_fd0, nb_fd1))
if nb_fd0 >= 0 and nb_fd0 < 0x10000 then
    local sr, sid, sres = aio_submit(1, nb_fd0, 16, "nb-empty-read")
    if sid ~= 0 then
        aio_poll(sid, "nb-poll")
        aio_delete(sid)
    end
    pcall(function() sc_close(uint64(nb_fd0)) end)
    pcall(function() sc_close(uint64(nb_fd1)) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 353a COMPLETE ===")
