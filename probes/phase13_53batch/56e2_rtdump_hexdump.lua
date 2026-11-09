-- CRASH_CLASS: LOW
-- PROBE 56e2: Hexdump NET_RT_DUMP messages with kernel-pointer hits
--
-- 56e found 5 kernel-pointer-shaped values at non-aligned offsets in
-- routing dump. Need to verify: real kernel pointers or false positives
-- from sockaddr boundary crossings (e.g., netmask FF FF FF 00 followed
-- by small sockaddr fields).
-- Strategy: full hexdump of messages 1-17, annotate sockaddr boundaries.

print("=== PROBE 56e2: RT DUMP HEXDUMP ===")
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
local function rb(buf, off)
    local dw = rd(N(buf) + (off - off % 4))
    if not dw then return 0 end
    local shift = (off % 4) * 8
    return math.floor(dw / (2 ^ shift)) % 256
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc_sysctl = mk(202)

-- NET_RT_DUMP
local mib = memory.alloc(24)
wd(N(mib), 4)       -- CTL_NET
wd(N(mib) + 4, 17)  -- PF_ROUTE
wd(N(mib) + 8, 0)   -- protocol
wd(N(mib) + 12, 0)  -- af=0
wd(N(mib) + 16, 1)  -- NET_RT_DUMP
wd(N(mib) + 20, 0)

local oldlenp = memory.alloc(8)
wq(oldlenp, uint64(0))
sc_sysctl(uint64(N(mib)), uint64(6), uint64(0), uint64(N(oldlenp)), uint64(0), uint64(0))
local _, need = get_hi_lo(rq(N(oldlenp)))
print(string.format("need=%d bytes", need))

if need == 0 or need > 0x100000 then
    print("ABORT")
    return
end

local outbuf = memory.alloc(need + 256)
for i = 0, math.min(need + 255, 0xFFFF), 4 do wd(N(outbuf) + i, 0) end
wq(oldlenp, uint64(need + 256))
local ret = sc_sysctl(uint64(N(mib)), uint64(6), uint64(N(outbuf)), uint64(N(oldlenp)), uint64(0), uint64(0))
local _, got = get_hi_lo(rq(N(oldlenp)))
print(string.format("ret=%d got=%d bytes", N(ret), got))

if got == 0 then print("ABORT: no data"); return end

-- Parse and hexdump each message
local pos = 0
local msg_num = 0

while pos < got and msg_num < 20 do
    local msglen = rb(outbuf, pos) + rb(outbuf, pos + 1) * 256
    if msglen < 4 or pos + msglen > got then break end
    msg_num = msg_num + 1

    local version = rb(outbuf, pos + 2)
    local mtype = rb(outbuf, pos + 3)
    local index = rb(outbuf, pos + 4) + rb(outbuf, pos + 5) * 256
    local flags_lo = rd(N(outbuf) + pos + 8) or 0
    local addrs = rd(N(outbuf) + pos + 12) or 0
    if addrs < 0 then addrs = addrs + 0x100000000 end

    -- Check for kernel pointers at stride 1
    local kptrs = {}
    for off = 0, msglen - 8 do
        local lo = rb(outbuf, pos + off) + rb(outbuf, pos + off + 1) * 256 +
                   rb(outbuf, pos + off + 2) * 65536 + rb(outbuf, pos + off + 3) * 16777216
        local hi = rb(outbuf, pos + off + 4) + rb(outbuf, pos + off + 5) * 256 +
                   rb(outbuf, pos + off + 6) * 65536 + rb(outbuf, pos + off + 7) * 16777216
        if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
            kptrs[#kptrs + 1] = {off = off, hi = hi, lo = lo}
        end
    end

    -- Only hexdump messages with kernel pointers, plus msg 1 for reference
    if #kptrs > 0 or msg_num == 1 then
        print(string.format("\n=== MSG#%d: type=%d ver=%d len=%d idx=%d flags=0x%X addrs=0x%X kptrs=%d ===",
            msg_num, mtype, version, msglen, index, flags_lo, addrs, #kptrs))

        -- RTA bitmask decode
        local rta_names = {"DST", "GW", "MASK", "GENMASK", "IFP", "IFA", "AUTHOR", "BRD"}
        local rta_bits = {}
        for bit = 0, 7 do
            if addrs % (2 ^ (bit + 1)) >= 2 ^ bit then
                rta_bits[#rta_bits + 1] = rta_names[bit + 1] or string.format("0x%X", 2 ^ bit)
            end
        end
        -- High bits
        for bit = 8, 15 do
            if addrs % (2 ^ (bit + 1)) >= 2 ^ bit then
                rta_bits[#rta_bits + 1] = string.format("bit%d", bit)
            end
        end
        print("  addrs: " .. table.concat(rta_bits, "+"))

        -- Print kernel pointers
        for _, kp in ipairs(kptrs) do
            print(string.format("  *** KPTR at +0x%02X: 0x%08X%08X ***", kp.off, kp.hi, kp.lo))
        end

        -- Full hexdump
        for row = 0, msglen - 1, 16 do
            local hex = {}
            local ascii = {}
            for j = 0, 15 do
                if row + j < msglen then
                    local b = rb(outbuf, pos + row + j)
                    hex[#hex + 1] = string.format("%02X", b)
                    if b >= 32 and b < 127 then
                        ascii[#ascii + 1] = string.char(b)
                    else
                        ascii[#ascii + 1] = "."
                    end
                else
                    hex[#hex + 1] = "  "
                    ascii[#ascii + 1] = " "
                end
            end
            -- Mark kernel pointer offsets
            local mark = "  "
            for _, kp in ipairs(kptrs) do
                if row <= kp.off and kp.off < row + 16 then mark = "<<" end
                if row <= kp.off + 7 and kp.off + 7 < row + 16 then mark = "<<" end
            end
            print(string.format("  +%03X: %s  %s %s", row, table.concat(hex, " "), table.concat(ascii), mark))
        end

        -- Parse sockaddrs after header (offset 0x98)
        local HDR = 0x98
        if msglen > HDR then
            print("  Sockaddrs:")
            local sa_pos = HDR
            local sa_idx = 0
            while sa_pos < msglen do
                local sa_len = rb(outbuf, pos + sa_pos)
                if sa_len == 0 then
                    -- Zero-length sa means 4-byte padding
                    sa_pos = sa_pos + 4
                    sa_idx = sa_idx + 1
                else
                    local sa_family = rb(outbuf, pos + sa_pos + 1)
                    local fam_name = "?"
                    if sa_family == 2 then fam_name = "INET"
                    elseif sa_family == 28 then fam_name = "INET6"
                    elseif sa_family == 18 then fam_name = "LINK"
                    elseif sa_family == 0 then fam_name = "UNSPEC" end
                    print(string.format("    sa#%d at +0x%02X: len=%d fam=%d(%s)",
                        sa_idx, sa_pos, sa_len, sa_family, fam_name))

                    -- Check if any kptr falls within this sockaddr
                    for _, kp in ipairs(kptrs) do
                        if kp.off >= sa_pos and kp.off < sa_pos + sa_len then
                            print(string.format("      ^^^ KPTR at sa+0x%02X ^^^", kp.off - sa_pos))
                        end
                    end

                    -- Advance, rounded up to 4-byte alignment
                    local advance = sa_len
                    if advance % 4 ~= 0 then advance = advance + (4 - advance % 4) end
                    if advance < 4 then advance = 4 end
                    sa_pos = sa_pos + advance
                    sa_idx = sa_idx + 1
                end
            end
        end
    end

    pos = pos + msglen
end

print(string.format("\nTotal: %d messages parsed", msg_num))
print("=== 56e2 COMPLETE ===")
