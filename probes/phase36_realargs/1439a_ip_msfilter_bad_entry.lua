-- CRASH_CLASS: LOW
-- PROBE 1439a: IPv4 IP_MSFILTER -- what a bad source entry does to the list
--
-- 1435a made the v4 source filter measurable: join 224.0.0.1 with
-- ip_mreq.imr_interface = 0, then IP_MSFILTER (opt 74, 152-byte __msfilterreq)
-- with msfr_ifindex = 3.  Set and get both answer 0, numsrc is exact, and the
-- reply is n*128 bytes.
--
-- The set path has to allocate a new list, copy the caller's entries in, and
-- validate them.  FreeBSD's ip_msfilter does that in place on the caller's
-- copied array and only then swaps it into the group, guarded by
--   if ((error = ...) != 0) goto out;
-- so the order of "allocate / copy / validate / swap / free old" is what decides
-- whether a rejected request can leave the group holding a half-built list.
-- A v6 probe cannot see this -- its entries are validated against family 28 and
-- it was the audited path -- but the v4 entries are validated against family 2
-- and have never been measured.
--
-- Each shape sets a deliberately wrong list and then reads the list back, so the
-- observable is the *state of the group after a rejected request*:
--   set rejects AND get still shows the previous list  -> clean
--   set rejects AND get shows 0 / a partial list       -> the swap ran anyway
--   set rejects AND get faults or answers a wild numsrc -> corruption
--
-- Prior art:
--   1435a results/phase36_realargs/1435a_ip_msfilter_ifindex_20261109_164339.txt
--   1434a results/phase36_realargs/1434a_ip_mcast_surface_20261109_164244.txt
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--   1432a results/phase36_realargs/1432a_msfilter_tail_reuse_20261109_163702.txt
--   docs/PRIVATE_IPV6_MSFILTER_1360_STATIC_2026-10-22.md

print("=== PROBE 1439a: V4 MSFILTER BAD-ENTRY STATE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function z(p, n) for i = 0, n - 1 do memory.write_byte(p + i, 0) end end
local function b(p, i, v) memory.write_byte(p + i, v) end
local function d(p, i, v) memory.write_dword(p + i, v) end
local function rd(p, i) return to_num(memory.read_dword(p + i)) end

local AF_INET, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IP = 2, 2, 17, 0
local socket, getsockopt, setsockopt = sc(97), sc(118), sc(105)

local sock = -1
local buf = memory.alloc(0x400)
local glen = memory.alloc(16)

local function map(len)
    local ok, r = pcall(function()
        return sc(477)(uint64(0), uint64(len), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local v = to_num(r)
    if v < 0x10000 or v > 0x8000000000 then return nil end
    return v
end
local src = map(0x10000)
local dst = map(0x10000)
assert(src and dst, "mmap failed")

local function call_set(name, len)
    local ok, r = pcall(function()
        return setsockopt(uint64(sock), uint64(IPPROTO_IP), uint64(name),
            uint64(buf), uint64(len), uint64(0))
    end)
    if not ok then return "EXC" end
    return to_num(r)
end
local function call_get(name, claim, out)
    d(glen, 0, 152)   -- getsockopt takes the request size in *optlen
    d(glen, 4, 0)
    z(buf, 0x400)
    d(buf, 0, 3)                  -- msfr_ifindex
    d(buf, 4, 1)                  -- MCAST_INCLUDE
    d(buf, 8, claim)
    b(buf, 16, 16); b(buf, 17, AF_INET)
    b(buf, 20, 0xE0); b(buf, 21, 0); b(buf, 22, 0); b(buf, 23, 0x01)
    memory.write_qword(buf + 144, uint64(out or 0))
    local ok, r = pcall(function()
        return getsockopt(uint64(sock), uint64(IPPROTO_IP), uint64(name),
            uint64(buf), uint64(glen), uint64(0))
    end)
    if not ok then return "EXC", nil end
    return to_num(r), to_num(memory.read_dword(glen))
end

local function src_ok(i, tail)
    local e = src + i * 128
    z(e, 128)
    b(e, 0, 16); b(e, 1, AF_INET)
    b(e, 4, 0xE0); b(e, 5, 0x00); b(e, 6, 0x40); b(e, 7, tail)
end

local function src_blank(i)
    z(src + i * 128, 128)
end
local function src_bad(i, fam, len, a3)
    local e = src + i * 128
    z(e, 128)
    b(e, 0, len); b(e, 1, fam)
    b(e, 4, 0xE0); b(e, 5, 0x00); b(e, 6, 0x40); b(e, a3 or 7, 0xAA)
end

-- build the request header and set it
local function do_set(ix, nsrc, a1)
    z(buf, 0x400)
    d(buf, 0, ix)
    d(buf, 4, 1)
    d(buf, 8, nsrc)
    b(buf, 16, 16); b(buf, 17, AF_INET)
    b(buf, 20, 0xE0); b(buf, 21, 0); b(buf, 22, 0); b(buf, 23, (a1 or 0x01))
    memory.write_qword(buf + 144, uint64(src))
    return 152
end

-- read the group back and report its state
local function state(label)
    local rv = call_get(74, 1, dst)
    local got = rd(buf, 8)          -- the count the kernel wrote back
    local e = es()
    local first = "----"
    if type(rv) == "number" and rv == 0 then first = string.format("%08X", rd(dst, 0)) end
    local rv2 = call_get(74, 128, dst)
    local got2 = rd(buf, 8)
    print(string.format("    %-26s get1 rv=%-5s numsrc=%-3d d0=%-8s | get128 rv=%-5s numsrc=%d (%s)",
        label, tostring(rv), got or -1, first, tostring(rv2), got2 or -1, e))
end

sock = to_num(socket(uint64(AF_INET), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print(string.format("socket=%-4d", sock))

-- join 224.0.0.1 on the default interface
z(buf, 0x400)
b(buf, 0, 0xE0); b(buf, 1, 0); b(buf, 2, 0); b(buf, 3, 0x01)
d(buf, 4, 0)
print(string.format("join 224.0.0.1 -> %s", tostring(call_set(12, 8))))
print("")

-- ---------------------------------------------------------------
print("[A] baseline: a good 2-source list, then what a rejected request does")
src_ok(0, 0x11); src_ok(1, 0x12)
print(string.format("  set 2 good -> %s", tostring(call_set(74, do_set(3, 2, 0x01)))))
state("after good set")
print("")

local badshapes = {
    { "family 28 (v6)",      28, 16, 7 },
    { "family 0",             0, 16, 7 },
    { "family 255",         255, 16, 7 },
    { "len 0",                2,  0, 7 },
    { "len 128",              2, 128, 7 },
    { "len 17",               2, 17, 7 },
    { "family 2 addr index 24", 2, 16, 24 },
}

for _, sh in ipairs(badshapes) do
    src_blank(0); src_blank(1)
    src_bad(0, sh[2], sh[3], sh[4])
    local rv = call_set(74, do_set(3, 1, 0x01))
    print(string.format("[B] set 1 bad entry: %-24s -> %-5s (%s)",
        sh[1], tostring(rv), es()))
    state("state after rejection")
end
print("")

-- ---------------------------------------------------------------
print("[C] half-valid 128-entry list: does validation stop before the swap?")
for i = 0, 127 do
    if i < 64 then src_ok(i, i % 16) else src_bad(i, 28, 16, 7) end
end
print(string.format("  set 64 good + 64 bad -> %s (%s)", tostring(call_set(74, do_set(3, 128, 0x01))), es()))
state("after half-valid set")
print("")
for i = 0, 127 do
    if i < 64 then src_bad(i, 28, 16, 7) else src_ok(i, i % 16) end
end
print(string.format("  set 64 bad + 64 good -> %s (%s)", tostring(call_set(74, do_set(3, 128, 0x01))), es()))
state("after half-valid set 2")
print("")

-- ---------------------------------------------------------------
print("[D] interleave: good set, failed set, then read the list contents")
src_ok(0, 0x21); src_ok(1, 0x22)
print(string.format("  set 2 good -> %s", tostring(call_set(74, do_set(3, 2, 0x01)))))
state("good")
src_blank(0); src_bad(0, 28, 16, 7)
print(string.format("  set 1 bad  -> %s (%s)", tostring(call_set(74, do_set(3, 1, 0x01))), es()))
state("after failed set")
-- if the failed set left the group holding our bad bytes, the readback shows them
local rv = call_get(74, 1, dst)
if rv == 0 then
    print(string.format("    readback dwords: %08X %08X %08X %08X",
        rd(dst, 0), rd(dst, 4), rd(dst, 8), rd(dst, 12)))
end
print("")

print("[E] survivor check")
print(string.format("  get 74 -> %s", tostring((call_get(74, 1, dst)))))

print("")
print("=== PROBE 1439a COMPLETE ===")
