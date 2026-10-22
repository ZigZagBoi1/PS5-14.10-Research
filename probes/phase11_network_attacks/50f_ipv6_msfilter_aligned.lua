-- CRASH_CLASS: MODERATE
-- Probe 50f: aligned __msfilterreq reachability, no race.
-- FreeBSD layout on amd64: fields at 0/4/8, padding at 12,
-- sockaddr_storage at 16 (128 bytes, 8-byte alignment), pointer at 144,
-- sizeof(__msfilterreq) = 152. Compare valid and malformed inputs.

print("=== PROBE 50f: aligned IPV6_MSFILTER ===")

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
local function z(p, n)
    for i = 0, n - 1 do memory.write_byte(p + i, 0) end
end
local function b(p, i, v) memory.write_byte(p + i, v) end
local function d(p, i, v) memory.write_dword(p + i, v) end
local function result(label, fn)
    print("  BEFORE " .. label)
    local ok, rv = pcall(fn)
    if ok then print("  RESULT " .. label .. " " .. tostring(rv))
    else print("  RAISED " .. label .. " " .. tostring(rv)) end
    return ok and to_num(rv) or nil
end

local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41
local JOIN, LEAVE, MSFILTER = 12, 13, 74
local socket, setsockopt, close = sc(97), sc(105), sc(6)
local fd = to_num(socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print("  socket=" .. tostring(fd))
if fd < 0 or fd > 1024 then print("=== PROBE 50f ABORT ===") return end

local mreq = memory.alloc(32)
z(mreq, 32)
b(mreq, 0, 0xff); b(mreq, 1, 0x02); b(mreq, 15, 1) -- ff02::1
d(mreq, 16, 1) -- ifindex
local jr = result("join ff02::1 if=1", function()
    return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(JOIN), uint64(mreq), uint64(20))
end)
if jr ~= 0 then close(uint64(fd)); print("=== PROBE 50f NO MEMBERSHIP ==="); return end

local req = memory.alloc(160)
local function prep(mode, group_family)
    z(req, 160)
    d(req, 0, 1) -- ifindex
    d(req, 4, mode)
    d(req, 8, 0) -- no sources
    b(req, 16, 28) -- sockaddr_in6 length
    b(req, 17, group_family)
    b(req, 24, 0xff); b(req, 25, 0x02); b(req, 39, 1) -- ff02::1 at +16+8
    d(req, 16 + 24, 1) -- sin6_scope_id = ifindex
end
local function set(label, mode, family, size)
    prep(mode, family)
    return result(label, function()
        return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER), uint64(req), uint64(size))
    end)
end

set("valid INCLUDE 0src 152B", 1, AF_INET6, 152)
set("valid EXCLUDE 0src 152B", 2, AF_INET6, 152)
local src = memory.alloc(128)
z(src, 128)
b(src, 0, 28); b(src, 1, AF_INET6)
b(src, 8, 0x20); b(src, 9, 0x01); b(src, 23, 1) -- 2001::1
prep(1, AF_INET6)
d(req, 8, 1)
memory.write_qword(req + 144, src)
result("valid INCLUDE 1src copyin 152B", function()
    return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(MSFILTER), uint64(req), uint64(152))
end)
set("invalid mode 99 152B", 99, AF_INET6, 152)
set("short size 148B", 1, AF_INET6, 148)
set("invalid family 2 152B", 1, 2, 152)

result("leave ff02::1 if=1", function()
    return setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(LEAVE), uint64(mreq), uint64(20))
end)
close(uint64(fd))
print("=== PROBE 50f COMPLETE ===")
