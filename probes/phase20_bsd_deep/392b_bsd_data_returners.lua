-- CRASH_CLASS: MODERATE
-- PROBE 392b: BSD syscalls that return data + unnamed slots
--
-- [A] sc125 deep buffer scan (returned ret=4 in 389c)
-- [B] fstatfs(397) with real fds (dev nodes, shm, sockets)
-- [C] socketex(113) with real AF/type combos
-- [D] __cap_rights_get(515) with real fds
-- [E] scan unnamed -1 slots with pointer args (91,94,151-153,364-370)
-- [F] getfsstat(395) with real buffer

print("=== PROBE 392b: BSD data returners ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

local function write_str(buf, s)
    zero_buf(buf, (#s + 8) - ((#s + 8) % 4))
    for i = 0, #s - 1, 4 do
        local dw = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #s then dw = dw + string.byte(s, idx) * (256 ^ j) end
        end
        wd(N(buf) + i, dw)
    end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

local function scan_buf(base, len, label)
    local mod = 0
    local kptrs = 0
    local first_nonzero = -1
    for off = 0, len - 4, 4 do
        local d = rd(N(base) + off)
        if d ~= 0xDEADDEAD and d ~= nil then
            mod = mod + 1
            if first_nonzero < 0 and d ~= 0 then first_nonzero = off end
        end
    end
    for off = 0, len - 8, 8 do
        local q = rq(N(base) + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                kptrs = kptrs + 1
                print(string.format("  %s +0x%02X: 0x%X%08X *** KPTR ***", label, off, h, l))
            end
        end
    end
    return mod, kptrs
end

local function fill_sentinel(buf, len)
    for i = 0, len - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end
end

-- ===================================================================
-- [A] syscall 125 deep scan
-- ===================================================================
print("[A] syscall 125")

local buf = memory.alloc(0x400)
fill_sentinel(buf, 0x400)

-- 125 with various arg orders — the previous probe showed ret=4
local ok_a1, rv_a1 = pcall(function()
    return mk(125)(buf, uint64(0x400))
end)
print(string.format("  125(buf, 0x400): ret=%d", ok_a1 and N(rv_a1) or -999))
local m1, k1 = scan_buf(buf, 0x400, "sc125-a")
print(string.format("  modified=%d dwords, kptrs=%d", m1, k1))

if m1 > 0 then
    -- Dump first 128 bytes
    for off = 0, 0x7C, 4 do
        local d = rd(N(buf) + off)
        if d ~= 0xDEADDEAD then
            print(string.format("  +%03X: %08X", off, d))
        end
    end
end

-- Try with (0, buf, size) — different arg order
fill_sentinel(buf, 0x400)
local ok_a2, rv_a2 = pcall(function()
    return mk(125)(uint64(0), buf, uint64(0x400))
end)
print(string.format("  125(0, buf, 0x400): ret=%d", ok_a2 and N(rv_a2) or -999))
local m2, k2 = scan_buf(buf, 0x400, "sc125-b")
if m2 > 0 then print(string.format("  modified=%d, kptrs=%d", m2, k2)) end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] fstatfs(397) with real fds
-- ===================================================================
print("[B] fstatfs(397)")

-- Open /dev/null to get a real fd
local dev_buf = memory.alloc(32)
write_str(dev_buf, "/dev/null")
local null_fd = -1
local ok_o, rv_o = pcall(function()
    return mk(5)(dev_buf, uint64(0), uint64(0))  -- open(2)
end)
if ok_o then null_fd = N(rv_o) end

-- Also try /dev/dce
write_str(dev_buf, "/dev/dce")
local dce_fd = -1
local ok_d, rv_d = pcall(function()
    return mk(5)(dev_buf, uint64(2), uint64(0))  -- O_RDWR
end)
if ok_d then dce_fd = N(rv_d) end

-- And shm fd
local shm_fd = -1
local ok_s, rv_s = pcall(function()
    return mk(482)(uint64(1), uint64(0x202), uint64(0x180))
end)
if ok_s then shm_fd = N(rv_s) end

-- And a socket
local sock_fd = -1
local ok_sk, rv_sk = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
if ok_sk then sock_fd = N(rv_sk) end

local fds_to_test = {}
if null_fd >= 0 then fds_to_test[#fds_to_test + 1] = {null_fd, "/dev/null"} end
if dce_fd >= 0 then fds_to_test[#fds_to_test + 1] = {dce_fd, "/dev/dce"} end
if shm_fd >= 0 then fds_to_test[#fds_to_test + 1] = {shm_fd, "shm"} end
if sock_fd >= 0 then fds_to_test[#fds_to_test + 1] = {sock_fd, "socket"} end

-- struct statfs is ~0x230 bytes on FreeBSD
local statfs_buf = memory.alloc(0x300)

for _, fd_info in ipairs(fds_to_test) do
    if not alive() then break end
    fill_sentinel(statfs_buf, 0x300)
    local ok_f, rv_f = pcall(function()
        return mk(397)(uint64(fd_info[1]), statfs_buf)
    end)
    local ret = ok_f and N(rv_f) or -999
    local m, k = scan_buf(statfs_buf, 0x300, fd_info[2])
    print(string.format("  fstatfs(%s, fd=%d): ret=%d mod=%d kptrs=%d",
        fd_info[2], fd_info[1], ret, m, k))

    if m > 0 then
        -- Dump first non-sentinel values
        local dumped = 0
        for off = 0, 0x100, 4 do
            local d = rd(N(statfs_buf) + off)
            if d ~= 0xDEADDEAD and d ~= 0 and dumped < 8 then
                print(string.format("    +%03X: %08X", off, d))
                dumped = dumped + 1
            end
        end
    end
end

-- Close fds
for _, fd_info in ipairs(fds_to_test) do
    pcall(function() mk(6)(uint64(fd_info[1])) end)
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] socketex(113) with real combos
-- ===================================================================
print("[C] socketex(113)")

-- socketex(domain, type, protocol, ???, ???, ???)
-- Try AF_INET/SOCK_STREAM with extra args
local combos = {
    {2, 1, 0, 0, 0, 0, "AF_INET/STREAM/zeros"},
    {2, 1, 6, 0, 0, 0, "AF_INET/STREAM/TCP/zeros"},
    {2, 1, 0, 1, 0, 0, "AF_INET/STREAM/0/1/0/0"},
    {2, 2, 17, 0, 0, 0, "AF_INET/DGRAM/UDP"},
    {1, 1, 0, 0, 0, 0, "AF_UNIX/STREAM"},
    {28, 1, 0, 0, 0, 0, "AF_INET6/STREAM"},
    {2, 3, 255, 0, 0, 0, "AF_INET/RAW/255"},
}

for _, c in ipairs(combos) do
    if not alive() then break end
    local ok_c, rv_c = pcall(function()
        return mk(113)(uint64(c[1]), uint64(c[2]), uint64(c[3]),
            uint64(c[4]), uint64(c[5]), uint64(c[6]))
    end)
    local ret = ok_c and N(rv_c) or -999
    if ret >= 0 then
        print(string.format("  113(%s): fd=%d ***", c[7], ret))
        pcall(function() mk(6)(uint64(ret)) end)
    end
end
-- If all -1, just report once
print("  all combos: ret=-1")

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] Unnamed slot sweep with pointer args
-- ===================================================================
print("[D] unnamed slot sweep")

local test_buf = memory.alloc(0x200)
local results_found = {}

-- These slots returned -1 to zeros but might respond to pointer args
local unnamed = {91, 94, 119, 151, 152, 153, 159, 167, 168, 172,
    177, 178, 179, 180, 184, 185, 186, 187,
    364, 365, 366, 367, 368, 369, 370, 375,
    380, 381, 382, 383, 418, 419, 420,
    434, 435, 440, 467, 468, 469, 470}

for _, num in ipairs(unnamed) do
    if not alive() then break end

    -- Try: (buf, size) — most common read pattern
    fill_sentinel(test_buf, 0x200)
    local ok1, rv1 = pcall(function()
        return mk(num)(test_buf, uint64(0x200))
    end)
    local ret1 = ok1 and N(rv1) or -999

    if ret1 >= 0 then
        local m, k = scan_buf(test_buf, 0x200, tostring(num))
        if m > 0 or k > 0 then
            results_found[#results_found + 1] = string.format(
                "  %d(buf, 0x200): ret=%d mod=%d kptrs=%d ***", num, ret1, m, k)
        else
            results_found[#results_found + 1] = string.format(
                "  %d(buf, 0x200): ret=%d (clean)", num, ret1)
        end
    end

    -- Try: (0, buf, size) — alternative pattern
    if ret1 < 0 and alive() then
        fill_sentinel(test_buf, 0x200)
        local ok2, rv2 = pcall(function()
            return mk(num)(uint64(0), test_buf, uint64(0x200))
        end)
        local ret2 = ok2 and N(rv2) or -999
        if ret2 >= 0 then
            local m, k = scan_buf(test_buf, 0x200, tostring(num))
            results_found[#results_found + 1] = string.format(
                "  %d(0, buf, 0x200): ret=%d mod=%d kptrs=%d", num, ret2, m, k)
        end
    end

    -- Try: (pid, buf, size) — process-info pattern
    if alive() then
        fill_sentinel(test_buf, 0x200)
        local ok3, rv3 = pcall(function()
            return mk(num)(uint64(pid_val), test_buf, uint64(0x200))
        end)
        local ret3 = ok3 and N(rv3) or -999
        if ret3 >= 0 and ret1 < 0 then
            local m, k = scan_buf(test_buf, 0x200, tostring(num))
            results_found[#results_found + 1] = string.format(
                "  %d(pid, buf, 0x200): ret=%d mod=%d kptrs=%d", num, ret3, m, k)
        end
    end
end

if #results_found == 0 then
    print("  all 40 slots: -1 for all arg patterns")
else
    for _, line in ipairs(results_found) do print(line) end
end

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] getfsstat(395/396)
-- ===================================================================
print("[E] getfsstat(395/396)")

-- getfsstat(buf, bufsize, mode) — MNT_NOWAIT=2
local fsbuf = memory.alloc(0x2000)

-- First call: NULL buf to get count
local ok_cnt, rv_cnt = pcall(function()
    return mk(395)(uint64(0), uint64(0), uint64(2))
end)
local count = ok_cnt and N(rv_cnt) or -1
print(string.format("  getfsstat(NULL, 0, NOWAIT): ret=%d (=count)", count))

-- 396 is the modern version
local ok_cnt2, rv_cnt2 = pcall(function()
    return mk(396)(uint64(0), uint64(0), uint64(2))
end)
print(string.format("  getfsstat(396, NULL): ret=%d", ok_cnt2 and N(rv_cnt2) or -999))

if count > 0 and alive() then
    fill_sentinel(fsbuf, 0x2000)
    local ok_fs, rv_fs = pcall(function()
        return mk(395)(fsbuf, uint64(0x2000), uint64(2))
    end)
    local ret_fs = ok_fs and N(rv_fs) or -1
    print(string.format("  getfsstat(buf, 0x2000): ret=%d", ret_fs))
    if ret_fs > 0 then
        local m, k = scan_buf(fsbuf, 0x2000, "getfsstat")
        print(string.format("  modified=%d, kptrs=%d", m, k))
    end
end

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] Quick test: some more interesting BSD calls
-- ===================================================================
print("[F] misc BSD")

-- aio_return(314) — might read from submitted AIO? No, but test anyway
local ok_ar, rv_ar = pcall(function() return mk(314)(uint64(0)) end)
print(string.format("  aio_return(314, 0): ret=%d", ok_ar and N(rv_ar) or -999))

-- aio_error(317)
local ok_ae, rv_ae = pcall(function() return mk(317)(uint64(0)) end)
print(string.format("  aio_error(317, 0): ret=%d", ok_ae and N(rv_ae) or -999))

-- __sysctlbyname(570) — listed as nosys, but retest with SIGSYS ignored
local sname = memory.alloc(32)
write_str(sname, "kern.ostype")
local sout = memory.alloc(64)
fill_sentinel(sout, 64)
local slen = memory.alloc(8)
wd(N(slen), 64)
local ok_sn, rv_sn = pcall(function()
    return mk(570)(sname, uint64(11), sout, slen, uint64(0), uint64(0))
end)
local ret_sn = ok_sn and N(rv_sn) or -999
print(string.format("  sysctlbyname(570, 'kern.ostype'): ret=%d", ret_sn))
if ret_sn == 0 then
    local m, k = scan_buf(sout, 64, "sysctl")
    print(string.format("  mod=%d kptrs=%d", m, k))
end

-- thr_set_name(464)
local tname = memory.alloc(32)
write_str(tname, "exploit")
local ok_tn, rv_tn = pcall(function()
    return mk(464)(uint64(0), tname, uint64(7))
end)
print(string.format("  thr_set_name(464, 0, 'exploit'): ret=%d", ok_tn and N(rv_tn) or -999))

-- sigtimedwait(345) — might return signal info
local ok_st, rv_st = pcall(function()
    return mk(345)(uint64(0), uint64(0), uint64(0))
end)
print(string.format("  sigtimedwait(345, 0,0,0): ret=%d", ok_st and N(rv_st) or -999))

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 392b COMPLETE ===")
