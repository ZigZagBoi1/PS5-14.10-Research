-- CRASH_CLASS: MODERATE
-- PROBE 392c: BSD remaining data returners (fix for 392b crash)
--
-- 392b crashed during buffer dump (binary output). This probe:
-- [A] sc125 with safe hex print (already know: ret=4, zero kptrs in hex)
-- [B] fstatfs(397) with real fds
-- [C] getfsstat(395) filesystem listing
-- [D] unnamed slot sweep with pointer args
-- [E] misc BSD calls (aio_return, thr_set_name, sigtimedwait)

print("=== PROBE 392c: BSD remaining ===")
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

local function fill_sentinel(buf, len)
    for i = 0, len - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end
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

-- Safe hex format that won't crash on weird Lua values
local function safe_hex(v)
    if v == nil then return "nil" end
    local ok, s = pcall(string.format, "%08X", v)
    if ok then return s end
    local ok2, s2 = pcall(tostring, v)
    if ok2 then return s2 end
    return "???"
end

-- Scan buffer for kptrs, return count
local function scan_kptrs(base, len)
    local kptrs = 0
    local mod = 0
    for off = 0, len - 4, 4 do
        local d = rd(N(base) + off)
        if d ~= nil and d ~= 0xDEADDEAD then mod = mod + 1 end
    end
    for off = 0, len - 8, 8 do
        local q = rq(N(base) + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                kptrs = kptrs + 1
                print(string.format("  +0x%02X: kptr h=%s l=%s",
                    off, safe_hex(h), safe_hex(l)))
            end
        end
    end
    return mod, kptrs
end

-- ===================================================================
-- [A] sc125 confirmation (quick)
-- ===================================================================
print("[A] sc125 confirm")
local buf = memory.alloc(0x400)
fill_sentinel(buf, 0x400)
local ok_a, rv_a = pcall(function() return mk(125)(buf, uint64(0x400)) end)
local ret_a = ok_a and N(rv_a) or -999
local m_a, k_a = scan_kptrs(buf, 0x400)
print(string.format("  ret=%d mod=%d kptrs=%d", ret_a, m_a, k_a))
if not alive() then print("DEAD"); return end
print("")

-- ===================================================================
-- [B] fstatfs(397) with real fds
-- ===================================================================
print("[B] fstatfs(397)")

local dev_buf = memory.alloc(32)

-- Open /dev/null
write_str(dev_buf, "/dev/null")
local null_fd = -1
local ok_n, rv_n = pcall(function() return mk(5)(dev_buf, uint64(0), uint64(0)) end)
if ok_n then null_fd = N(rv_n) end

-- Open /dev/dce
write_str(dev_buf, "/dev/dce")
local dce_fd = -1
local ok_d, rv_d = pcall(function() return mk(5)(dev_buf, uint64(2), uint64(0)) end)
if ok_d then dce_fd = N(rv_d) end

-- shm fd
local shm_fd = -1
local ok_s, rv_s = pcall(function()
    return mk(482)(uint64(1), uint64(0x202), uint64(0x180))
end)
if ok_s then shm_fd = N(rv_s) end

-- socket
local sock_fd = -1
local ok_sk, rv_sk = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
if ok_sk then sock_fd = N(rv_sk) end

print(string.format("  fds: null=%d dce=%d shm=%d sock=%d",
    null_fd, dce_fd, shm_fd, sock_fd))

-- statfs struct is ~0x230 on FreeBSD
local statfs_buf = memory.alloc(0x300)

local fds = {}
if null_fd >= 0 then fds[#fds+1] = {null_fd, "null"} end
if dce_fd >= 0 then fds[#fds+1] = {dce_fd, "dce"} end
if shm_fd >= 0 then fds[#fds+1] = {shm_fd, "shm"} end
if sock_fd >= 0 then fds[#fds+1] = {sock_fd, "sock"} end

for _, fi in ipairs(fds) do
    if not alive() then break end
    fill_sentinel(statfs_buf, 0x300)
    local ok_f, rv_f = pcall(function()
        return mk(397)(uint64(fi[1]), statfs_buf)
    end)
    local ret = ok_f and N(rv_f) or -999
    local m, k = scan_kptrs(statfs_buf, 0x300)
    print(string.format("  fstatfs(%s fd=%d): ret=%d mod=%d kptrs=%d",
        fi[2], fi[1], ret, m, k))

    -- If ret=0, show fstype at +0x00 (f_version at +0, f_type at +4)
    if ret == 0 and m > 0 then
        local fver = rd(N(statfs_buf)) or 0
        local ftype = rd(N(statfs_buf) + 4) or 0
        local flags = rd(N(statfs_buf) + 8) or 0
        print(string.format("    ver=%s type=%s flags=%s",
            safe_hex(fver), safe_hex(ftype), safe_hex(flags)))
        -- f_fstypename at +0x24 (16 chars)
        local fsname = ""
        for i = 0, 12, 4 do
            local d = rd(N(statfs_buf) + 0x24 + i)
            if d and d ~= 0 then
                for b = 0, 3 do
                    local c = math.floor(d / (256^b)) % 256
                    if c > 0 and c < 128 then fsname = fsname .. string.char(c) end
                end
            end
        end
        if #fsname > 0 then print("    fstype: " .. fsname) end
    end
end

-- Close fds
for _, fi in ipairs(fds) do pcall(function() mk(6)(uint64(fi[1])) end) end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] getfsstat(395) — filesystem count + listing
-- ===================================================================
print("[C] getfsstat(395)")

-- NULL call to get count
local ok_c1, rv_c1 = pcall(function()
    return mk(395)(uint64(0), uint64(0), uint64(2))  -- MNT_NOWAIT
end)
local count = ok_c1 and N(rv_c1) or -1
print(string.format("  getfsstat(NULL): count=%d", count))

-- getfsstat(396) modern version
local ok_c2, rv_c2 = pcall(function()
    return mk(396)(uint64(0), uint64(0), uint64(2))
end)
print(string.format("  getfsstat(396, NULL): ret=%d", ok_c2 and N(rv_c2) or -999))

if count > 0 and count < 50 and alive() then
    local fsbuf = memory.alloc(0x4000)
    fill_sentinel(fsbuf, 0x4000)
    local ok_c3, rv_c3 = pcall(function()
        return mk(395)(fsbuf, uint64(0x4000), uint64(2))
    end)
    local ret_c3 = ok_c3 and N(rv_c3) or -1
    local m, k = scan_kptrs(fsbuf, 0x4000)
    print(string.format("  getfsstat(buf): ret=%d mod=%d kptrs=%d", ret_c3, m, k))
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] Unnamed slot sweep (pointer args)
-- ===================================================================
print("[D] slot sweep")

local test_buf = memory.alloc(0x200)
local hits = 0

local unnamed = {91, 94, 119, 151, 152, 153, 159, 167, 168, 172,
    177, 178, 179, 180, 184, 185, 186, 187,
    364, 365, 366, 367, 368, 369, 370, 375,
    380, 381, 382, 383, 418, 419, 420,
    434, 435, 440, 467, 468, 469, 470}

for _, num in ipairs(unnamed) do
    if not alive() then break end

    -- Pattern 1: (buf, size)
    fill_sentinel(test_buf, 0x200)
    local ok1, rv1 = pcall(function()
        return mk(num)(test_buf, uint64(0x200))
    end)
    local ret1 = ok1 and N(rv1) or -999

    if ret1 >= 0 then
        local m, k = scan_kptrs(test_buf, 0x200)
        print(string.format("  %d(buf,0x200): ret=%d mod=%d kptrs=%d", num, ret1, m, k))
        hits = hits + 1
    end

    -- Pattern 2: (0, buf, size)
    if ret1 < 0 and alive() then
        fill_sentinel(test_buf, 0x200)
        local ok2, rv2 = pcall(function()
            return mk(num)(uint64(0), test_buf, uint64(0x200))
        end)
        local ret2 = ok2 and N(rv2) or -999
        if ret2 >= 0 then
            local m, k = scan_kptrs(test_buf, 0x200)
            print(string.format("  %d(0,buf,0x200): ret=%d mod=%d kptrs=%d", num, ret2, m, k))
            hits = hits + 1
        end
    end

    -- Pattern 3: (pid, buf, size)
    if alive() then
        fill_sentinel(test_buf, 0x200)
        local ok3, rv3 = pcall(function()
            return mk(num)(uint64(pid_val), test_buf, uint64(0x200))
        end)
        local ret3 = ok3 and N(rv3) or -999
        if ret3 >= 0 and ret1 < 0 then
            local m, k = scan_kptrs(test_buf, 0x200)
            print(string.format("  %d(pid,buf,0x200): ret=%d mod=%d kptrs=%d", num, ret3, m, k))
            hits = hits + 1
        end
    end
end

if hits == 0 then
    print("  all 40 slots: -1 for all patterns")
else
    print(string.format("  %d slots responded", hits))
end

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] Misc BSD
-- ===================================================================
print("[E] misc")

-- thr_set_name(464)
local tname = memory.alloc(32)
write_str(tname, "exploit")
local ok_tn, rv_tn = pcall(function()
    return mk(464)(uint64(0), tname, uint64(7))
end)
print(string.format("  thr_set_name(464): ret=%d", ok_tn and N(rv_tn) or -999))

-- sigtimedwait(345) with zero timeout
local sigset = memory.alloc(16)
zero_buf(sigset, 16)
wd(N(sigset), 0xFFFFFFFF)  -- all signals
local ts = memory.alloc(16)
zero_buf(ts, 16)  -- zero timeout = poll
local siginfo = memory.alloc(0x80)
fill_sentinel(siginfo, 0x80)
local ok_st, rv_st = pcall(function()
    return mk(345)(sigset, siginfo, ts)
end)
local ret_st = ok_st and N(rv_st) or -999
print(string.format("  sigtimedwait(345): ret=%d", ret_st))
if ret_st > 0 then
    local m, k = scan_kptrs(siginfo, 0x80)
    print(string.format("    siginfo mod=%d kptrs=%d", m, k))
end

-- aio_return(314)
local ok_ar, rv_ar = pcall(function() return mk(314)(uint64(0)) end)
print(string.format("  aio_return(314): ret=%d", ok_ar and N(rv_ar) or -999))

-- clock_getcpuclockid2(247)
local clkid = memory.alloc(8)
fill_sentinel(clkid, 8)
local ok_clk, rv_clk = pcall(function()
    return mk(247)(uint64(pid_val), uint64(0), clkid)
end)
local ret_clk = ok_clk and N(rv_clk) or -999
print(string.format("  clock_getcpuclockid2(247, pid, 0): ret=%d", ret_clk))
if ret_clk == 0 then
    local cid = rd(N(clkid)) or 0
    print(string.format("    clockid=%s", safe_hex(cid)))
end

-- __cap_rights_get(515)
local cr = memory.alloc(0x40)
fill_sentinel(cr, 0x40)
-- Try on stdin (fd 0)
local ok_cap, rv_cap = pcall(function()
    return mk(515)(uint64(0), uint64(0), cr)
end)
local ret_cap = ok_cap and N(rv_cap) or -999
print(string.format("  __cap_rights_get(515, 0, 0): ret=%d", ret_cap))
if ret_cap == 0 then
    local m, k = scan_kptrs(cr, 0x40)
    print(string.format("    mod=%d kptrs=%d", m, k))
end

-- socketex(113) with real args
local ok_se, rv_se = pcall(function()
    return mk(113)(uint64(2), uint64(1), uint64(0),
        uint64(0), uint64(0), uint64(0))
end)
print(string.format("  socketex(113, AF_INET, STREAM): ret=%d",
    ok_se and N(rv_se) or -999))

-- sched_getparam(328)
local sp = memory.alloc(16)
fill_sentinel(sp, 16)
local ok_sp, rv_sp = pcall(function()
    return mk(328)(uint64(0), sp)  -- pid=0 = self
end)
local ret_sp = ok_sp and N(rv_sp) or -999
print(string.format("  sched_getparam(328, self): ret=%d", ret_sp))
if ret_sp == 0 then
    local prio = rd(N(sp)) or 0xDEADDEAD
    print(string.format("    prio=%s", safe_hex(prio)))
end

-- sched_getscheduler(329)
local ok_ss, rv_ss = pcall(function()
    return mk(329)(uint64(0))
end)
print(string.format("  sched_getscheduler(329, self): ret=%d",
    ok_ss and N(rv_ss) or -999))

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] socketex/socketclose deeper
-- ===================================================================
print("[F] socketex(113)")

-- Try different extra arg patterns
local se_combos = {
    {2,1,0, 1,0,0, "INET/STREAM/ext1"},
    {2,1,6, 1,0,0, "INET/STREAM/TCP/ext1"},
    {2,2,17, 0,0,0, "INET/DGRAM/UDP"},
    {1,1,0, 0,0,0, "UNIX/STREAM"},
    {2,1,0, 0,1,0, "INET/ext5=1"},
    {2,1,0, 0,0,1, "INET/ext6=1"},
}

for _, c in ipairs(se_combos) do
    if not alive() then break end
    local ok_c, rv_c = pcall(function()
        return mk(113)(uint64(c[1]), uint64(c[2]), uint64(c[3]),
            uint64(c[4]), uint64(c[5]), uint64(c[6]))
    end)
    local ret = ok_c and N(rv_c) or -999
    if ret >= 0 then
        print(string.format("  113(%s): fd=%d ***", c[7], ret))
        -- Test socketclose(114) on it
        local ok_sc, rv_sc = pcall(function()
            return mk(114)(uint64(ret))
        end)
        print(string.format("    socketclose(114): ret=%d", ok_sc and N(rv_sc) or -999))
    end
end

-- Also test: if 113 always returns -1, all combos dead
print("  (if no fd printed: all combos ret=-1)")

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 392c COMPLETE ===")
